#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
static void snapshot(const char *path,int argc,char **argv) {
    int fd=open(path,O_RDONLY|O_CLOEXEC); assert(fd>=0);
    char buffer[4096];
    for (int i=0;i<argc;++i) {
        size_t left=strlen(argv[i])+1, offset=0;
        while (left) {
            size_t size=left<sizeof(buffer) ? left : sizeof(buffer);
            ssize_t n=read(fd,buffer,size);
            assert(n>0 && !memcmp(buffer,argv[i]+offset,(size_t)n));
            left-=(size_t)n; offset+=(size_t)n;
        }
    }
    assert(!read(fd,buffer,1)); close(fd);
}
static void wait_child(pid_t pid) {
    int status;
    // EVENT_WAIT: exact child completion; the runner's deadline fails a hang.
    assert(waitpid(pid,&status,0)==pid);
    if (status) fprintf(stderr,"argument child=%d status=%#x\n",pid,status);
    assert(WIFEXITED(status) && !WEXITSTATUS(status));
}
static int mappings(void) {
    FILE *f=fopen("/proc/self/maps","r"); assert(f);
    int n=0,c; while ((c=fgetc(f))!=EOF) if (c=='\n') ++n;
    assert(!ferror(f)); fclose(f); return n;
}
static int descriptors(void) {
    int count=0;
    for (int i=0;i<1024;++i) if (fcntl(i,F_GETFD)>=0) ++count;
    return count;
}
static void payload(char *out,int i) { snprintf(out,32,"argument-%d",i); }
int main(int argc,char **argv) {
    setvbuf(stdout,NULL,_IONBF,0);
    if (argc>1 && !strcmp(argv[1],"bulk")) {
        assert(argc==650000);
        for (int i=2;i<argc;++i) assert(!*argv[i]);
        return 0;
    }
    int start=1;
    while (start<argc && strcmp(argv[start],"child")) ++start;
    if (start<argc) {
        int count=atoi(argv[start+1]), ready=atoi(argv[start+2]), release=atoi(argv[start+3]);
        assert(argc==start+4+count && count>0);
        for (int i=0;i<count-1;++i) {
            char text[32]; payload(text,i);
            assert(!strcmp(argv[start+4+i],text));
        }
        assert(strlen(argv[argc-1])==32768);
        snapshot("/proc/self/cmdline",argc,argv);
        snapshot("/proc/thread-self/cmdline",argc,argv);
        char *saved=argv[0]; argv[0]=(char *)1;
        char **original=malloc((size_t)argc*sizeof(char *)); assert(original);
        memcpy(original,argv,(size_t)argc*sizeof(char *)); original[0]=saved;
        snapshot("/proc/self/cmdline",argc,original);
        argv[0]=saved; free(original);
        assert(write(ready,"x",1)==1);
        char byte;
        // EVENT_WAIT: parent finishes the foreign /proc snapshot before release.
        assert(read(release,&byte,1)==1);
        return 0;
    }
    char self[4096]; ssize_t n=readlink("/proc/self/exe",self,sizeof(self)-1); assert(n>0); self[n]=0;
    char script[]="/tmp/md-arguments-XXXXXX";
    int scriptfd=mkstemp(script); assert(scriptfd>=0);
    char header[8192]; int length=snprintf(header,sizeof(header),"#!%s script\n",self);
    assert(write(scriptfd,header,(size_t)length)==length && !fchmod(scriptfd,0700)); close(scriptfd);
    int image=open(self,O_PATH|O_CLOEXEC); assert(image>=0);
    const int counts[]={1018,1024,8192,32768};
    for (unsigned test=0;test<sizeof(counts)/sizeof(*counts);++test) {
        int count=counts[test], ready[2], release[2];
        assert(!pipe(ready) && !pipe(release));
        char number[32], output[32], input[32];
        snprintf(number,sizeof(number),"%d",count);
        snprintf(output,sizeof(output),"%d",ready[1]); snprintf(input,sizeof(input),"%d",release[0]);
        char **args=calloc((size_t)count+6,sizeof(char *)); assert(args);
        args[0]=self; args[1]="child"; args[2]=number; args[3]=output; args[4]=input;
        for (int i=0;i<count;++i) {
            args[5+i]=malloc(i==count-1 ? 32769 : 32); assert(args[5+i]);
            if (i==count-1) { memset(args[5+i],'z',32768); args[5+i][32768]=0; }
            else payload(args[5+i],i);
        }
        for (int mode=0;mode<3;++mode) {
            pid_t pid;
            if (mode==2) assert(!posix_spawn(&pid,self,NULL,NULL,args,environ));
            else {
                pid=fork(); assert(pid>=0);
                if (!pid) {
                    if (!mode) syscall(SYS_execveat,image,"",args,environ,AT_EMPTY_PATH);
                    else execve(script,args,environ);
                    perror("large exec"); _exit(90);
                }
            }
            char byte;
            // EVENT_WAIT: child validates its image before publishing readiness.
            assert(read(ready[0],&byte,1)==1);
            char path[128]; snprintf(path,sizeof(path),"/proc/%d/cmdline",pid);
            if (mode==1) {
                char **expanded=calloc((size_t)count+8,sizeof(char *)); assert(expanded);
                expanded[0]=self; expanded[1]="script"; expanded[2]=script;
                memcpy(expanded+3,args+1,((size_t)count+5)*sizeof(char *));
                snapshot(path,count+7,expanded); free(expanded);
            } else snapshot(path,count+5,args);
            assert(write(release[1],"x",1)==1); wait_child(pid);
        }
        int maps=mappings(), fds=descriptors();
        for (int i=0;i<8;++i) assert(execve("/missing-argv-program",args,environ)==-1 && errno==ENOENT);
        assert(mappings()==maps && descriptors()==fds);
        for (int i=0;i<count;++i) free(args[5+i]); free(args);
        close(ready[0]); close(ready[1]); close(release[0]); close(release[1]);
        printf("PASS %d arguments: execveat, shebang, spawn, self/foreign proc and failed-exec cleanup\n",count);
    }
    close(image); assert(!unlink(script));
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    char *large=malloc(32*page+1); assert(large); memset(large,'x',32*page); large[32*page]=0;
    char *bad[]={self,large,NULL};
    int maps=mappings(), fds=descriptors();
    for (int i=0;i<8;++i) assert(execve(self,bad,environ)==-1 && errno==E2BIG);
    bad[1]=(char *)1;
    for (int i=0;i<8;++i) assert(execve(self,bad,environ)==-1 && errno==EFAULT);
    bad[1]=NULL;
    char *bad_env[]={large,NULL};
    assert(execve(self,bad,bad_env)==-1 && errno==E2BIG);
    bad_env[0]=(char *)1;
    assert(execve(self,bad,bad_env)==-1 && errno==EFAULT);
    assert(mappings()==maps && descriptors()==fds); free(large);
    pid_t pid=fork(); assert(pid>=0);
    if (!pid) {
        struct rlimit limit; assert(!getrlimit(RLIMIT_STACK,&limit));
        limit.rlim_cur=512*1024; assert(!setrlimit(RLIMIT_STACK,&limit));
        char **many=calloc(32769,sizeof(char *)); assert(many);
        for (int i=0;i<32768;++i) many[i]="x";
        assert(execve(self,many,environ)==-1 && errno==E2BIG);
        _exit(0);
    }
    wait_child(pid);
    pid=fork(); assert(pid>=0);
    if (!pid) {
        struct rlimit limit; assert(!getrlimit(RLIMIT_STACK,&limit));
        assert(limit.rlim_max>=32*1024*1024);
        limit.rlim_cur=32*1024*1024; assert(!setrlimit(RLIMIT_STACK,&limit));
        char **many=calloc(650001,sizeof(char *)); assert(many);
        many[0]=self; many[1]="bulk";
        for (int i=2;i<650000;++i) many[i]="";
        execve(self,many,environ);
        perror("bulk exec"); _exit(90);
    }
    wait_child(pid);
    puts("PASS 650000 empty arguments with enlarged RLIMIT_STACK");
    puts("PASS exec limits: real kernel E2BIG, RLIMIT_STACK, EFAULT and resource cleanup");
}

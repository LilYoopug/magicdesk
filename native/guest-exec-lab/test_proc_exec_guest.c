#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
static void execute(const char *path,int base,int protected) {
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        if (protected) assert(!prctl(PR_SET_DUMPABLE,0));
        char *args[]={(char *)path,"proc-exec","target",NULL};
        errno=0;
        assert(syscall(SYS_execveat,base,path,args,environ,AT_SYMLINK_NOFOLLOW)==-1 && errno==ELOOP);
        syscall(SYS_execveat,base,path,args,environ,0);
        fprintf(stderr,"foreign executable %s: %s\n",path,strerror(errno));
        _exit(99);
    }
    int status=0;
    /* EVENT_WAIT: exact exec child exit; alarm bounds a missing completion. */
    assert(waitpid(child,&status,0)==child);
    assert(WIFEXITED(status) && WEXITSTATUS(status)==37);
}
static void exercise(const char *proc,const char *directory) {
    char path[256],alias[256];
    snprintf(path,sizeof(path),"%s/%d/exe",proc,getpid());
    execute(path,AT_FDCWD,0);
    execute(path,AT_FDCWD,1);
    snprintf(alias,sizeof(alias),"%s/proc-image-alias",directory);
    assert(!symlink(path,alias));
    execute(alias,AT_FDCWD,0);
    assert(!unlink(alias));
    snprintf(path,sizeof(path),"%s/%d",proc,getpid());
    int base=open(path,O_PATH|O_DIRECTORY|O_CLOEXEC); assert(base>=0);
    execute("exe",base,0); close(base);
    puts("PASS foreign executable selection");
}
int test_proc_exec_guest(int argc, char **argv) {
    if (argc==3 && !strcmp(argv[2],"target")) return 37;
    setbuf(stdout,NULL); alarm(40);
    assert(argc==4);
    if (!strcmp(argv[2],"memfd")) {
        int source=open("/proc/self/exe",O_RDONLY|O_CLOEXEC); assert(source>=0);
        int fd=memfd_create("proc-exec",MFD_CLOEXEC|MFD_ALLOW_SEALING); assert(fd>=0);
        char bytes[16384]; ssize_t n;
        while ((n=read(source,bytes,sizeof(bytes)))>0) assert(write(fd,bytes,(size_t)n)==n);
        assert(n==0); close(source);
        struct stat st; assert(!fstat(fd,&st) && (st.st_mode&0111));
        assert(!fcntl(fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL));
        char *args[]={"anonymous","proc-exec","direct",argv[3],NULL};
        syscall(SYS_execveat,fd,"",args,environ,AT_EMPTY_PATH);
        perror("memfd image"); return 99;
    }
    if (!strcmp(argv[2],"pid")) {
        assert(!unshare(CLONE_NEWNS|CLONE_NEWPID));
        pid_t child=fork(); assert(child>=0);
        if (!child) {
            assert(getpid()==1);
            char proc[256]; snprintf(proc,sizeof(proc),"%s/proc-exec",argv[3]);
            assert(!mkdir(proc,0700));
            assert(!mount("proc",proc,"proc",MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL));
            exercise(proc,argv[3]);
            assert(!umount(proc) && !rmdir(proc)); _exit(0);
        }
        int status=0; assert(waitpid(child,&status,0)==child && !status);
        return 0;
    }
    exercise("/proc",argv[3]);
    return 0;
}

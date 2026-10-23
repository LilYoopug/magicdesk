#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/mount.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
static void put(const char *path,const char *text) {
    int fd=open(path,O_WRONLY|O_CLOEXEC);
    if (fd<0) { perror(path); abort(); }
    ssize_t size=(ssize_t)strlen(text), n=write(fd,text,(size_t)size);
    if (n!=size) { perror("binfmt write"); fprintf(stderr,"%s: %s\n",path,text); abort(); }
    assert(!close(fd));
}
static void contents(const char *path,const char *text) {
    int fd=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0755); assert(fd>=0);
    assert(write(fd,text,strlen(text))==(ssize_t)strlen(text)); assert(!close(fd));
}
static void copy(const char *from,const char *to) {
    int source=open(from,O_RDONLY|O_CLOEXEC), dest=open(to,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0755);
    assert(source>=0 && dest>=0);
    char bytes[65536]; ssize_t n;
    while ((n=read(source,bytes,sizeof(bytes)))>0) assert(write(dest,bytes,(size_t)n)==n);
    assert(!n); close(source); close(dest);
}
static void run(const char *path,int preserve,int opened,uid_t euid,int failure,int nnp,int descriptor) {
    char expected[80]; snprintf(expected,sizeof(expected),"%d:%d:%u",preserve,opened,euid);
    assert(!setenv("MD_BINFMT_EXPECT",expected,1));
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        if (nnp) assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
        if (euid!=getuid()) { assert(!setgid(1000)); assert(!setuid(1000)); }
        char *args[]={"original-zero","binfmt-child",NULL};
        if (descriptor>=0) syscall(SYS_execveat,descriptor,"",args,environ,AT_EMPTY_PATH);
        else execve(path,args,environ);
        if (errno!=failure) { perror("binfmt exec"); _exit(90); }
        _exit(0);
    }
    int status;
    /* EVENT_WAIT: child exit; outer launch deadline fails a blocked execution. */
    assert(waitpid(child,&status,0)==child);
    if (!WIFEXITED(status) || WEXITSTATUS(status)!=(failure ? 0 : 42))
        fprintf(stderr,"binfmt child status=%#x path=%s expected=%d\n",status,path,failure);
    assert(WIFEXITED(status) && WEXITSTATUS(status)==(failure ? 0 : 42));
}
int main(int argc,char **argv) {
    setvbuf(stdout,NULL,_IONBF,0);
    if (argc>=3 && !strcmp(argv[argc-1],"binfmt-child")) {
        int preserve,opened; unsigned euid;
        assert(sscanf(getenv("MD_BINFMT_EXPECT"),"%d:%d:%u",&preserve,&opened,&euid)==3);
        assert(argc==3+preserve);
        if (preserve) assert(!strcmp(argv[2],"original-zero"));
        assert(geteuid()==euid);
        int fd=(int)getauxval(AT_EXECFD);
        if (opened) {
            assert(fd>=3 && !(fcntl(fd,F_GETFD)&FD_CLOEXEC));
            char bytes[4]; assert(read(fd,bytes,4)==4 && !memcmp(bytes,"MD!\n",4));
            struct stat st; assert(!fstat(fd,&st) && st.st_uid==0 && S_ISREG(st.st_mode));
            close(fd);
        } else assert(!fd);
        return 42;
    }
    char directory[]="/tmp/md-binfmt-XXXXXX";
    assert(mkdtemp(directory) && !chmod(directory,0755) && !chdir(directory));
    assert(!mkdir("rules",0755) && !mkdir("alias",0755));
    if (mount("binfmt_misc","rules","binfmt_misc",0,NULL)) { perror("mount binfmt_misc"); abort(); }
    int context=(int)syscall(SYS_fsopen,"binfmt_misc",FSOPEN_CLOEXEC); assert(context>=0);
    assert(!syscall(SYS_fsconfig,context,FSCONFIG_CMD_CREATE,NULL,NULL,0));
    int tree=(int)syscall(SYS_fsmount,context,FSMOUNT_CLOEXEC,0); assert(tree>=0);
    assert(!syscall(SYS_move_mount,tree,"",AT_FDCWD,"alias",MOVE_MOUNT_F_EMPTY_PATH));
    close(tree); close(context);
    struct statfs fs; assert(!statfs("rules",&fs) && fs.f_type==0x42494e4d);
    assert(!access("rules",W_OK));
    int root=open("rules",O_PATH|O_CLOEXEC); assert(root>=0);
    assert(!syscall(SYS_faccessat2,root,"",W_OK,AT_EMPTY_PATH)); close(root);
    assert(mkdir("rules/not-a-registration",0755)<0 && errno==EROFS);
    assert(!mount(NULL,"alias",NULL,MS_REMOUNT|MS_RDONLY,NULL));
    assert(access("rules",W_OK)<0 && errno==EROFS);
    assert(!mount(NULL,"alias",NULL,MS_REMOUNT,NULL));
    copy("/proc/self/exe","interpreter"); contents("payload.bin","MD!\n");
    char interpreter[PATH_MAX],payload[PATH_MAX],registration[PATH_MAX+100];
    snprintf(interpreter,sizeof(interpreter),"%s/interpreter",directory);
    snprintf(payload,sizeof(payload),"%s/payload.bin",directory);
    snprintf(registration,sizeof(registration),":fixture:M::MD!::%s:P",interpreter);
    put("rules/register",registration);
    assert(!access("alias/fixture",F_OK));
    int registration_fd=open("rules/register",O_WRONLY|O_CLOEXEC); assert(registration_fd>=0);
    assert(write(registration_fd,registration,strlen(registration))<0 && errno==EEXIST);
    close(registration_fd);
    run(payload,1,0,0,0,0,-1);
    snprintf(registration,sizeof(registration),":newest:M::MD!::%s:",interpreter);
    put("rules/register",registration); run(payload,0,0,0,0,0,-1);
    put("rules/newest","-1"); run(payload,1,0,0,0,0,-1);
    put("alias/fixture","0\n"); run(payload,1,0,0,ENOEXEC,0,-1);
    put("rules/fixture","1"); put("rules/status","0"); run(payload,1,0,0,ENOEXEC,0,-1);
    put("rules/status","1"); run(payload,1,0,0,0,0,-1);
    pid_t namespace_child=fork(); assert(namespace_child>=0);
    if (!namespace_child) {
        assert(!unshare(CLONE_NEWUSER|CLONE_NEWNS));
        put("/proc/self/uid_map","0 0 1"); put("/proc/self/setgroups","deny");
        put("/proc/self/gid_map","0 0 1");
        run(payload,1,0,0,0,0,-1);
        int parent=open("rules/status",O_WRONLY|O_CLOEXEC);
        if (parent>=0) { assert(write(parent,"0",1)<0 && errno==EPERM); close(parent); }
        else assert(errno==EACCES);
        assert(!mkdir("private",0755));
        assert(!mount("binfmt_misc","private","binfmt_misc",0,NULL));
        run(payload,0,0,0,ENOEXEC,0,-1);
        snprintf(registration,sizeof(registration),":private:M::MD!::%s:",interpreter);
        put("private/register",registration); run(payload,0,0,0,0,0,-1);
        put("private/status","-1"); assert(!umount("private") && !rmdir("private"));
        _exit(0);
    }
    int namespace_status;
    assert(waitpid(namespace_child,&namespace_status,0)==namespace_child && !namespace_status);
    run(payload,1,0,0,0,0,-1);
    put("rules/fixture","-1");
    snprintf(registration,sizeof(registration),":fixture:E::bin::%s:O",interpreter);
    put("rules/register",registration); run(payload,0,1,0,0,0,-1);
    assert(!rename("payload.bin","payload.raw") && !symlink("payload.raw","payload.bin"));
    run(payload,0,1,0,0,0,-1);
    assert(!symlink("payload.bin","alias.raw"));
    run("alias.raw",0,1,0,ENOEXEC,0,-1);
    assert(!unlink("alias.raw") && !unlink("payload.bin") && !rename("payload.raw","payload.bin"));
    put("rules/status","-1"); assert(access("rules/fixture",F_OK)<0 && errno==ENOENT);
    puts("PASS binfmt M/E matching, P/O, toggles, removal and mount aliases");

    snprintf(registration,sizeof(registration),":fixture:M::MD!::%s:CF",interpreter);
    put("rules/register",registration);
    assert(!chown(payload,0,0) && !chmod(payload,04711));
    assert(!unlink(interpreter));
    run(payload,0,1,1000,0,1,-1);
    /* Drop credentials in a separate child even when expected euid is root. */
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        assert(!setgid(1000) && !setuid(1000)); run(payload,0,1,0,0,0,-1); _exit(0);
    }
    int status; assert(waitpid(child,&status,0)==child && !status);
    child=fork(); assert(child>=0);
    if (!child) {
        assert(!chroot(".") && !chdir("/"));
        run("/payload.bin",0,1,0,0,0,-1); _exit(0);
    }
    assert(waitpid(child,&status,0)==child && !status);
    int fd=open(payload,O_RDONLY|O_CLOEXEC); assert(fd>=0);
    run(payload,0,1,0,ENOENT,0,fd); close(fd);
    puts("PASS binfmt C/F credentials, no_new_privs, removed interpreter, chroot and inaccessible execfd");
    put("rules/status","-1");
    assert(!umount("alias") && !umount("rules"));
    assert(!unlink(payload) && !rmdir("alias") && !rmdir("rules"));
    assert(!chdir("/") && !rmdir(directory));
    puts("PASS binfmt_misc");
}

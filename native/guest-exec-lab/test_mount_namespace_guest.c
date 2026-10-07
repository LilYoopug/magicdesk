#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/stat.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static uint64_t id(int fd, const char *path) {
    struct statx st={0};
    assert(!syscall(SYS_statx,fd,path,*path ? 0 : AT_EMPTY_PATH,STATX_MNT_ID,&st));
    assert(st.stx_mask&STATX_MNT_ID); assert(st.stx_mnt_id); return st.stx_mnt_id;
}
struct context { uint64_t original; int dir; int split; };
static int copied(void *argument) {
    struct context *c=argument;
    if (c->split) assert(!unshare(CLONE_NEWNS));
    assert(id(AT_FDCWD,"/")!=c->original);
    assert(id(c->dir,"")==c->original);
    assert(id(c->dir,".")==c->original);
    assert(id(AT_FDCWD,".")==id(AT_FDCWD,"/"));
    char cwd[64]; assert(getcwd(cwd,sizeof(cwd)) && !strcmp(cwd,"/tmp"));
    uint64_t before=id(AT_FDCWD,"/");
    assert(unshare(CLONE_NEWNS|CLONE_NEWUTS)<0 && errno==ENOTSUP);
    assert(id(AT_FDCWD,"/")==before);
    assert(!chdir("/"));
    return 0;
}
static void binding(void) {
    assert(!mkdir("/tmp/source",0755)); assert(!mkdir("/tmp/target",0755));
    int value=open("/tmp/source/value",O_CREAT|O_WRONLY,0644); assert(value>=0);
    assert(write(value,"data",4)==4); close(value);
    assert(!mount("/tmp/source","/tmp/target",NULL,MS_BIND,NULL));
    uint64_t first=id(AT_FDCWD,"/tmp/source"), second=id(AT_FDCWD,"/tmp/target");
    assert(first!=second);
    value=open("/tmp/target/value",O_RDONLY); assert(value>=0);
    char text[8]={0}; assert(read(value,text,sizeof(text))==4 && !strcmp(text,"data")); close(value);
    int dir=open("/tmp/target",O_PATH|O_DIRECTORY); assert(dir>=0);
    assert(id(dir,"")==second);
    assert(!mount(NULL,"/tmp/target",NULL,MS_BIND|MS_REMOUNT|MS_RDONLY,NULL));
    value=openat(dir,"value",O_RDWR); assert(value<0 && errno==EROFS);
    value=open("/tmp/source/value",O_RDWR); assert(value>=0); close(value);
    assert(umount2("/tmp/target",0)<0 && errno==EBUSY);
    assert(!umount2("/tmp/target",MNT_DETACH));
    assert(id(AT_FDCWD,"/tmp/target")==first);
    assert(id(dir,"")==second);
    value=openat(dir,"value",O_RDONLY); assert(value>=0); close(value);
    value=open("/tmp/target/value",O_RDONLY); assert(value<0 && errno==ENOENT);
    close(dir);
    puts("PASS guest bind: distinct mount IDs, alias data, readonly policy, busy/detached lifetime");
}
static void root_busy(void) {
    assert(!mkdir("/tmp/root-use",0755));
    assert(!mkdir("/tmp/root-replacement",0755));
    assert(!mount("/tmp/root-use","/tmp/root-use",NULL,MS_BIND,NULL));
    uint64_t mounted=id(AT_FDCWD,"/tmp/root-use");
    int commands[2], replies[2]; assert(!pipe(commands) && !pipe(replies));
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        close(commands[1]); close(replies[0]);
        /* No cwd or descriptor inside the mount: only this FS root pins it. */
        assert(!chroot("/tmp/root-use"));
        assert(write(replies[1],"r",1)==1);
        char byte; assert(read(commands[0],&byte,1)==1);
        assert(id(AT_FDCWD,"/")==mounted); _exit(0);
    }
    close(commands[0]); close(replies[1]);
    /* EVENT_WAIT: child publishes its root before unmount; the executable's
     * alarm fails missing acknowledgement or child completion. */
    char byte; assert(read(replies[0],&byte,1)==1);
    assert(umount2("/tmp/root-use",0)<0 && errno==EBUSY);
    assert(!umount2("/tmp/root-use",MNT_DETACH));
    assert(!mount("/tmp/root-replacement","/tmp/root-use",NULL,MS_BIND,NULL));
    assert(id(AT_FDCWD,"/tmp/root-use")!=mounted);
    assert(write(commands[1],"q",1)==1);
    int status; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    close(commands[1]); close(replies[0]);
    assert(!umount2("/tmp/root-use",0));
    puts("PASS mount root lifetime: busy unmount, lazy detach and replacement preserve another FS root");
}
static void churn(void) {
    assert(!mkdir("/tmp/churn",0755));
    uint64_t previous=0;
    for (unsigned i=0;i<64;++i) {
        assert(!mount("/tmp/source","/tmp/churn",NULL,MS_BIND,NULL));
        uint64_t current=id(AT_FDCWD,"/tmp/churn"); assert(current!=previous); previous=current;
        int held=open("/tmp/churn",O_PATH|O_DIRECTORY); assert(held>=0);
        assert(!umount2("/tmp/churn",MNT_DETACH));
        assert(id(held,"")==current);
        int fd=openat(held,"value",O_RDONLY); assert(fd>=0); close(fd); close(held);
    }
    puts("PASS guest mount retirement: 64 reused slots, distinct mount IDs and retained detached dirfds");
}
static void stacks(void) {
    assert(!mkdir("/tmp/outer",0755)); assert(!mkdir("/tmp/other",0755));
    assert(!mkdir("/tmp/other/deep",0755)); assert(!mkdir("/tmp/stack",0755));
    assert(!mount("/tmp/outer","/tmp/stack",NULL,MS_BIND,NULL));
    int lower=open("/tmp/stack",O_PATH|O_DIRECTORY); assert(lower>=0);
    uint64_t lower_id=id(lower,"");
    assert(!mount("/tmp/other/deep","/tmp/stack",NULL,MS_BIND,NULL));
    assert(id(AT_FDCWD,"/tmp/stack")!=lower_id);
    struct stat parent, expected;
    assert(!stat("/tmp/stack/..",&parent) && !stat("/tmp",&expected));
    assert(parent.st_dev==expected.st_dev && parent.st_ino==expected.st_ino);
    assert(!chdir("/tmp/stack"));
    char cwd[128]; assert(getcwd(cwd,sizeof(cwd)) && !strcmp(cwd,"/tmp/stack"));
    assert(!chdir("..")); assert(getcwd(cwd,sizeof(cwd)) && !strcmp(cwd,"/tmp"));
    assert(!symlink("/tmp/stack","/tmp/stack-link"));
    assert(id(AT_FDCWD,"/tmp/stack-link")==id(AT_FDCWD,"/tmp/stack"));
    assert(!umount2("/tmp/stack",MNT_DETACH));
    assert(id(AT_FDCWD,"/tmp/stack")==lower_id);
    assert(!umount2("/tmp/stack",MNT_DETACH));
    assert(!fchdir(lower));
    assert(getcwd(cwd,sizeof(cwd))==NULL && errno==ENOENT);
    assert(id(AT_FDCWD,"..")==lower_id);
    assert(!chdir("/tmp")); close(lower);
    puts("PASS guest mount stacks: covered parent traversal, absolute links, detach and retained cwd");
}
static void files(void) {
    int fd=open("/tmp/file-target",O_CREAT|O_WRONLY,0644); assert(fd>=0); close(fd);
    assert(!mount("/tmp/source/value","/tmp/file-target",NULL,MS_BIND,NULL));
    uint64_t mounted=id(AT_FDCWD,"/tmp/file-target");
    assert(mounted!=id(AT_FDCWD,"/tmp/source/value"));
    fd=open("/tmp/file-target",O_RDWR); assert(fd>=0);
    char text[8]={0}; assert(read(fd,text,sizeof(text))==4 && !strcmp(text,"data"));
    assert(write(fd,"!",1)==1); close(fd);
    struct stat st; assert(!stat("/tmp/source/value",&st) && st.st_size==5);
    assert(!chmod("/tmp/file-target",0600));
    assert(!stat("/tmp/file-target",&st) && (st.st_mode&0777)==0600);
    assert(open("/tmp/file-target",O_CREAT|O_EXCL|O_WRONLY,0600)<0 && errno==EEXIST);
    assert(open("/tmp/file-target/",O_RDONLY)<0 && errno==ENOTDIR);
    assert(open("/tmp/file-target",O_PATH|O_DIRECTORY)<0 && errno==ENOTDIR);
    assert(!mount(NULL,"/tmp/file-target",NULL,MS_BIND|MS_REMOUNT|MS_RDONLY,NULL));
    assert(open("/tmp/file-target",O_WRONLY)<0 && errno==EROFS);
    fd=open("/tmp/file-target",O_PATH); assert(fd>=0);
    assert(!umount2("/tmp/file-target",MNT_DETACH));
    assert(id(fd,"")==mounted); close(fd);
    assert(!stat("/tmp/file-target",&st) && !st.st_size);
    puts("PASS guest file bind: selected-object open, data, metadata, readonly and exact old FD");
}
static void recursive(void) {
    assert(!mkdir("/tmp/tree",0755)); assert(!mkdir("/tmp/tree/sub",0755));
    assert(!mkdir("/tmp/recursive",0755)); assert(!mkdir("/tmp/nonrecursive",0755));
    assert(!mount("/tmp/source","/tmp/tree/sub",NULL,MS_BIND,NULL));
    assert(!mount("/tmp/tree","/tmp/nonrecursive",NULL,MS_BIND,NULL));
    assert(open("/tmp/nonrecursive/sub/value",O_RDONLY)<0 && errno==ENOENT);
    assert(!mount("/tmp/tree","/tmp/recursive",NULL,MS_BIND|MS_REC,NULL));
    int fd=open("/tmp/recursive/sub/value",O_RDONLY); assert(fd>=0); close(fd);
    assert(id(AT_FDCWD,"/tmp/recursive/sub")!=id(AT_FDCWD,"/tmp/tree/sub"));
    assert(!mount(NULL,"/tmp/recursive/sub",NULL,MS_BIND|MS_REMOUNT|MS_RDONLY,NULL));
    assert(open("/tmp/recursive/sub/value",O_RDWR)<0 && errno==EROFS);
    fd=open("/tmp/tree/sub/value",O_RDWR); assert(fd>=0); close(fd);
    assert(umount2("/tmp/recursive",0)<0 && errno==EBUSY);
    assert(!umount2("/tmp/recursive",MNT_DETACH));
    assert(open("/tmp/recursive/sub/value",O_RDONLY)<0 && errno==ENOENT);
    assert(!umount2("/tmp/nonrecursive",0));
    assert(!umount2("/tmp/tree/sub",0));
    puts("PASS recursive bind: copied subtree, independent IDs/policy and subtree detachment");
}
static void moving(void) {
    assert(!mkdir("/tmp/move-target",0755)); assert(!mkdir("/tmp/move-parent",0755));
    assert(!mkdir("/tmp/move-parent/slot",0755)); assert(!mkdir("/tmp/move-copy",0755));
    assert(!mount("/tmp/source","/tmp/move-target",NULL,MS_BIND,NULL));
    assert(!mount("/tmp/move-parent","/tmp/move-parent",NULL,MS_BIND,NULL));
    int held=open("/tmp/move-target",O_PATH|O_DIRECTORY); assert(held>=0);
    uint64_t old=id(held,"");
    assert(!chdir("/tmp/move-target"));
    assert(!mount("/tmp/move-target","/tmp/move-parent/slot",NULL,MS_MOVE,NULL));
    assert(id(held,"")==old && id(AT_FDCWD,"/tmp/move-parent/slot")==old);
    assert(open("/tmp/move-target/value",O_RDONLY)<0 && errno==ENOENT);
    int fd=openat(held,"value",O_RDONLY); assert(fd>=0); close(fd);
    char cwd[128]; assert(getcwd(cwd,sizeof(cwd)) && !strcmp(cwd,"/tmp/move-parent/slot"));
    assert(id(held,"..")==id(AT_FDCWD,"/tmp/move-parent"));
    assert(mount("/tmp/move-parent","/tmp/move-parent/slot",NULL,MS_MOVE,NULL)<0 && errno==EINVAL);
    assert(getcwd(cwd,sizeof(cwd)) && !strcmp(cwd,"/tmp/move-parent/slot"));
    /* The moved child predates its parent in stable storage. Recursive bind
     * must traverse topology, not assume allocation order is parent-first. */
    assert(!mount("/tmp/move-parent","/tmp/move-copy",NULL,MS_BIND|MS_REC,NULL));
    fd=open("/tmp/move-copy/slot/value",O_RDONLY); assert(fd>=0); close(fd);
    assert(id(AT_FDCWD,"/tmp/move-copy/slot")!=old);
    assert(!chdir("/tmp")); close(held);
    assert(!umount2("/tmp/move-copy",MNT_DETACH));
    assert(!umount2("/tmp/move-parent",MNT_DETACH));
    puts("PASS mount move: stable IDs/FDs, cwd/parent relocation, cycle rollback and recursive copy");
}
static int pivoting(void *argument) {
    int initial=argument!=NULL;
    if (!initial) {
        assert(!mkdir("/tmp/pivot",0755)); assert(!mkdir("/tmp/pivot/new",0755));
        assert(!mkdir("/tmp/pivot/new/old",0755)); assert(!mkdir("/tmp/pivot/stay",0755));
        assert(!mount("/tmp/pivot","/tmp/pivot",NULL,MS_BIND,NULL));
        assert(!chroot("/tmp/pivot"));
    } else {
        assert(!mkdir("/base-new",0755) && !mkdir("/base-new/old",0755));
        assert(!mkdir("/base-stay",0755));
    }
    assert(!chdir("/"));
    const char *next_path=initial ? "/base-new" : "/new";
    const char *put_path=initial ? "/base-new/old" : "/new/old";
    const char *stay=initial ? "/base-stay" : "/stay";
    assert(!mount(next_path,next_path,NULL,MS_BIND,NULL));
    int held=open("/",O_PATH|O_DIRECTORY); assert(held>=0);
    uint64_t previous=id(held,""), next=id(AT_FDCWD,next_path);
    assert(previous!=next);
    assert(syscall(SYS_pivot_root,next_path,stay)<0 && errno==EBUSY);
    assert(id(AT_FDCWD,"/")==previous);
    int commands[2], replies[2]; assert(!pipe(commands) && !pipe(replies));
    pid_t peer=fork(); assert(peer>=0);
    if (!peer) {
        assert(!chdir(stay));
        assert(write(replies[1],"r",1)==1);
        char byte; assert(read(commands[0],&byte,1)==1);
        assert(id(AT_FDCWD,"/")==next);
        char cwd[128]; assert(getcwd(cwd,sizeof(cwd)) && !strcmp(cwd,initial ? "/old/base-stay" : "/old/stay"));
        assert(!chdir("/") && id(AT_FDCWD,".")==next);
        assert(write(replies[1],"r",1)==1); _exit(0);
    }
    /* EVENT_WAIT: peer has captured its own cwd before the atomic root change;
     * the executable's alarm bounds a missing pipe acknowledgement. */
    char byte; assert(read(replies[0],&byte,1)==1);
    assert(!syscall(SYS_pivot_root,next_path,put_path));
    assert(id(AT_FDCWD,"/")==next && id(AT_FDCWD,".")==next);
    assert(id(held,"")==previous && id(AT_FDCWD,"/old")==previous);
    char cwd[128]; assert(getcwd(cwd,sizeof(cwd)) && !strcmp(cwd,"/"));
    assert(id(AT_FDCWD,"/..")==next);
    if (initial) assert(umount2("/",MNT_DETACH)<0 && errno==EBUSY);
    assert(write(commands[1],"p",1)==1 && read(replies[0],&byte,1)==1);
    int status; assert(waitpid(peer,&status,0)==peer && WIFEXITED(status) && !WEXITSTATUS(status));
    close(commands[0]); close(commands[1]); close(replies[0]); close(replies[1]);
    if (initial) {
        assert(!mkdir("/clone",0755));
        assert(!mount("/","/clone",NULL,MS_BIND|MS_REC,NULL));
        int child=open("/clone/old/base-stay",O_PATH|O_DIRECTORY); assert(child>=0); close(child);
        assert(id(AT_FDCWD,"/clone/old")!=previous);
        assert(!umount2("/clone",MNT_DETACH));
        assert(!mkdir("/old/base-return",0755));
        assert(!syscall(SYS_pivot_root,"/old","/old/base-return"));
        assert(id(AT_FDCWD,"/")==previous && id(AT_FDCWD,".")==previous);
        assert(id(AT_FDCWD,"/base-return")==next && id(held,"")==previous);
        assert(!syscall(SYS_pivot_root,"/base-return","/base-return/old"));
        assert(id(AT_FDCWD,"/")==next && id(AT_FDCWD,"/old")==previous);
    }
    assert(!umount2("/old",MNT_DETACH));
    assert(id(held,"")==previous);
    int retained=openat(held,stay+1,O_PATH|O_DIRECTORY); assert(retained>=0); close(retained);
    close(held);
    uint64_t before_copy=id(AT_FDCWD,"/");
    assert(!unshare(CLONE_NEWNS));
    assert(id(AT_FDCWD,"/")!=before_copy && id(AT_FDCWD,".")==id(AT_FDCWD,"/"));
    assert(getcwd(cwd,sizeof(cwd)) && !strcmp(cwd,"/"));
    puts(initial ? "PASS initial pivot root: peer roots, cwd, retained base, recursive copy, reverse pivot, detach and namespace copy"
        : "PASS pivot root: peer roots, selective cwd relocation, old dirfd and detached old root");
    return 0;
}
void test_mount_namespace_guest(void) {
    assert(!chdir("/tmp"));
    struct context c={.original=id(AT_FDCWD,"/"),.dir=open(".",O_PATH|O_DIRECTORY)};
    assert(c.dir>=0);
    void *stack=malloc(1024*1024); assert(stack);
    for (unsigned i=0;i<3;++i) {
        c.split=i!=0;
        int flags=SIGCHLD | (i==0 ? CLONE_NEWNS : i==1 ? CLONE_FS : 0);
        pid_t child=clone(copied,(char *)stack+1024*1024,flags,&c); assert(child>0);
        /* EVENT_WAIT: exact child completion before checking parent isolation;
         * the executable's alarm fails a missing completion. */
        int status; assert(waitpid(child,&status,0)==child);
        assert(WIFEXITED(status) && !WEXITSTATUS(status));
        assert(id(AT_FDCWD,"/")==c.original);
        char cwd[64]; assert(getcwd(cwd,sizeof(cwd)) && !strcmp(cwd,"/tmp"));
    }
    assert(clone(copied,(char *)stack+1024*1024,SIGCHLD|CLONE_FS|CLONE_NEWNS,&c)<0 && errno==EINVAL);
    root_busy();
    binding();
    churn();
    stacks();
    files();
    recursive();
    moving();
    for (uintptr_t initial=0;initial<2;++initial) {
        pid_t pivot=clone(pivoting,(char *)stack+1024*1024,SIGCHLD|CLONE_NEWNS,(void *)initial);
        assert(pivot>0);
        int status; assert(waitpid(pivot,&status,0)==pivot && WIFEXITED(status) && !WEXITSTATUS(status));
    }
    assert(id(AT_FDCWD,"/")==c.original);
    assert(!setresuid(1000,1000,1000));
    assert(unshare(CLONE_NEWNS)<0 && errno==EPERM);
    close(c.dir); free(stack);
    puts("PASS guest mount namespaces: clone, unshare, implicit FS split, retained dirfd, cwd, rollback and authority");
}

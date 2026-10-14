#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void files(const char *directory) {
    assert(!chdir(directory));
    int fd=open("data",O_CREAT|O_EXCL|O_RDWR,0600); assert(fd>=0);
    assert(write(fd,"content",7)==7 && !fdatasync(fd));
    assert(!link("data","alias") && !rename("data","renamed"));
    int dir=open(".",O_RDONLY|O_DIRECTORY); assert(dir>=0 && !fsync(dir));
    int opath=open("alias",O_PATH); assert(opath>=0);
    assert(fsync(opath)<0 && errno==EBADF);
    assert(fdatasync(opath)<0 && errno==EBADF);
    assert(syncfs(opath)<0 && errno==EBADF); close(opath);
    pid_t child=fork(); assert(child>=0);
    if (!child) { assert(!unlink("renamed") && !fsync(fd)); _exit(0); }
    int status; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    assert(!unlink("alias") && !fsync(fd) && !syncfs(fd));
    char value[8]={0}; assert(pread(fd,value,7,0)==7 && !strcmp(value,"content"));
    close(fd);
    fd=open("sync",O_CREAT|O_EXCL|O_RDWR|O_SYNC,0600); assert(fd>=0);
    assert(write(fd,"s",1)==1); close(fd); assert(!unlink("sync"));
    assert(!mkfifo("fifo",0600)); fd=open("fifo",O_RDWR|O_NONBLOCK); assert(fd>=0);
    assert(fsync(fd)<0 && errno==EINVAL); close(fd); assert(!unlink("fifo"));
    int pair[2]; assert(!pipe(pair)); assert(fsync(pair[0])<0 && errno==EINVAL); close(pair[0]); close(pair[1]);
    assert(!fsync(dir)); close(dir);
}
int main(int argc,char **argv) {
    assert(argc==2);
    if (!strcmp(argv[1],"protected")) {
        assert(!prctl(PR_SET_DUMPABLE,0));
        assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
        struct sock_filter code[]={BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
        struct sock_fprog program={.len=1,.filter=code};
        assert(!prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program));
    }
    assert(!mkdir("/tmp/durability",0700)); files("/tmp/durability");
    assert(!chdir("/") && !rmdir("/tmp/durability"));
    assert(!unshare(CLONE_NEWNS));
    assert(!mkdir("/tmp/durability-tmpfs",0700));
    assert(!mount("tmpfs","/tmp/durability-tmpfs","tmpfs",0,NULL));
    files("/tmp/durability-tmpfs"); assert(!chdir("/"));
    assert(!umount("/tmp/durability-tmpfs") && !rmdir("/tmp/durability-tmpfs"));
    const char *dirs[]={"/tmp/durability-lower","/tmp/durability-upper","/tmp/durability-work","/tmp/durability-merged"};
    for (unsigned i=0;i<4;++i) assert(!mkdir(dirs[i],0700));
    int fd=open("/tmp/durability-lower/lower",O_CREAT|O_RDWR,0600); assert(fd>=0);
    assert(write(fd,"before",6)==6 && !fsync(fd)); close(fd);
    const char *options="lowerdir=/tmp/durability-lower,upperdir=/tmp/durability-upper,workdir=/tmp/durability-work";
    int mounted=mount("overlay",dirs[3],"overlay",0,options);
    if (mounted) perror("durability overlay mount");
    assert(!mounted);
    files(dirs[3]);
    fd=open("lower",O_RDWR); assert(fd>=0);
    assert(pwrite(fd,"after!",6,0)==6 && !fsync(fd)); close(fd);
    assert(!link("lower","lower-alias") && !rename("lower","moved"));
    int dir=open(".",O_RDONLY|O_DIRECTORY); assert(dir>=0 && !fsync(dir)); close(dir);
    assert(!chdir("/") && !umount(dirs[3]));
    mounted=mount("overlay",dirs[3],"overlay",0,options);
    if (mounted) perror("durability overlay remount");
    assert(!mounted);
    fd=open("/tmp/durability-merged/moved",O_RDONLY); assert(fd>=0);
    char value[7]={0}; assert(read(fd,value,6)==6 && !strcmp(value,"after!")); close(fd);
    assert(!umount(dirs[3]));
    struct stat attached;
    if (!stat("/attached",&attached)) {
        /* Native attachments retain the host's hardlink/FIFO restrictions;
         * this branch verifies native data and directory barriers only. */
        fd=open("/attached/native-sync",O_CREAT|O_TRUNC|O_RDWR,0600); assert(fd>=0);
        assert(write(fd,"native",6)==6 && !fsync(fd) && !fdatasync(fd) && !syncfs(fd)); close(fd);
        assert(!unlink("/attached/native-sync"));
        dir=open("/attached",O_RDONLY|O_DIRECTORY); assert(dir>=0 && !fsync(dir)); close(dir);
    }
    puts("PASS guest durability calls: native data, namespace barrier, shared/unlinked FD, O_SYNC, tmpfs, overlay and error semantics");
}

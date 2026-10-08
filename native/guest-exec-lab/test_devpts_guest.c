#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <linux/magic.h>
#include <termios.h>
#include <unistd.h>

static unsigned entries(const char *path) {
    DIR *dir=opendir(path);
    if (!dir) fprintf(stderr,"devpts opendir %s: %s\n",path,strerror(errno));
    assert(dir); unsigned count=0;
    for (struct dirent *e;(e=readdir(dir));) {
        if (!strcmp(e->d_name,".") || !strcmp(e->d_name,"..") || !strcmp(e->d_name,"ptmx")) continue;
        ++count;
    }
    closedir(dir); return count;
}
int test_devpts_guest(int pid_namespace) {
    alarm(45);
    if (pid_namespace) {
        assert(!unshare(CLONE_NEWPID));
        pid_t child=fork(); assert(child>=0);
        if (!child) _exit(test_devpts_guest(0));
        int status; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
        puts("PASS guest devpts: PID namespace terminal ownership"); return 0;
    }
    assert(!unshare(CLONE_NEWNS));
    assert(!mkdir("/tmp/pts-a",0700) && !mkdir("/tmp/pts-b",0700));
    assert(!mount("devpts","/tmp/pts-a","devpts",MS_NOSUID|MS_NOEXEC,"newinstance,ptmxmode=0666,mode=620"));
    assert(!mount("devpts","/tmp/pts-b","devpts",MS_NOSUID|MS_NOEXEC,"newinstance,ptmxmode=0666,mode=600"));
    assert(!entries("/tmp/pts-a") && !entries("/tmp/pts-b"));
    int master=open("/tmp/pts-a/ptmx",O_RDWR|O_NOCTTY|O_CLOEXEC); assert(master>=0);
    unsigned index; assert(!ioctl(master,TIOCGPTN,&index));
    int locked=0; assert(!ioctl(master,TIOCSPTLCK,&locked));
    char path[96]; snprintf(path,sizeof(path),"/tmp/pts-a/%u",index);
    struct stat st; assert(!stat(path,&st) && (st.st_mode&0777)==0620 && S_ISCHR(st.st_mode));
    int slave=open(path,O_RDWR|O_NOCTTY|O_CLOEXEC); assert(slave>=0);
    assert(!chmod(path,0600) && !fstat(slave,&st) && (st.st_mode&0777)==0600);
    struct termios term; assert(!tcgetattr(slave,&term)); cfmakeraw(&term); assert(!tcsetattr(slave,TCSANOW,&term));
    char byte;
    assert(write(master,"x",1)==1 && read(slave,&byte,1)==1 && byte=='x');
    assert(write(slave,"y",1)==1 && read(master,&byte,1)==1 && byte=='y');
    struct statfs filesystem; assert(!fstatfs(slave,&filesystem) && filesystem.f_type==DEVPTS_SUPER_MAGIC);
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        close(slave); close(master);
        assert(setsid()==getpid());
        int terminal=open(path,O_RDWR|O_CLOEXEC); assert(terminal>=0);
        pid_t foreground=0; assert(!ioctl(terminal,TIOCGPGRP,&foreground) && foreground==getpgrp());
        assert(!ioctl(terminal,TIOCSPGRP,&foreground));
        int controlling=open("/dev/tty",O_RDWR|O_CLOEXEC); assert(controlling>=0);
        assert(!ioctl(controlling,TIOCGPGRP,&foreground) && foreground==getpgrp());
        close(controlling); close(terminal); _exit(0);
    }
    int status;
    /* EVENT_WAIT: session/controlling-terminal assertions finish in the child;
     * the fixture alarm bounds failure, with no settling delay. */
    assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    snprintf(path,sizeof(path),"/tmp/pts-b/%u",index);
    assert(open(path,O_RDWR)<0 && errno==ENOENT);
    assert(entries("/tmp/pts-a")==1 && !entries("/tmp/pts-b"));
    close(slave); close(master);
    assert(!entries("/tmp/pts-a"));
    assert(!umount2("/tmp/pts-a",0) && !umount2("/tmp/pts-b",0));
    assert(!rmdir("/tmp/pts-a") && !rmdir("/tmp/pts-b"));
    puts("PASS guest devpts: private membership, native terminal IO, controlling session, logical modes and close lifetime");
    return 0;
}

#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/socket.h>
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
static void ownership(void) {
    struct stat st;
    int directory=open("/tmp/pts-a",O_PATH|O_DIRECTORY|O_CLOEXEC); assert(directory>=0);
    int modefd=open("/tmp/pts-a",O_RDONLY|O_DIRECTORY|O_CLOEXEC); assert(modefd>=0);
    int ptmx=open("/tmp/pts-a/ptmx",O_PATH|O_CLOEXEC); assert(ptmx>=0);
    assert(!fchownat(directory,"",1234,5678,AT_EMPTY_PATH));
    assert(!fchownat(ptmx,"",2345,6789,AT_EMPTY_PATH));
    assert(!chmod("/tmp/pts-a",0711));
    assert(!fstat(directory,&st) && st.st_uid==1234 && st.st_gid==5678 && (st.st_mode&07777)==0711);
    assert(!fstat(ptmx,&st) && st.st_uid==2345 && st.st_gid==6789 && (st.st_mode&07777)==0666);
    assert(!stat("/tmp/pts-b",&st) && !st.st_uid && !st.st_gid && (st.st_mode&07777)==0755);
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        assert(!setresgid(1000,1000,1000) && !setresuid(1000,1000,1000));
        assert(fchownat(directory,"",1000,1000,AT_EMPTY_PATH)==-1 && errno==EPERM);
        assert(fchownat(ptmx,"",1000,1000,AT_EMPTY_PATH)==-1 && errno==EPERM);
        assert(fchmod(modefd,0777)==-1 && errno==EPERM);
        _exit(0);
    }
    int status;
    /* EVENT_WAIT: child checks unprivileged metadata denial; fixture alarm bounds failure. */
    assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    close(directory); close(ptmx); close(modefd);
}
static void peer_transfer(int master,int slave) {
    int sockets[2]; assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,sockets));
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        close(sockets[0]); close(master); close(slave);
        assert(!unshare(CLONE_NEWNS));
        assert(!umount2("/tmp/pts-a",MNT_DETACH));
        assert(!mount("devpts","/tmp/pts-a","devpts",0,"newinstance,ptmxmode=0666"));
        char byte; struct iovec iov={&byte,1};
        union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control;
        struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control)};
        assert(recvmsg(sockets[1],&msg,MSG_CMSG_CLOEXEC)==1 && !(msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC)));
        struct cmsghdr *c=CMSG_FIRSTHDR(&msg); assert(c && c->cmsg_type==SCM_RIGHTS);
        int received; memcpy(&received,CMSG_DATA(c),sizeof(received));
        int peer=ioctl(received,TIOCGPTPEER,O_RDWR|O_NOCTTY|O_NONBLOCK);
        if (peer<0) perror("TIOCGPTPEER");
        assert(peer>=0 && !(fcntl(peer,F_GETFD)&FD_CLOEXEC) && (fcntl(peer,F_GETFL)&O_NONBLOCK));
        struct stat st; assert(!fstat(peer,&st) && !st.st_uid && !st.st_gid && (st.st_mode&0777)==0600);
        assert(!fchown(peer,1234,5678) && !fchmod(peer,0620));
        assert(!fstat(peer,&st) && st.st_uid==1234 && st.st_gid==5678 && (st.st_mode&0777)==0620);
        assert(!entries("/tmp/pts-a"));
        close(peer); close(received); close(sockets[1]); _exit(0);
    }
    close(sockets[1]);
    char byte=0; struct iovec iov={&byte,1};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control={0};
    struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control)};
    struct cmsghdr *c=CMSG_FIRSTHDR(&msg);
    c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS; c->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c),&master,sizeof(master)); assert(sendmsg(sockets[0],&msg,0)==1);
    int status;
    /* EVENT_WAIT: peer metadata after namespace replacement; alarm bounds failure. */
    assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    struct stat st; assert(!fstat(slave,&st) && st.st_uid==1234 && st.st_gid==5678 && (st.st_mode&0777)==0620);
    assert(!fchown(slave,0,0) && !fchmod(slave,0600)); close(sockets[0]);
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
    ownership();
    int master=open("/tmp/pts-a/ptmx",O_RDWR|O_NOCTTY|O_CLOEXEC); assert(master>=0);
    unsigned index; assert(!ioctl(master,TIOCGPTN,&index));
    int locked_peer=ioctl(master,TIOCGPTPEER,O_RDWR|O_NOCTTY);
    if (locked_peer!=-1 || errno!=EIO) fprintf(stderr,"locked peer=%d errno=%d\n",locked_peer,errno);
    assert(locked_peer==-1 && errno==EIO);
    int locked=0; assert(!ioctl(master,TIOCSPTLCK,&locked));
    char path[96]; snprintf(path,sizeof(path),"/tmp/pts-a/%u",index);
    struct stat st; assert(!stat(path,&st) && (st.st_mode&0777)==0620 && S_ISCHR(st.st_mode));
    assert(!st.st_uid && !st.st_gid);
    int slave=open(path,O_RDWR|O_NOCTTY|O_CLOEXEC); assert(slave>=0);
    assert(!chmod(path,0600) && !fstat(slave,&st) && (st.st_mode&0777)==0600);
    int peer=ioctl(master,TIOCGPTPEER,O_RDWR|O_NOCTTY|O_CLOEXEC);
    assert(peer>=0 && (fcntl(peer,F_GETFD)&FD_CLOEXEC));
    assert(!fstat(peer,&st) && (st.st_mode&0777)==0600); close(peer);
    peer_transfer(master,slave);
    struct termios term; assert(!tcgetattr(slave,&term)); cfmakeraw(&term); assert(!tcsetattr(slave,TCSANOW,&term));
    char byte;
    assert(write(master,"x",1)==1 && read(slave,&byte,1)==1 && byte=='x');
    assert(write(slave,"y",1)==1 && read(master,&byte,1)==1 && byte=='y');
    struct statfs filesystem; assert(!fstatfs(slave,&filesystem) && filesystem.f_type==DEVPTS_SUPER_MAGIC);
    for (int via_peer=0;via_peer<2;++via_peer) {
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        close(slave);
        assert(setsid()==getpid());
        int terminal=via_peer ? ioctl(master,TIOCGPTPEER,O_RDWR|O_CLOEXEC) : open(path,O_RDWR|O_CLOEXEC);
        assert(terminal>=0); close(master);
        pid_t foreground=0; assert(!ioctl(terminal,TIOCGPGRP,&foreground) && foreground==getpgrp());
        assert(!ioctl(terminal,TIOCSPGRP,&foreground));
        int controlling=open("/dev/tty",O_RDWR|O_CLOEXEC);
        if (controlling<0) perror("open controlling tty");
        assert(controlling>=0);
        assert(!ioctl(controlling,TIOCGPGRP,&foreground) && foreground==getpgrp());
        /* Persistent FD selectors survive close/reuse and must not hide PID
         * translation when this descriptor later names a terminal. */
        for (int kind=0;kind<2;++kind) {
            int reused=kind ? open("/proc/self/status",O_RDONLY|O_CLOEXEC)
                : inotify_init1(IN_CLOEXEC);
            assert(reused>=0);
            assert(dup3(controlling,reused,O_CLOEXEC)==reused);
            assert(!ioctl(reused,TIOCGPGRP,&foreground) && foreground==getpgrp());
            assert(!ioctl(reused,TIOCSPGRP,&foreground));
            pid_t session=0;
            assert(!ioctl(reused,TIOCGSID,&session) && session==getsid(0));
            close(reused);
        }
        close(controlling); close(terminal); _exit(0);
    }
    int status;
    /* EVENT_WAIT: session/controlling-terminal assertions finish in the child;
     * the fixture alarm bounds failure, with no settling delay. */
    assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    }
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

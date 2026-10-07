#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "fs_wire.h"
#include "event_wait.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int fail_memfd, fail_map, fail_map_after=-1;
void test_mount_policy_map_failure_after(int count) { fail_map_after=count; }
int __real_memfd_create(const char *, unsigned);
int __wrap_memfd_create(const char *name, unsigned flags) {
    if (fail_memfd) { errno=ENOSYS; return -1; }
    return __real_memfd_create(name,flags);
}
void *__real_mmap(void *, size_t, int, int, int, off_t);
void *__wrap_mmap(void *address, size_t size, int prot, int flags, int fd, off_t offset) {
    /* Inject only the policy mapping, not allocator/diagnostic mappings that
     * libc may need while releasing a partially imported graph. */
    if (size==4*sizeof(uint32_t) && flags==MAP_SHARED && fd>=0 && !offset) {
        if (fail_map || fail_map_after==0) { errno=ENOMEM; return MAP_FAILED; }
        if (fail_map_after>0) --fail_map_after;
    }
    return __real_mmap(address,size,prot,flags,fd,offset);
}
static unsigned descriptors(void) {
    DIR *dir=opendir("/proc/self/fd"); assert(dir);
    unsigned n=0; struct dirent *entry;
    while ((entry=readdir(dir))) if (entry->d_name[0]!='.') ++n;
    assert(!closedir(dir)); return n;
}
static void ready(int fd) {
    /* EVENT_WAIT: exact fixture packet; expiry fails without assuming progress. */
    assert(!md_event_wait_fd(fd,POLLIN,md_event_now()+5000000000LL));
}
static void send_byte(int fd, char byte) {
    assert(md_fs_send(fd,&byte,1,&(struct md_fs_rights){0})==1);
}
static char receive_byte(int fd) {
    ready(fd); char byte; struct md_fs_rights rights={0};
    assert(md_fs_receive(fd,&byte,1,&rights)==1 && !rights.count); return byte;
}
static void channel(int fds[2]) {
    assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0,fds));
}
static void reap(pid_t child) {
    /* EVENT_WAIT: exact fixture child; outer alarm fails a stuck process. */
    int status; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
}
static pid_t start(const char *mode, int fd, const char *base) {
    pid_t parent=getpid(), child=fork(); assert(child>=0);
    if (!child) {
        assert(!prctl(PR_SET_PDEATHSIG,SIGKILL) && getppid()==parent);
        assert(!fcntl(fd,F_SETFD,0)); char number[16]; snprintf(number,sizeof(number),"%d",fd);
        execl("/proc/self/exe","mount-policy",mode,number,base,(char *)NULL); _exit(90);
    }
    return child;
}
static int receive_policy(int channel) {
    ready(channel); char byte; struct md_fs_rights rights={0};
    assert(md_fs_receive(channel,&byte,1,&rights)==1 && byte=='p' && rights.count==1);
    return rights.fd[0];
}
static void basics(void) {
    unsigned before=descriptors(); struct md_mount_policy p={0}, observer={0};
    for (unsigned i=0;i<10000;++i) {
        assert(!md_mount_policy_set(&p,i&1) && md_mount_policy_flags(&p)==(i&1));
    }
    assert(!p.page && descriptors()==before);
    assert(md_mount_policy_set(&p,2)==-EINVAL && md_mount_policy_flags(&p)==MD_MOUNT_READONLY);
    fail_memfd=1; assert(md_mount_policy_share(&p)==-ENOSYS); fail_memfd=0;
    assert(!p.page && md_mount_policy_flags(&p)==MD_MOUNT_READONLY && descriptors()==before);
    fail_map=1; assert(md_mount_policy_share(&p)==-ENOMEM); fail_map=0;
    assert(!p.page && md_mount_policy_flags(&p)==MD_MOUNT_READONLY && descriptors()==before);
    struct rlimit old, limited; assert(!getrlimit(RLIMIT_NOFILE,&old)); limited=old; limited.rlim_cur=0;
    assert(!setrlimit(RLIMIT_NOFILE,&limited)); assert(md_mount_policy_share(&p)==-EMFILE);
    assert(!setrlimit(RLIMIT_NOFILE,&old));
    assert(!p.page && md_mount_policy_flags(&p)==MD_MOUNT_READONLY && descriptors()==before);
    int fd=md_mount_policy_share(&p); assert(fd>=0 && descriptors()==before+1);
    assert(md_mount_policy_share(&p)==fd && descriptors()==before+1);
    int imported=fcntl(fd,F_DUPFD_CLOEXEC,3); assert(imported>=0);
    fail_map=1; assert(md_mount_policy_import(&observer,imported)==-ENOMEM); fail_map=0;
    assert(!observer.page && fcntl(imported,F_GETFD)>=0);
    assert(!md_mount_policy_import(&observer,imported));
    assert(md_mount_policy_set(&observer,0)==-EPERM);
    assert(md_mount_policy_import(&observer,fd)==-EINVAL && fcntl(fd,F_GETFD)>=0);
    assert(md_mount_policy_share(&observer)==imported);
    assert(!setrlimit(RLIMIT_NOFILE,&limited));
    for (unsigned i=0;i<10000;++i) {
        assert(!md_mount_policy_set(&p,i&1) && md_mount_policy_flags(&observer)==(i&1));
        assert(md_mount_policy_share(&p)==fd && md_mount_policy_share(&observer)==imported);
    }
    assert(!setrlimit(RLIMIT_NOFILE,&old));
    uint32_t zero=0;
    assert(pwrite(imported,&zero,sizeof(zero),12)<0 && errno==EPERM);
    assert(ftruncate(imported,0)<0 && errno==EPERM);
    assert(ftruncate(imported,4096)<0 && errno==EPERM);
    assert(mmap(NULL,16,PROT_READ|PROT_WRITE,MAP_SHARED,imported,0)==MAP_FAILED && errno==EPERM);
    assert(mprotect(observer.page,16,PROT_READ|PROT_WRITE)<0 && errno==EACCES);
    md_mount_policy_close(&p);
    assert(md_mount_policy_flags(&observer)==MD_MOUNT_READONLY);
    md_mount_policy_close(&observer); md_mount_policy_close(&observer);
    assert(descriptors()==before);
    puts("PASS mount policy: lazy FD, no-slot reads/updates, writer-only changes, independent observer lifetime and rollback");
}
static void malformed(void) {
    unsigned before=descriptors();
    for (unsigned i=0;i<8;++i) {
        int fd=memfd_create("bad-policy",MFD_CLOEXEC|MFD_ALLOW_SEALING); assert(fd>=0);
        uint32_t header[5]={0x4d444d50U,1,0,0,0}; size_t bytes=16;
        int seals=F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_FUTURE_WRITE|F_SEAL_SEAL;
        switch (i) {
        case 0: ++header[0]; break;
        case 1: ++header[1]; break;
        case 2: ++header[2]; break;
        case 3: header[3]=2; break;
        case 4: bytes=12; break;
        case 5: bytes=20; break;
        case 6: seals&=~F_SEAL_FUTURE_WRITE; break;
        case 7: assert(!fcntl(fd,F_SETFD,0)); break;
        }
        assert(write(fd,header,bytes)==(ssize_t)bytes && !fcntl(fd,F_ADD_SEALS,seals));
        struct md_mount_policy p={0}; unsigned current=descriptors();
        assert(md_mount_policy_import(&p,fd)==(i==7 ? -EINVAL : -EPROTO));
        assert(!p.page && !p.local && descriptors()==current && fcntl(fd,F_GETFD)>=0);
        close(fd);
    }
    int fd=open("/dev/null",O_RDONLY|O_CLOEXEC); assert(fd>=0);
    struct md_mount_policy p={0}; assert(md_mount_policy_import(&p,fd)==-EPROTO); close(fd);
    assert(descriptors()==before);
    puts("PASS mount policy import: malformed type/header/size/seals/flags rejected without FD ownership or partial publication");
}
static void sealing_rejection(void) {
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        struct sock_filter code[]={
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_fcntl,0,3),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_ADD_SEALS,0,1),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EOPNOTSUPP),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
        struct sock_fprog program={sizeof(code)/sizeof(code[0]),code};
        assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
        assert(!prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program));
        unsigned before=descriptors(); struct md_mount_policy p={0};
        assert(!md_mount_policy_set(&p,MD_MOUNT_READONLY));
        assert(md_mount_policy_share(&p)==-EOPNOTSUPP && !p.page);
        assert(md_mount_policy_flags(&p)==MD_MOUNT_READONLY && descriptors()==before);
        assert(!md_mount_policy_set(&p,0)); md_mount_policy_close(&p); _exit(0);
    }
    reap(child);
    puts("PASS mount policy sealing denial: publication rolls back while local policy remains usable");
}
static struct md_filesystem filesystem(const char *base, int create) {
    char store[PATH_MAX], host[PATH_MAX], path[PATH_MAX];
    snprintf(store,sizeof(store),"%s/policy-store",base);
    snprintf(host,sizeof(host),"%s/policy-host",base);
    struct md_filesystem fs={0}; assert(!md_inode_store_open(store,create,&fs.store));
    if (create) {
        assert(!mkdir(host,0700) && !md_inode_mkdir(fs.store,-1,"/volume",0700));
        snprintf(path,sizeof(path),"%s/value",host);
        int fd=open(path,O_CREAT|O_RDWR|O_CLOEXEC,0600); assert(fd>=0);
        assert(write(fd,"value",5)==5); close(fd);
    }
    assert(!md_fs_mounts_open(&fs,&(struct md_fs_attachment){host,"/volume",0},1));
    return fs;
}
static void descriptor_checks(struct md_filesystem *fs, struct md_fs_anchor *origin, unsigned readonly) {
    struct md_fs_request q={.operation=MD_FS_REOPEN,.directory={md_fs_anchor_fd(origin),-1},
        .origin={origin,NULL},.flags=O_RDWR};
    struct md_fs_result r; md_fs_execute(fs,&q,&r,NULL);
    if (readonly) assert(r.error==-EROFS && r.fd<0);
    else { assert(!r.error && r.fd>=0); close(r.fd); }
    q.flags=O_RDONLY; md_fs_execute(fs,&q,&r,NULL); assert(!r.error); close(r.fd);
    q=(struct md_fs_request){.operation=MD_FS_ACCESS,.directory={md_fs_anchor_fd(origin),-1},
        .origin={origin,NULL},.mode=W_OK};
    md_fs_execute(fs,&q,&r,NULL); assert(r.error==(readonly ? -EROFS : 0));
    q.operation=MD_FS_XATTR_OPEN;
    md_fs_execute(fs,&q,&r,NULL); assert(r.error==(readonly ? -EROFS : -EXDEV));
}
static void engine_checks(struct md_filesystem *fs, struct md_fs_anchor *origin, unsigned readonly) {
    descriptor_checks(fs,origin,readonly);
    struct md_fs_request q={.operation=MD_FS_OPEN,.directory={-1,-1},.path={"/volume/value",NULL},.flags=O_RDWR};
    struct md_fs_result r; md_fs_execute(fs,&q,&r,NULL);
    if (readonly) assert(r.error==-EROFS && r.fd<0);
    else { assert(!r.error && r.fd>=0); close(r.fd); }
    char bytes[8192]; int fd=md_fs_mount_table(fs,1,O_RDONLY); assert(fd>=0);
    ssize_t n=read(fd,bytes,sizeof(bytes)-1); assert(n>0); bytes[n]=0; close(fd);
    assert(strstr(bytes,readonly ? " /volume ro - none attachment ro" : " /volume rw - none attachment rw"));
}
int test_mount_policy_child(int argc, char **argv) {
    if (argc!=4 || (strcmp(argv[1],"--policy-reader") && strcmp(argv[1],"--policy-writer"))) return -1;
    /* EVENT_WAIT: fixture process failure bound, not a settling delay. */
    alarm(30); int fd=atoi(argv[2]); assert(!fcntl(fd,F_SETFD,FD_CLOEXEC));
    if (!strcmp(argv[1],"--policy-writer")) {
        struct md_mount_policy p={0}; int policy=md_mount_policy_share(&p); assert(policy>=0);
        assert(!md_mount_policy_set(&p,MD_MOUNT_READONLY));
        assert(md_fs_send(fd,"p",1,&(struct md_fs_rights){.count=1,.fd={policy}})==1);
        md_mount_policy_close(&p); close(fd); return 0;
    }
    struct md_filesystem fs=filesystem(argv[3],0);
    assert(!md_mount_policy_import(&fs.mounts->tree->mounts[0].policy,receive_policy(fd)));
    struct md_fs_anchor *origin=NULL;
    struct md_fs_request q={.operation=MD_FS_OPEN,.directory={-1,-1},.path={"/volume/value",NULL},.flags=O_PATH};
    struct md_fs_result r; md_fs_execute(&fs,&q,&r,&(struct md_fs_output){.origin=&origin});
    if (r.error) fprintf(stderr,"policy reader capture: %d\n",r.error);
    assert(!r.error && origin); close(r.fd);
    engine_checks(&fs,origin,0); send_byte(fd,'0');
    const char expected[]={'1','0','e'};
    for (unsigned i=0;i<sizeof(expected);++i) {
        assert(receive_byte(fd)==expected[i]); engine_checks(&fs,origin,i!=1); send_byte(fd,expected[i]);
    }
    md_fs_mounts_close(&fs);
    assert(!md_fs_mounts_open(&fs,NULL,0));
    descriptor_checks(&fs,origin,1);
    md_fs_anchor_release(origin); md_fs_mounts_close(&fs); md_inode_store_close(fs.store); close(fd); return 0;
}
static void processes(const char *base) {
    unsigned before=descriptors();
    struct md_filesystem fs=filesystem(base,1);
    struct md_mount_policy *p=&fs.mounts->tree->mounts[0].policy;
    int policy=md_mount_policy_share(p); assert(policy>=0);
    int fds[2]; channel(fds);
    pid_t child=start("--policy-reader",fds[1],base); close(fds[1]);
    assert(md_fs_send(fds[0],"p",1,&(struct md_fs_rights){.count=1,.fd={policy}})==1);
    assert(receive_byte(fds[0])=='0');
    assert(!md_mount_policy_set(p,MD_MOUNT_READONLY)); send_byte(fds[0],'1'); assert(receive_byte(fds[0])=='1');
    assert(!md_mount_policy_set(p,0)); send_byte(fds[0],'0'); assert(receive_byte(fds[0])=='0');
    assert(!md_mount_policy_set(p,MD_MOUNT_READONLY)); md_fs_mounts_close(&fs); md_inode_store_close(fs.store);
    send_byte(fds[0],'e'); assert(receive_byte(fds[0])=='e'); close(fds[0]); reap(child);
    assert(descriptors()==before);
    channel(fds); child=start("--policy-writer",fds[1],base); close(fds[1]);
    reap(child);
    struct md_mount_policy observer={0}; assert(!md_mount_policy_import(&observer,receive_policy(fds[0])));
    assert(md_mount_policy_flags(&observer)==MD_MOUNT_READONLY);
    assert(md_mount_policy_set(&observer,0)==-EPERM);
    md_mount_policy_close(&observer); close(fds[0]); assert(descriptors()==before);
    puts("PASS mount policy exec peers: live engine open/reopen/access/xattr/mountinfo, retained anchors, source view/SQLite release and queued state after writer exit");
}
void test_mount_policy(const char *base) {
    /* EVENT_WAIT: complete fixture failure bound, including exact child reaping. */
    alarm(60); basics(); malformed(); sealing_rejection(); processes(base); alarm(0);
}

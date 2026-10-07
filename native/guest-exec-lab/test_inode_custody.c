#define _GNU_SOURCE
#include "inode_custody.h"
#include "inode_internal.h"
#include "sealed_manifest.h"
#include "fs_wire.h"
#include "event_wait.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

void test_mount_allocation_failure_after(int count);
static unsigned descriptors(void) {
    DIR *d=opendir("/proc/self/fd"); assert(d); unsigned n=0; struct dirent *e;
    while ((e=readdir(d))) if (e->d_name[0]!='.') ++n;
    assert(!closedir(d)); return n;
}
static void path(char *out, const char *base, const char *leaf) {
    assert(snprintf(out,PATH_MAX,"%s/%s",base,leaf)<PATH_MAX);
}
static struct md_inode_store *store(const char *base, const char *leaf, int create) {
    char name[PATH_MAX]; path(name,base,leaf); struct md_inode_store *s=NULL;
    assert(!md_inode_store_open(name,create,&s)); return s;
}
static void contents(struct md_inode_store *s, const char *name, const char *value) {
    int fd=md_inode_open(s,-1,name,O_CREAT|O_WRONLY,0600); assert(fd>=0);
    assert(write(fd,value,strlen(value))==(ssize_t)strlen(value)); close(fd);
}
static struct md_inode_store *layers(const char *base) {
    struct md_inode_store *a=store(base,"lower",1), *b=store(base,"middle",1), *c=store(base,"upper",1);
    contents(a,"/first","first"); assert(!md_inode_store_seal(a) && !md_inode_snapshot(a,b));
    contents(b,"/second","second"); assert(!md_inode_store_seal(b) && !md_inode_snapshot(b,c));
    md_inode_store_close(a); md_inode_store_close(b); return c;
}
static void maintenance(const char *base, const char *leaf, int blocked) {
    char name[PATH_MAX]; path(name,base,leaf);
    struct md_inode_store *s=NULL; int r=md_inode_store_open_exclusive(name,&s);
    if (blocked) assert(r==-EBUSY && !s);
    else { assert(!r && s); md_inode_store_close(s); }
}
static void all_maintenance(const char *base, const char *upper, int blocked) {
    maintenance(base,upper,blocked); maintenance(base,"lower",blocked); maintenance(base,"middle",blocked);
}
static void native_maintenance(const char *base, const char *leaf, int blocked) {
    char name[PATH_MAX]; path(name,base,leaf);
    int fd=open(name,O_RDONLY|O_DIRECTORY|O_CLOEXEC); assert(fd>=0);
    int r=flock(fd,LOCK_EX|LOCK_NB);
    if (blocked) assert(r<0 && errno==EWOULDBLOCK);
    else assert(!r);
    close(fd);
}
static void relation(struct md_inode_lifetime *p, unsigned source, int held) {
    struct stat a,b; assert(!fstat(p->sources[source],&a) && !fstatat(p->source_leases[source],"objects",&b,0));
    assert(md_fd_identity_same(md_fd_identity(&a),md_fd_identity(&b)));
    /* A fresh description tests exclusion; never flock the imported lease. */
    int other=openat(p->source_leases[source],".",O_RDONLY|O_DIRECTORY|O_CLOEXEC); assert(other>=0);
    int r=flock(other,LOCK_EX|LOCK_NB);
    if (held) assert(r<0 && errno==EWOULDBLOCK);
    else assert(!r);
    close(other);
}
static void mutate_manifest(struct md_inode_custody_parcel *p, unsigned word, uint32_t value,
        int seals, int size_change) {
    uint32_t data[2600]; ssize_t n=pread(p->fd[0],data,sizeof(data),0); assert(n>=32);
    data[word]=value; int fd=memfd_create("bad-custody",MFD_CLOEXEC|MFD_ALLOW_SEALING); assert(fd>=0);
    assert(write(fd,data,(size_t)n)==n);
    if (size_change) assert(!ftruncate(fd,n+size_change));
    assert(!fcntl(fd,F_ADD_SEALS,seals)); close(p->fd[0]); p->fd[0]=fd;
}
static void failures(struct md_inode_store *s, const char *base) {
    unsigned before=descriptors(); struct md_inode_lifetime *owner=md_inode_store_lifetime(s);
    struct md_inode_custody_parcel p={0};
    for (unsigned i=0;i<17;++i) {
        assert(!md_inode_custody_export(owner,&p) && p.count==6);
        int seals=F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_WRITE|F_SEAL_SEAL;
        switch (i) {
        case 0: mutate_manifest(&p,0,0,seals,0); break;
        case 1: mutate_manifest(&p,1,2,seals,0); break;
        case 2: mutate_manifest(&p,2,256,seals,0); break;
        case 3: mutate_manifest(&p,3,1,seals,0); break;
        case 4: mutate_manifest(&p,4,~0U,seals,0); break;
        case 5: mutate_manifest(&p,8,0,seals,0); break;
        case 6: mutate_manifest(&p,8,256,seals,0); break;
        case 7: mutate_manifest(&p,9,1,seals,0); break;
        case 8: mutate_manifest(&p,18,1,seals,0); break;
        case 9: mutate_manifest(&p,1,1,seals,1); break;
        case 10: mutate_manifest(&p,1,1,seals&~F_SEAL_WRITE,0); break;
        case 11: { int fd=p.fd[2]; p.fd[2]=p.fd[3]; p.fd[3]=fd; break; }
        case 12: { int fd=p.fd[2]; p.fd[2]=p.fd[4]; p.fd[4]=fd; break; }
        case 13: close(p.fd[--p.count]); break;
        case 14: assert(!fcntl(p.fd[1],F_SETFD,0)); break;
        case 15: close(p.fd[2]); p.fd[2]=p.fd[1]; break;
        case 16: {
            int fd=openat(owner->root,".",O_PATH|O_DIRECTORY|O_CLOEXEC); assert(fd>=0);
            close(p.fd[1]); p.fd[1]=fd; break;
        }
        }
        struct md_inode_lifetime *received=NULL;
        assert(md_inode_custody_import(&p,owner->root,&received)<0 && !p.count && !received);
        assert(descriptors()==before);
    }
    assert(!md_inode_custody_export(owner,&p));
    struct md_inode_lifetime *received=NULL; test_mount_allocation_failure_after(0);
    int r=md_inode_custody_import(&p,owner->root,&received);
    test_mount_allocation_failure_after(-1);
    assert(r==-ENOMEM && !p.count && !received && descriptors()==before);
    struct md_inode_store *foreign=store(base,"foreign",1);
    assert(!md_inode_custody_export(owner,&p));
    assert(md_inode_custody_import(&p,foreign->lifetime->root,&received)==-ESTALE && !received);
    md_inode_store_close(foreign); assert(descriptors()==before);
    /* Exactly four slots allow manifest/root/first lower, then fail midway. */
    struct rlimit old, limit; assert(!getrlimit(RLIMIT_NOFILE,&old)); limit=old;
    if (limit.rlim_cur>128) limit.rlim_cur=128;
    assert(!setrlimit(RLIMIT_NOFILE,&limit)); int fill[128]; unsigned count=0; int fd;
    while ((fd=fcntl(owner->root,F_DUPFD_CLOEXEC,3))>=0) { assert(count<128); fill[count++]=fd; }
    assert(errno==EMFILE && count>=4);
    for (unsigned i=0;i<4;++i) close(fill[--count]);
    r=md_inode_custody_export(owner,&p);
    assert(!setrlimit(RLIMIT_NOFILE,&old));
    while (count) close(fill[--count]);
    assert(r==-EMFILE && !p.count && descriptors()==before);
    /* A failed export must not unlock or convert any original description. */
    all_maintenance(base,"upper",1);
    puts("PASS inode custody rollback: malformed identities/rights, wrong store, allocation and partial-FD exhaustion");
}
static void local(const char *base) {
    unsigned before=descriptors(); struct md_inode_store *s=layers(base); failures(s,base);
    struct md_inode_custody_parcel p={0};
    assert(!md_inode_custody_export(s->lifetime,&p));
    int root=openat(s->lifetime->root,".",O_PATH|O_DIRECTORY|O_CLOEXEC); assert(root>=0);
    struct md_inode_lifetime *received=NULL;
    assert(!md_inode_custody_import(&p,root,&received) && !p.count);
    assert(md_inode_lifetime_same(received,s->lifetime));
    unsigned current=descriptors();
    for (unsigned i=0;i<10000;++i) md_inode_lifetime_release(md_inode_lifetime_retain(received));
    assert(descriptors()==current);
    relation(received,1,1); relation(received,2,1);
    assert(!md_inode_custody_export(received,&p));
    md_inode_lifetime_release(received); received=NULL; md_inode_store_close(s);
    all_maintenance(base,"upper",1);
    assert(!md_inode_custody_import(&p,root,&received)); close(root);
    all_maintenance(base,"upper",1);
    md_inode_lifetime_release(received); all_maintenance(base,"upper",0);
    assert(descriptors()==before);
    puts("PASS inode custody lifetime: real layered stores, allocation-free pins, forwarding, SQLite teardown and last-owner unlock");
}
static void wait_fd(int fd, short events) {
    /* EVENT_WAIT: bounded fixture channel progress; timeout fails the test. */
    assert(!md_event_wait_fd(fd,events,md_event_now()+5000000000LL));
}
static void send_packet(int fd, const void *data, size_t size, const struct md_fs_rights *rights) {
    long r;
    while ((r=md_fs_send(fd,data,size,rights))==-EAGAIN) wait_fd(fd,POLLOUT);
    assert(r==(long)size);
}
static void byte(int fd, char value) { send_packet(fd,&value,1,&(struct md_fs_rights){0}); }
static char receive_byte(int fd) {
    wait_fd(fd,POLLIN); char value; struct md_fs_rights rights={0};
    assert(md_fs_receive(fd,&value,1,&rights)==1 && !rights.count); return value;
}
static void send_custody(int fd, struct md_inode_custody_parcel *p) {
    send_packet(fd,&p->count,sizeof(p->count),&(struct md_fs_rights){0});
    for (unsigned i=0;i<p->count;) {
        struct md_fs_rights rights={0};
        while (rights.count<MD_FS_MAX_FDS && i<p->count) rights.fd[rights.count++]=p->fd[i++];
        send_packet(fd,"c",1,&rights);
    }
    md_inode_custody_parcel_close(p);
}
static struct md_inode_custody_parcel receive_custody(int fd) {
    wait_fd(fd,POLLIN); unsigned count; struct md_fs_rights rights={0};
    assert(md_fs_receive(fd,&count,sizeof(count),&rights)==sizeof(count) && !rights.count);
    assert(count>=2 && count<=MD_INODE_CUSTODY_FDS); struct md_inode_custody_parcel p={0};
    while (p.count<count) {
        wait_fd(fd,POLLIN); char value;
        assert(md_fs_receive(fd,&value,1,&rights)==1 && value=='c' && rights.count && rights.count<=count-p.count);
        for (unsigned i=0;i<rights.count;++i) p.fd[p.count++]=rights.fd[i];
    }
    return p;
}
static pid_t start(const char *mode, int fd, const char *base) {
    pid_t parent=getpid(), child=fork(); assert(child>=0);
    if (!child) {
        assert(!prctl(PR_SET_PDEATHSIG,SIGKILL) && getppid()==parent);
        assert(!fcntl(fd,F_SETFD,0)); char number[16]; snprintf(number,sizeof(number),"%d",fd);
        execl("/proc/self/exe","inode-custody",mode,number,base,(char *)NULL); _exit(90);
    }
    return child;
}
static void reap(pid_t child, int killed) {
    /* EVENT_WAIT: exact fixture child; outer alarm bounds a stuck process. */
    int status; assert(waitpid(child,&status,0)==child);
    if (killed) assert(WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL);
    else assert(WIFEXITED(status) && !WEXITSTATUS(status));
}
int test_inode_custody_child(int argc, char **argv) {
    if (argc!=4 || (strcmp(argv[1],"--custody-writer") && strcmp(argv[1],"--custody-reader")
            && strcmp(argv[1],"--custody-prefix"))) return -1;
    alarm(30); int fd=atoi(argv[2]); assert(!fcntl(fd,F_SETFD,FD_CLOEXEC));
    unsigned before=descriptors();
    if (!strcmp(argv[1],"--custody-writer")) {
        struct md_inode_store *s=store(argv[3],"upper",0);
        byte(fd,'r'); assert(receive_byte(fd)=='g');
        struct md_inode_custody_parcel p={0}; assert(!md_inode_custody_export(s->lifetime,&p));
        send_custody(fd,&p); md_inode_store_close(s);
    } else if (!strcmp(argv[1],"--custody-prefix")) {
        wait_fd(fd,POLLIN); unsigned count; struct md_fs_rights rights={0};
        assert(md_fs_receive(fd,&count,sizeof(count),&rights)==sizeof(count) && count==6 && !rights.count);
        wait_fd(fd,POLLIN); char value;
        assert(md_fs_receive(fd,&value,1,&rights)==1 && value=='c' && rights.count==2);
        byte(fd,'r');
        /* EVENT_WAIT: parent kills this partial receiver; alarm fails a missing
         * kill. Do not consume the rest of the custody queue while waiting. */
        for (;;) pause();
    } else {
        char name[PATH_MAX]; path(name,argv[3],"upper");
        int root=open(name,O_PATH|O_DIRECTORY|O_CLOEXEC); assert(root>=0);
        struct md_inode_custody_parcel p=receive_custody(fd); struct md_inode_lifetime *owner=NULL;
        assert(!md_inode_custody_import(&p,root,&owner)); close(root);
        byte(fd,'r'); assert(receive_byte(fd)=='x'); md_inode_lifetime_release(owner);
    }
    assert(descriptors()==before); close(fd); return 0;
}
static void processes(const char *base) {
    unsigned before=descriptors(); struct md_inode_store *s=layers(base); md_inode_store_close(s);
    int pair[2]; assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair));
    pid_t child=start("--custody-writer",pair[1],base); close(pair[1]);
    assert(receive_byte(pair[0])=='r');
    char upper[PATH_MAX], moved[PATH_MAX]; path(upper,base,"upper"); path(moved,base,"moved");
    int scope=open(upper,O_PATH|O_DIRECTORY|O_CLOEXEC); assert(scope>=0);
    byte(pair[0],'g'); reap(child,0);
    /* Only queued rights retain leases now, not an inherited worker or SQLite. */
    all_maintenance(base,"upper",1);
    assert(!rename(upper,moved)); s=store(base,"upper",1); md_inode_store_close(s);
    struct md_inode_custody_parcel p=receive_custody(pair[0]); close(pair[0]);
    struct md_inode_lifetime *owner=NULL;
    assert(!md_inode_custody_import(&p,scope,&owner)); close(scope);
    all_maintenance(base,"moved",1); maintenance(base,"upper",0);
    s=store(base,"upper",0); assert(!md_inode_custody_export(owner,&p));
    struct md_inode_lifetime *wrong=NULL;
    assert(md_inode_custody_import(&p,s->lifetime->root,&wrong)==-ESTALE && !wrong);
    md_inode_store_close(s);
    /* Exercise COW and logical unlink with a receiver's own SQLite connection. */
    s=store(base,"moved",0); assert(md_inode_lifetime_same(owner,s->lifetime));
    int old=md_inode_open(s,-1,"/first",O_RDONLY,0); assert(old>=0);
    contents(s,"/first","upper"); assert(!md_inode_unlink(s,-1,"/first",0));
    int reopened=md_inode_reopen(s,old,O_RDONLY,0); assert(reopened>=0);
    char bytes[5]; assert(read(reopened,bytes,5)==5 && !memcmp(bytes,"upper",5)); close(reopened);
    assert(pread(old,bytes,5,0)==5 && !memcmp(bytes,"first",5)); close(old);
    md_inode_store_close(s); all_maintenance(base,"moved",1);
    /* Rename lower roots too: custody never needs their recorded old paths. */
    char lower[PATH_MAX], renamed[PATH_MAX]; path(lower,base,"lower"); path(renamed,base,"renamed-lower");
    assert(!rename(lower,renamed)); s=store(base,"lower",1); md_inode_store_close(s);
    relation(owner,1,1); relation(owner,2,1); maintenance(base,"lower",0);
    assert(!md_inode_custody_export(owner,&p)); md_inode_lifetime_release(owner); owner=NULL;
    scope=open(moved,O_PATH|O_DIRECTORY|O_CLOEXEC); assert(scope>=0);
    assert(!md_inode_custody_import(&p,scope,&owner)); close(scope);
    md_inode_lifetime_release(owner);
    /* The renamed upper's catalogue still contains its original lower paths.
     * Probe its root lease directly; custody does not rewrite that catalogue. */
    native_maintenance(base,"moved",0);
    maintenance(base,"renamed-lower",0);
    native_maintenance(base,"middle",0);
    assert(descriptors()==before);
    puts("PASS inode custody exec: queued leases after sender exit, root/path replacement, COW/unlink, lower rename and final unlock");
}
static void receiver_death(const char *base, unsigned mode) {
    unsigned before=descriptors(); struct md_inode_store *s=layers(base);
    struct md_inode_custody_parcel p={0}; assert(!md_inode_custody_export(s->lifetime,&p));
    int pair[2]; assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair));
    pid_t child=mode==1 ? -1 : start(mode==2 ? "--custody-prefix" : "--custody-reader",pair[1],base);
    if (child>=0) close(pair[1]);
    send_custody(pair[0],&p); md_inode_store_close(s);
    if (child>=0) assert(receive_byte(pair[0])=='r');
    all_maintenance(base,"upper",1);
    if (child<0) close(pair[1]);
    else { assert(!kill(child,SIGKILL)); reap(child,1); }
    close(pair[0]); all_maintenance(base,"upper",0); assert(descriptors()==before);
}
static void bounds(const char *base) {
    unsigned before=descriptors(); struct md_inode_store *s=store(base,"upper",1);
    struct md_inode_custody_parcel p={0}; struct md_inode_lifetime *received=NULL;
    assert(!md_inode_custody_export(s->lifetime,&p) && p.count==2);
    assert(!md_inode_custody_import(&p,s->lifetime->root,&received)); md_inode_lifetime_release(received);
    /* Sparse source IDs and the maximum catalogue are custody checks, not 255
     * downloaded OCI layers. Each entry owns distinct real directory/lock FDs. */
    for (unsigned i=1;i<MDI_SOURCES;++i) {
        char name[32]; snprintf(name,sizeof(name),"layer-%u",i);
        char root[PATH_MAX], objects[PATH_MAX]; path(root,base,name); path(objects,root,"objects");
        assert(!mkdir(root,0700) && !mkdir(objects,0700));
        int lease=open(root,O_RDONLY|O_DIRECTORY|O_CLOEXEC), fd=open(objects,O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        assert(lease>=0 && fd>=0 && !flock(lease,LOCK_SH|LOCK_NB));
        unsigned id=MDI_SOURCES-i;
        s->lifetime->sources[id]=fd; s->lifetime->source_leases[id]=lease;
        if (i==1) {
            assert(!md_inode_custody_export(s->lifetime,&p) && p.count==4); received=NULL;
            assert(!md_inode_custody_import(&p,s->lifetime->root,&received));
            assert(received->sources[255]>=0 && received->sources[1]<0); md_inode_lifetime_release(received);
        }
    }
    assert(!md_inode_custody_export(s->lifetime,&p) && p.count==MD_INODE_CUSTODY_FDS); received=NULL;
    assert(!md_inode_custody_import(&p,s->lifetime->root,&received));
    for (unsigned i=1;i<MDI_SOURCES;++i) relation(received,i,1);
    int pair[2]; assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair));
    pid_t child=start("--custody-reader",pair[1],base); close(pair[1]);
    assert(!md_inode_custody_export(received,&p) && p.count==512);
    send_custody(pair[0],&p); assert(receive_byte(pair[0])=='r');
    md_inode_store_close(s); md_inode_lifetime_release(received);
    native_maintenance(base,"upper",1);
    for (unsigned i=1;i<MDI_SOURCES;++i) {
        char name[32]; snprintf(name,sizeof(name),"layer-%u",i); native_maintenance(base,name,1);
    }
    byte(pair[0],'x'); reap(child,0); close(pair[0]); native_maintenance(base,"upper",0);
    for (unsigned i=1;i<MDI_SOURCES;++i) {
        char name[32]; snprintf(name,sizeof(name),"layer-%u",i); native_maintenance(base,name,0);
    }
    assert(descriptors()==before);
    puts("PASS inode custody bounds: empty, sparse and 255-source catalogue without per-pin descriptors");
    puts("PASS inode custody 512-right transfer: bounded packets to exec peer, all leases retained and released");
}
static void exclusive(const char *base) {
    unsigned before=descriptors(); struct md_inode_store *s=store(base,"upper",1); md_inode_store_close(s);
    char name[PATH_MAX]; path(name,base,"upper"); assert(!md_inode_store_open_exclusive(name,&s));
    struct md_inode_custody_parcel p={0}; assert(!md_inode_custody_export(s->lifetime,&p));
    struct md_inode_lifetime *received=NULL; assert(!md_inode_custody_import(&p,s->lifetime->root,&received));
    md_inode_store_close(s); s=NULL;
    assert(md_inode_store_open(name,0,&s)==-EBUSY && !s);
    md_inode_lifetime_release(received); s=store(base,"upper",0); md_inode_store_close(s);
    assert(descriptors()==before);
    puts("PASS inode custody preserves original exclusive lock without converting it to shared");
}
void test_inode_custody(const char *base) {
    alarm(90); const char *names[]={"custody-local","custody-processes","custody-killed","custody-discarded",
        "custody-bounds","custody-partial","custody-exclusive"};
    char dirs[7][PATH_MAX];
    for (unsigned i=0;i<7;++i) { path(dirs[i],base,names[i]); assert(!mkdir(dirs[i],0700)); }
    local(dirs[0]); processes(dirs[1]); receiver_death(dirs[2],0); receiver_death(dirs[3],1); bounds(dirs[4]);
    receiver_death(dirs[5],2); exclusive(dirs[6]);
    alarm(0); puts("PASS portable inode custody: receiver death/discard and exact descriptor balance");
}

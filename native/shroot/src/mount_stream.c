#define _GNU_SOURCE
#include "mount_stream.h"
#include "mount_graph.h"
#include "fd_bundle.h"
#include "fs_wire.h"
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

enum { MAGIC=0x4d445453, VERSION=2, DECISION_MAGIC=0x4d444d43,
    SEALS=F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_FUTURE_WRITE|F_SEAL_SEAL };
struct publication {
    uint32_t magic, version, count, previous_count;
    uint64_t sequence, revision, previous;
};
struct decision { uint32_t magic; atomic_uint state; };
_Static_assert(ATOMIC_INT_LOCK_FREE==2 && sizeof(struct decision)==8,"mount commit layout");

int md_mount_stream_new(int *reader, int *writer) {
    int pair[2];
    if (socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair)) return -errno;
    *reader=pair[0]; *writer=pair[1]; return 0;
}
static int valid(const struct publication *p, ssize_t n) {
    return n==sizeof(*p) && p->magic==MAGIC && p->version==VERSION
        && p->sequence && p->revision && p->count && p->count<MD_MOUNT_GRAPH_FDS
        && p->previous_count<MD_MOUNT_GRAPH_FDS
        && (!!p->previous_count==!!p->previous) ? 0 : -EPROTO;
}
int md_mount_stream_revision(int reader, uint64_t *revision) {
    struct publication p;
    /* Deliberately omit ancillary space: a peek never consumes queued rights.
     * Checking an unchanged view needs neither an allocation nor an FD slot. */
    ssize_t n=recv(reader,&p,sizeof(p),MSG_PEEK|MSG_DONTWAIT|MSG_TRUNC);
    int r=n<0 ? -errno : valid(&p,n);
    if (!r) *revision=p.sequence;
    return r;
}
static int decision_read(int fd, unsigned *out) {
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    if (!S_ISREG(st.st_mode) || st.st_size!=sizeof(struct decision)) return -EPROTO;
    int seals=fcntl(fd,F_GET_SEALS);
    if (seals<0) return -errno;
    if ((seals&SEALS)!=SEALS) return -EPROTO;
    struct decision *d=mmap(NULL,sizeof(*d),PROT_READ,MAP_SHARED,fd,0);
    if (d==MAP_FAILED) return -errno;
    unsigned state=atomic_load_explicit(&d->state,memory_order_acquire);
    int r=d->magic!=DECISION_MAGIC || state>2 ? -EPROTO : 0;
    munmap(d,sizeof(*d));
    if (!r) *out=state;
    return r;
}
int md_mount_stream_read(int reader, uint64_t *revision, int **rights, unsigned *count,int *settled) {
    if (!rights || *rights || !count) return -EINVAL;
    struct publication p={0};
    unsigned received=0; int parts[3]={-1,-1,-1};
    long n=md_fs_peek_fds(reader,&p,sizeof(p),parts,3,&received);
    int r=n<0 ? (int)n : valid(&p,n);
    if (!r && received!=(p.previous_count ? 3U : 1U)) r=-EPROTO;
    unsigned state=1;
    if (!r && p.previous_count) r=decision_read(parts[2],&state);
    unsigned selected=state==1 ? 0 : 1;
    unsigned size=selected ? p.previous_count : p.count;
    int *fds=NULL;
    if (!r && !(fds=calloc(size,sizeof(int)))) r=-ENOMEM;
    if (!r) r=md_fd_bundle_peek(parts[selected],size,fds);
    if (r && selected && received==3) {
        unsigned current=0;
        int checked=decision_read(parts[2],&current);
        if (!checked && current==1) {
            /* Commit may retire the old bundle after its decision was read.
             * Retry only snapshot selection, never an application operation. */
            free(fds); fds=calloc(p.count,sizeof(int));
            r=fds ? md_fd_bundle_peek(parts[0],p.count,fds) : -ENOMEM;
            selected=0; size=p.count; state=1;
        }
    }
    for (unsigned i=0;i<received;++i) close(parts[i]);
    if (r) free(fds);
    else {
        *rights=fds; *count=size; *revision=selected ? p.previous : p.revision;
        if (settled) *settled=state!=0;
    }
    return r;
}
struct pending { struct publication header; int next, previous; uint64_t sequence; };
static int prepare(const struct md_mount_stream_change *c,int transaction,struct pending *p) {
    if (c->writer<0) return -EPERM;
    if (c->previous==UINT64_MAX || !c->count || c->count>=MD_MOUNT_GRAPH_FDS) return -EOVERFLOW;
    int r=c->previous ? md_mount_stream_revision(c->reader,&p->sequence) : 0;
    if (!r && p->sequence==UINT64_MAX) r=-EOVERFLOW;
    uint64_t revision=0; int *old=NULL; unsigned count=0; int settled=0;
    if (!r && c->previous) r=md_mount_stream_read(c->reader,&revision,&old,&count,&settled);
    if (!r && c->previous && (revision!=c->previous || !settled)) r=-ESTALE;
    if (!r && transaction && !c->previous) r=-EINVAL;
    if (!r && transaction) r=md_fd_bundle_pack(old,count,&p->previous);
    for (unsigned i=0;i<count;++i) close(old[i]);
    free(old);
    if (!r) r=md_fd_bundle_pack(c->rights,c->count,&p->next);
    p->header=(struct publication){MAGIC,VERSION,c->count,transaction ? count : 0,
        p->sequence+1,c->previous+1,transaction ? c->previous : 0};
    return r;
}
static int stage(const struct md_mount_stream_change *c,const struct pending *p,int decision) {
    int parts[]={p->next,p->previous,decision};
    long sent=md_fs_send_fds(c->writer,&p->header,sizeof(p->header),parts,decision<0 ? 1 : 3);
    if (sent!=sizeof(p->header)) return sent<0 ? (int)sent : -EPROTO;
    if (!c->previous) return 0;
    /* The candidate still selects the old snapshot until the common decision.
     * Consumers only peek; removing the old head cannot consume their reads. */
    struct publication old; ssize_t n;
    do n=recv(c->reader,&old,sizeof(old),MSG_DONTWAIT|MSG_TRUNC); while (n<0 && errno==EINTR);
    return n==sizeof(old) && old.sequence==p->sequence ? 0 : -EIO;
}
static void discard_bundle(int fd) {
    if (fd<0) return;
    char byte; ssize_t n;
    do n=recv(fd,&byte,1,MSG_DONTWAIT|MSG_TRUNC); while (n<0 && errno==EINTR);
    /* The bundle is an owned, immutable queue. Omitting ancillary space closes
     * its rights without installing them, including nested bundle roots. */
}
int md_mount_stream_publish_many(const struct md_mount_stream_change *changes,unsigned count) {
    if (!changes || !count) return -EINVAL;
    struct pending *pending=calloc(count,sizeof(*pending));
    if (!pending) return -ENOMEM;
    for (unsigned i=0;i<count;++i) pending[i].next=pending[i].previous=-1;
    int r=0,fd=-1; struct decision *d=MAP_FAILED;
    for (unsigned i=0;i<count && !r;++i) {
        for (unsigned j=0;j<i;++j) if (changes[j].reader==changes[i].reader) r=-EINVAL;
        if (!r) r=prepare(changes+i,count>1,pending+i);
    }
    if (!r && count>1) {
        fd=memfd_create("shroot-mount-commit",MFD_CLOEXEC|MFD_ALLOW_SEALING);
        if (fd<0 || ftruncate(fd,sizeof(*d))) r=-errno;
        if (!r) {
            d=mmap(NULL,sizeof(*d),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
            if (d==MAP_FAILED) r=-errno;
        }
        if (!r) {
            d->magic=DECISION_MAGIC; atomic_init(&d->state,0);
            if (fcntl(fd,F_ADD_SEALS,SEALS)) r=-errno;
        }
    }
    for (unsigned i=0;i<count && !r;++i) r=stage(changes+i,pending+i,fd);
    if (d!=MAP_FAILED) {
        atomic_store_explicit(&d->state,r ? 2U : 1U,memory_order_release);
        for (unsigned i=0;i<count;++i) discard_bundle(r ? pending[i].next : pending[i].previous);
        munmap(d,sizeof(*d));
    }
    if (fd>=0) close(fd);
    for (unsigned i=0;i<count;++i) {
        if (pending[i].next>=0) close(pending[i].next);
        if (pending[i].previous>=0) close(pending[i].previous);
    }
    free(pending); return r;
}
int md_mount_stream_publish(int reader,int writer,uint64_t previous,const int *rights,unsigned count) {
    const struct md_mount_stream_change c={reader,writer,previous,rights,count};
    return md_mount_stream_publish_many(&c,1);
}

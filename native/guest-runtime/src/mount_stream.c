#define _GNU_SOURCE
#include "mount_stream.h"
#include "mount_graph.h"
#include "fd_bundle.h"
#include "fs_wire.h"
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

enum { MAGIC=0x4d445453, VERSION=1 };
struct publication { uint32_t magic, version, count, reserved; uint64_t revision; };

int md_mount_stream_new(int *reader, int *writer) {
    int pair[2];
    if (socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair)) return -errno;
    *reader=pair[0]; *writer=pair[1]; return 0;
}
static int valid(const struct publication *p, ssize_t n) {
    return n==sizeof(*p) && p->magic==MAGIC && p->version==VERSION && !p->reserved
        && p->revision && p->count && p->count<MD_MOUNT_GRAPH_FDS ? 0 : -EPROTO;
}
int md_mount_stream_revision(int reader, uint64_t *revision) {
    struct publication p;
    /* Deliberately omit ancillary space: a peek never consumes queued rights.
     * Checking an unchanged view needs neither an allocation nor an FD slot. */
    ssize_t n=recv(reader,&p,sizeof(p),MSG_PEEK|MSG_DONTWAIT|MSG_TRUNC);
    int r=n<0 ? -errno : valid(&p,n);
    if (!r) *revision=p.revision;
    return r;
}
int md_mount_stream_publish(int reader, int writer, uint64_t previous,
        const int *rights, unsigned count) {
    if (writer<0) return -EPERM;
    if (previous==UINT64_MAX || !count || count>=MD_MOUNT_GRAPH_FDS) return -EOVERFLOW;
    uint64_t current=0;
    int r=previous ? md_mount_stream_revision(reader,&current) : 0;
    if (!r && previous && current!=previous) r=-ESTALE;
    int bundle=-1;
    if (!r) r=md_fd_bundle_pack(rights,count,&bundle);
    if (!r) {
        struct publication p={MAGIC,VERSION,count,0,previous+1};
        long n=md_fs_send_fds(writer,&p,sizeof(p),&bundle,1);
        if (n!=sizeof(p)) r=n<0 ? (int)n : -EPROTO;
    }
    if (bundle>=0) close(bundle);
    if (r || !previous) return r;
    /* All fallible preparation precedes this commit. Discarding the old packet
     * atomically exposes the new one; no receiver consumes this queue. Death
     * before this point leaves the previous committed snapshot at its head. */
    struct publication old;
    ssize_t n;
    do n=recv(reader,&old,sizeof(old),MSG_DONTWAIT|MSG_TRUNC); while (n<0 && errno==EINTR);
    return n==sizeof(old) && old.revision==previous ? 0 : -EIO;
}
int md_mount_stream_read(int reader, uint64_t *revision, int **rights, unsigned *count) {
    if (!rights || *rights || !count) return -EINVAL;
    struct publication p;
    unsigned received=0; int bundle=-1;
    long n=md_fs_peek_fds(reader,&p,sizeof(p),&bundle,1,&received);
    int r=n<0 ? (int)n : valid(&p,n);
    if (!r && received!=1) r=-EPROTO;
    int *fds=NULL;
    if (!r && !(fds=calloc(p.count,sizeof(int)))) r=-ENOMEM;
    if (!r) r=md_fd_bundle_peek(bundle,p.count,fds);
    if (bundle>=0) close(bundle);
    if (r) free(fds);
    else { *rights=fds; *count=p.count; *revision=p.revision; }
    return r;
}

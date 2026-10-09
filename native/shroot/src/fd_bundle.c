#define _GNU_SOURCE
#include "fd_bundle.h"
#include "fs_wire.h"
#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

enum { FANOUT=MD_FD_RECEIPT_MAX, MAGIC=0x4d444642, VERSION=1 };
struct node { uint32_t magic, version, count, span; };

static unsigned span_for(unsigned count) {
    unsigned span=1;
    while ((count-1)/span>=FANOUT) span*=FANOUT;
    return span;
}
static void close_fds(int *fds, unsigned count) {
    for (unsigned i=0;i<count;++i) if (fds[i]>=0) { close(fds[i]); fds[i]=-1; }
}
int md_fd_bundle_pack(const int *fds, unsigned count, int *out) {
    if (!fds || !count || !out || *out>=0) return -EINVAL;
    /* Three queue levels cover the bounded origin parcel. Deeper Unix graphs
     * consume the kernel's recursion allowance without serving this protocol. */
    if (count>FANOUT*FANOUT*FANOUT) return -E2BIG;
    unsigned span=span_for(count), children=(count-1)/span+1, made=0;
    int nested[FANOUT], sockets[2]={-1,-1}, error=0;
    if (span>1) {
        for (;made<children;++made) {
            unsigned start=made*span, size=count-start;
            if (size>span) size=span;
            nested[made]=-1;
            error=md_fd_bundle_pack(fds+start,size,&nested[made]);
            if (error) break;
        }
    }
    if (!error && socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0,sockets)) error=-errno;
    if (!error) {
        struct node header={MAGIC,VERSION,count,span};
        long n=md_fs_send_fds(sockets[0],&header,sizeof(header),span>1 ? nested : fds,children);
        if (n!=sizeof(header)) error=n<0 ? (int)n : -EPROTO;
    }
    close_fds(nested,made);
    if (sockets[0]>=0) close(sockets[0]);
    if (error) { if (sockets[1]>=0) close(sockets[1]); }
    else *out=sockets[1];
    return error;
}
static int peek(int fd, unsigned count, int *out) {
    unsigned span=span_for(count), children=(count-1)/span+1, installed=0;
    int fds[FANOUT]; struct node header={0};
    long n=md_fs_peek_fds(fd,&header,sizeof(header),fds,children,&installed);
    if (n<0) return (int)n;
    int error=n!=sizeof(header) || header.magic!=MAGIC || header.version!=VERSION
        || header.count!=count || header.span!=span || installed!=children ? -EPROTO : 0;
    if (!error && span==1) {
        for (unsigned i=0;i<count;++i) { out[i]=fds[i]; fds[i]=-1; }
    } else for (unsigned i=0;!error && i<children;++i) {
        unsigned start=i*span, size=count-start;
        if (size>span) size=span;
        error=peek(fds[i],size,out+start);
    }
    close_fds(fds,installed);
    return error;
}
int md_fd_bundle_peek(int fd, unsigned count, int *out) {
    if (!count || !out) return -EINVAL;
    if (count>FANOUT*FANOUT*FANOUT) return -E2BIG;
    for (unsigned i=0;i<count;++i) out[i]=-1;
    int error=peek(fd,count,out);
    if (error) close_fds(out,count);
    return error;
}

#define _GNU_SOURCE
#include "ipc_peer.h"
#include "ipc_peer_wire.h"
#include "fs_wire.h"
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

enum { SEND_OFFER, RECEIVE_OFFER, SEND_CONFIRM, RECEIVE_CONFIRM, AGREED };
struct md_ipc_peer {
    struct md_ipc_binding binding;
    struct md_ipc_peer_packet offer, peer;
    uint64_t selected;
    int fd, state, error;
};
void md_ipc_peer_close(struct md_ipc_peer *p) {
    if (!p) return;
    if (p->fd>=0) close(p->fd);
    md_ipc_binding_release(&p->binding); free(p);
}
int md_ipc_peer_open(struct md_ipc_credentials *s, int application, int control,
        uint64_t supported, uint64_t required, struct md_ipc_peer **out) {
    if (!out || *out || (supported&~(uint64_t)MD_IPC_PEER_ORIGINS) || (required&~supported)) return -EINVAL;
    long native_peer=md_fs_private_peer(control);
    if (native_peer<0) return (int)native_peer;
    int error;
    struct md_ipc_connection used;
    error=md_ipc_credentials_connection(s,control,&used);
    if (error!=-ENODATA) return error ? error : -EINVAL;
    struct md_ipc_peer *p=calloc(1,sizeof(*p));
    if (!p) return -ENOMEM;
    p->fd=-1;
    error=md_ipc_credentials_bind(s,application,&p->binding);
    p->offer=(struct md_ipc_peer_packet){.magic=MD_IPC_PEER_MAGIC,.version=MD_IPC_PEER_VERSION,
        .kind=MD_IPC_PEER_OFFER,.side=p->binding.connection.side,.supported=supported,.required=required};
    memcpy(p->offer.link,p->binding.connection.link,sizeof(p->offer.link));
    if (!error && getrandom(p->offer.nonce,sizeof(p->offer.nonce),0)!=sizeof(p->offer.nonce)) error=-EIO;
    if (error) md_ipc_peer_close(p);
    else { p->fd=control; *out=p; }
    return error;
}
int md_ipc_peer_fd(const struct md_ipc_peer *p) { return p ? p->fd : -1; }
short md_ipc_peer_events(const struct md_ipc_peer *p) {
    if (!p || p->error || p->state==AGREED) return 0;
    return p->state==SEND_OFFER || p->state==SEND_CONFIRM ? POLLOUT : POLLIN;
}
static int validate(struct md_ipc_peer *p, const struct md_ipc_peer_packet *q) {
    if (q->magic!=MD_IPC_PEER_MAGIC) return -EPROTO;
    if (q->version!=MD_IPC_PEER_VERSION) return -EPROTONOSUPPORT;
    if (q->side!=(p->offer.side^1) || memcmp(q->link,p->offer.link,sizeof(q->link))) return -EXDEV;
    if (p->state==RECEIVE_OFFER) {
        const unsigned char zero[16]={0};
        if (q->kind!=MD_IPC_PEER_OFFER || memcmp(q->echo,zero,sizeof(zero))
                || (q->required&~q->supported)) return -EPROTO;
        uint64_t selected=q->supported&p->offer.supported;
        if ((p->offer.required|q->required)&~selected) return -ENOTSUP;
        p->peer=*q; p->selected=selected;
    } else if (q->kind!=MD_IPC_PEER_CONFIRM || q->required || q->supported!=p->selected
            || memcmp(q->nonce,p->peer.nonce,sizeof(q->nonce))
            || memcmp(q->echo,p->offer.nonce,sizeof(q->echo))) return -EPROTO;
    return 0;
}
int md_ipc_peer_step(struct md_ipc_peer *p) {
    if (!p) return -EINVAL;
    if (p->error) return p->error;
    while (p->state!=AGREED) {
        struct md_ipc_peer_packet packet=p->offer;
        long n;
        if (p->state==SEND_OFFER || p->state==SEND_CONFIRM) {
            if (p->state==SEND_CONFIRM) {
                packet.kind=MD_IPC_PEER_CONFIRM; packet.supported=p->selected; packet.required=0;
                memcpy(packet.echo,p->peer.nonce,sizeof(packet.echo));
            }
            n=md_fs_send(p->fd,&packet,sizeof(packet),&(struct md_fs_rights){0});
        } else {
            struct md_fs_rights rights={0};
            n=md_fs_receive(p->fd,&packet,sizeof(packet),&rights);
            if (rights.count) { md_fs_close_rights(&rights); n=-EPROTO; }
            if (n==sizeof(packet)) {
                int error=validate(p,&packet);
                if (error) n=error;
            } else if (!n) n=-ECONNRESET;
        }
        if (n==-EAGAIN || n==-EWOULDBLOCK || n==-EINTR) return 0;
        if (n!=sizeof(packet)) {
            p->error=n<0 ? (int)n : -EPROTO;
            close(p->fd); p->fd=-1;
            md_ipc_binding_release(&p->binding);
            return p->error;
        }
        ++p->state;
    }
    return 1;
}
int md_ipc_peer_agreement(const struct md_ipc_peer *p, const struct md_ipc_binding **binding, uint64_t *features) {
    if (!p || !binding || !features) return -EINVAL;
    if (p->error) return p->error;
    if (p->state!=AGREED) return -EAGAIN;
    *binding=&p->binding; *features=p->selected; return 0;
}

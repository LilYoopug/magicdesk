#define _GNU_SOURCE
#include "network_forward.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

struct listener {
    struct listener *next;
    uint64_t id, space;
    const void *endpoint;
    int fd, type, active, external, published, listening;
    struct sockaddr_in address, client, target;
    struct md_network_flow_path path;
    int64_t deadline;
};
struct stream_buffer { size_t begin, end; unsigned char data[65536]; };
struct datagram { struct datagram *next; size_t size; unsigned char data[]; };
struct datagram_queue { struct datagram *head, *tail; size_t bytes, count; };
struct flow {
    struct flow *next;
    uint64_t id, listener, space, checked[2];
    const void *endpoint, *receiver;
    int fd[2], borrowed, type, connecting, eof[2], denied[2], receiver_closed;
    struct sockaddr_in client, remote, gateway;
    struct md_network_flow_path path;
    struct stream_buffer *buffer;
    struct datagram_queue datagrams[2];
    struct md_filter_accounting accounting[2];
    unsigned started;
    int64_t deadline;
};
struct md_network_forward {
    struct md_network_fabric *fabric;
    pthread_t thread;
    int epoll, wake, stopped;
    uint64_t next_id;
    size_t flows, listeners;
    uint64_t dropped_datagrams;
    struct listener *ports;
    struct flow *connections;
};
struct md_network_forward_update {
    struct md_network_forward *owner;
    uint64_t space;
    struct listener *ports[512];
    unsigned char created[512];
    size_t count;
};
struct md_network_port_reservation { struct md_network_forward *owner; struct listener *listener; int created; };
static int64_t now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
    return (int64_t)ts.tv_sec*1000+ts.tv_nsec/1000000;
}
static int same(const struct sockaddr_in *a,const struct sockaddr_in *b) {
    return a->sin_addr.s_addr==b->sin_addr.s_addr && a->sin_port==b->sin_port;
}
static void wake(struct md_network_forward *f) {
    uint64_t one=1;
    if (f) { ssize_t result=write(f->wake,&one,sizeof(one)); (void)result; }
}
static struct listener *find_listener(struct md_network_forward *f,uint64_t id) {
    for (struct listener *l=f->ports;l;l=l->next) if (l->id==id) return l;
    return NULL;
}
static struct flow *find_flow(struct md_network_forward *f,uint64_t id) {
    for (struct flow *c=f->connections;c;c=c->next) if (c->id==id) return c;
    return NULL;
}
static int watch(struct md_network_forward *f,int command,int fd,uint64_t id,unsigned leg,uint32_t mask) {
    struct epoll_event e={.events=mask,.data.u64=id*4+leg};
    return epoll_ctl(f->epoll,command,fd,&e) ? -errno : 0;
}
static void listener_interests(struct md_network_forward *,uint64_t);
static void drop_flow(struct md_network_forward *f,struct flow *c) {
    struct flow **at=&f->connections;
    while (*at && *at!=c) at=&(*at)->next;
    if (*at) { *at=c->next; --f->flows; }
    if (!c->borrowed && c->fd[0]>=0) { epoll_ctl(f->epoll,EPOLL_CTL_DEL,c->fd[0],NULL); close(c->fd[0]); }
    if (c->fd[1]>=0) { epoll_ctl(f->epoll,EPOLL_CTL_DEL,c->fd[1],NULL); close(c->fd[1]); }
    for (unsigned i=0;i<2;++i) while (c->datagrams[i].head) {
        struct datagram *d=c->datagrams[i].head;
        c->datagrams[i].head=d->next; free(d);
    }
    if (c->borrowed) listener_interests(f,c->listener);
    free(c->accounting[0].cells); free(c->accounting[1].cells);
    free(c->buffer); free(c);
}
static void drop_listener(struct md_network_forward *f,struct listener *l) {
    struct flow *c=f->connections;
    while (c) { struct flow *next=c->next; if (c->listener==l->id) drop_flow(f,c); c=next; }
    struct listener **at=&f->ports;
    while (*at && *at!=l) at=&(*at)->next;
    if (*at) { *at=l->next; --f->listeners; }
    if (l->fd>=0) { epoll_ctl(f->epoll,EPOLL_CTL_DEL,l->fd,NULL); close(l->fd); }
    free(l);
}
static int socket_bound(int type,struct sockaddr_in *address) {
    int fd=socket(AF_INET,type|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if (fd<0) return -errno;
    if (type==SOCK_STREAM) { int one=1; setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one)); }
    if (bind(fd,(void *)address,sizeof(*address))) { int error=-errno; close(fd); return error; }
    socklen_t size=sizeof(*address);
    if (getsockname(fd,(void *)address,&size)) { int error=-errno; close(fd); return error; }
    return fd;
}
static int endpoint_target(struct md_network_fabric *f,const struct md_network_flow_path *path,int type,struct sockaddr_in *target) {
    struct sockaddr_in logical={.sin_family=AF_INET,.sin_addr.s_addr=path->translated.destination,
        .sin_port=path->translated.destination_port};
    return md_network_endpoint_resolve(f,path->destination,type,&logical,target,NULL);
}
static int check(struct md_network_forward *f,struct flow *c,unsigned direction) {
    if (c->checked[direction]!=f->fabric->policy_generation) {
        unsigned mark=c->path.translated.ctmark;
        c->denied[direction]=md_network_flow_accounting(f->fabric,&c->path,direction,!c->started,&c->accounting[direction])!=0;
        if (mark!=c->path.translated.ctmark) c->checked[1-direction]=0;
        c->checked[direction]=f->fabric->policy_generation;
    }
    return c->denied[direction];
}
static void account(struct flow *c,unsigned direction,size_t bytes) {
    md_filter_account(&c->accounting[direction],bytes);
    if (!direction && !c->started) { c->started=1; c->checked[0]=0; }
}
static int interests(struct md_network_forward *f,struct flow *c) {
    for (unsigned leg=0;leg<2;++leg) {
        if (!leg && c->borrowed) continue;
        uint32_t events=0;
        if (c->connecting) { if (leg) events|=EPOLLOUT; }
        else if (c->type==SOCK_DGRAM) {
            if (c->datagrams[leg].count<64 && c->datagrams[leg].bytes<262144) events|=EPOLLIN;
            if (c->datagrams[1-leg].head) events|=EPOLLOUT;
        }
        else {
            if (!c->eof[leg] && !c->buffer[leg].end && !check(f,c,leg)) events|=EPOLLIN|EPOLLRDHUP;
            if (c->buffer[1-leg].end && !check(f,c,1-leg)) events|=EPOLLOUT;
        }
        int error=watch(f,EPOLL_CTL_MOD,c->fd[leg],c->id,leg,events);
        if (error) return error;
    }
    return 0;
}
static struct flow *new_flow(struct md_network_forward *f,struct listener *l,int front,
        const struct sockaddr_in *client,struct md_network_flow_path *path,const struct sockaddr_in *target) {
    if (f->flows==1024 || f->next_id>UINT64_MAX/4) { errno=ENOSPC; return NULL; }
    struct flow *c=calloc(1,sizeof(*c));
    if (!c) return NULL;
    c->fd[0]=front; c->fd[1]=-1; c->type=l->type; c->borrowed=l->external && l->type==SOCK_DGRAM;
    c->listener=l->external ? l->id : 0; c->space=l->space; c->endpoint=l->external ? NULL : l->endpoint;
    c->client=*client; c->path=*path; c->gateway=l->address;
    if (c->type==SOCK_DGRAM && path->destination) {
        struct sockaddr_in logical={.sin_family=AF_INET,.sin_addr.s_addr=path->translated.destination,
            .sin_port=path->translated.destination_port}, ignored;
        int error=md_network_endpoint_resolve(f->fabric,path->destination,c->type,&logical,&ignored,&c->receiver);
        if (error) { free(c); errno=-error; return NULL; }
    }
    c->id=++f->next_id;
    c->remote=(struct sockaddr_in){.sin_family=AF_INET};
    c->fd[1]=socket_bound(c->type,&c->remote);
    if (c->fd[1]<0) { errno=-c->fd[1]; goto failed; }
    if (connect(c->fd[1],(const void *)target,sizeof(*target))) {
        if (errno!=EINPROGRESS) goto failed;
        c->connecting=1;
    }
    if (c->type==SOCK_STREAM) {
        c->buffer=calloc(2,sizeof(*c->buffer)); if (!c->buffer) goto failed;
    }
    c->deadline=c->type==SOCK_DGRAM || c->connecting ? now_ms()+30000 : INT64_MAX;
    for (unsigned leg=0;leg<2;++leg) if (leg || !c->borrowed)
        if (watch(f,EPOLL_CTL_ADD,c->fd[leg],c->id,leg,0)) goto failed;
    c->next=f->connections; f->connections=c; ++f->flows;
    int error=interests(f,c);
    if (error) {
        if (!c->borrowed) epoll_ctl(f->epoll,EPOLL_CTL_DEL,front,NULL);
        c->fd[0]=-1; drop_flow(f,c); errno=-error; return NULL;
    }
    return c;
failed:
    if (c->fd[1]>=0) { epoll_ctl(f->epoll,EPOLL_CTL_DEL,c->fd[1],NULL); close(c->fd[1]); }
    if (!c->borrowed && c->fd[0]>=0) epoll_ctl(f->epoll,EPOLL_CTL_DEL,c->fd[0],NULL);
    free(c->buffer); free(c); return NULL;
}
static int incoming_path(struct md_network_forward *f,struct listener *l,const struct sockaddr_in *client,
        const struct sockaddr_in *local,struct md_network_flow_path *path,struct sockaddr_in *target) {
    if (!l->external) { *path=l->path; *target=l->target; return 0; }
    struct md_network_namespace *n=md_network_space_find(f->fabric,l->space);
    if (!n) return -ENETUNREACH;
    struct md_filter_packet p={.source=client->sin_addr.s_addr,.source_port=client->sin_port,
        .destination=local->sin_addr.s_addr,.destination_port=local->sin_port,.state=8,
        .protocol=l->type==SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP};
    if (l->address.sin_addr.s_addr && (ntohl(l->address.sin_addr.s_addr)>>24)!=127)
        p.destination=l->address.sin_addr.s_addr;
    int error=md_network_flow_route(n,&p,1,path);
    if (!error && !p.dnat && !l->endpoint) error=-ECONNREFUSED;
    if (!error) error=endpoint_target(f->fabric,path,l->type,target);
    return error;
}
static void tcp_accept(struct md_network_forward *f,struct listener *l) {
    for (unsigned budget=0;budget<16;++budget) {
        struct sockaddr_in client; socklen_t size=sizeof(client);
        int fd=accept4(l->fd,(void *)&client,&size,SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (fd<0) return;
        if (!l->external && !same(&client,&l->client)) { close(fd); continue; }
        struct sockaddr_in local; size=sizeof(local);
        struct md_network_flow_path path;
        struct sockaddr_in target;
        if (getsockname(fd,(void *)&local,&size) || incoming_path(f,l,&client,&local,&path,&target)) { close(fd); continue; }
        struct flow *c=new_flow(f,l,fd,&client,&path,&target);
        if (!c) close(fd);
        if (!l->external) { drop_listener(f,l); return; }
    }
}
static int datagram_send(struct flow *c,unsigned direction,const void *data,size_t size) {
    /* A retained tuple describes queued packets, not authority to deliver to a
     * new socket which happens to reuse the closed peer's native port. */
    if ((!direction && c->receiver_closed)
            || (direction && !c->borrowed && !c->endpoint)) return -ECONNREFUSED;
    ssize_t sent=direction ? sendto(c->fd[0],data,size,MSG_DONTWAIT|MSG_NOSIGNAL,(void *)&c->client,sizeof(c->client))
        : send(c->fd[1],data,size,MSG_DONTWAIT|MSG_NOSIGNAL);
    return sent<0 ? -errno : (size_t)sent==size ? 0 : -EIO;
}
static void listener_interests(struct md_network_forward *f,uint64_t id) {
    struct listener *l=find_listener(f,id);
    if (!l) return;
    uint32_t events=EPOLLIN;
    for (struct flow *c=f->connections;c;c=c->next)
        if (c->borrowed && c->listener==id && c->datagrams[1].head) { events|=EPOLLOUT; break; }
    watch(f,EPOLL_CTL_MOD,l->fd,l->id,2,events);
}
static void datagram_submit(struct md_network_forward *f,struct flow *c,unsigned direction,const void *data,size_t size) {
    int denied=check(f,c,direction);
    account(c,direction,size);
    if (denied) return;
    struct datagram_queue *q=&c->datagrams[direction];
    if (!q->head) {
        int error=datagram_send(c,direction,data,size);
        if (!error) { c->deadline=now_ms()+30000; return; }
        if (error!=-EAGAIN && error!=-EWOULDBLOCK && error!=-EINTR) { ++f->dropped_datagrams; return; }
    }
    struct datagram *d=q->count<64 && size<=262144-q->bytes ? malloc(sizeof(*d)+size) : NULL;
    if (!d) { ++f->dropped_datagrams; return; }
    d->next=NULL; d->size=size; memcpy(d->data,data,size);
    if (q->tail) q->tail->next=d; else q->head=d;
    q->tail=d; q->bytes+=size; ++q->count;
    c->deadline=now_ms()+30000;
    interests(f,c);
    if (c->borrowed && direction) listener_interests(f,c->listener);
}
static void datagram_flush(struct md_network_forward *f,struct flow *c,unsigned direction) {
    struct datagram_queue *q=&c->datagrams[direction];
    for (unsigned budget=0;q->head && budget<16;++budget) {
        struct datagram *d=q->head;
        int error=check(f,c,direction) ? -EACCES : datagram_send(c,direction,d->data,d->size);
        if (error==-EAGAIN || error==-EWOULDBLOCK || error==-EINTR) break;
        if (error && error!=-EACCES) ++f->dropped_datagrams;
        q->head=d->next; q->bytes-=d->size; --q->count; free(d);
        if (!q->head) q->tail=NULL;
    }
    interests(f,c);
    if (c->borrowed && direction) listener_interests(f,c->listener);
}
static void udp_receive(struct md_network_forward *f,struct flow *c,unsigned leg) {
    unsigned char data[65536];
    for (unsigned budget=0;budget<16;++budget) {
        struct sockaddr_in source; socklen_t size=sizeof(source);
        ssize_t bytes=recvfrom(c->fd[leg],data,sizeof(data),MSG_DONTWAIT,(void *)&source,&size);
        if (bytes<0) return;
        if (!leg && !same(&source,&c->client)) continue;
        datagram_submit(f,c,leg,data,(size_t)bytes);
        if (c->datagrams[leg].count>=64 || c->datagrams[leg].bytes>=262144) break;
    }
}
static void udp_accept(struct md_network_forward *f,struct listener *l) {
    unsigned char data[65536];
    for (unsigned budget=0;budget<16;++budget) {
        struct sockaddr_in client; socklen_t size=sizeof(client);
        struct iovec vector={data,sizeof(data)};
        union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(struct in_pktinfo))]; } ancillary;
        struct msghdr message={.msg_name=&client,.msg_namelen=size,.msg_iov=&vector,.msg_iovlen=1,
            .msg_control=ancillary.bytes,.msg_controllen=sizeof(ancillary)};
        ssize_t bytes=recvmsg(l->fd,&message,MSG_DONTWAIT);
        if (bytes<0) return;
        struct sockaddr_in local=l->address;
        for (struct cmsghdr *h=CMSG_FIRSTHDR(&message);h;h=CMSG_NXTHDR(&message,h))
            if (h->cmsg_level==IPPROTO_IP && h->cmsg_type==IP_PKTINFO && h->cmsg_len==CMSG_LEN(sizeof(struct in_pktinfo))) {
                struct in_pktinfo info; memcpy(&info,CMSG_DATA(h),sizeof(info)); local.sin_addr=info.ipi_addr;
            }
        struct flow *c=f->connections;
        while (c && !(c->listener==l->id && same(&c->client,&client) && c->path.original.destination==local.sin_addr.s_addr)) c=c->next;
        if (c && c->receiver_closed) { drop_flow(f,c); c=NULL; }
        if (!c) {
            struct md_network_flow_path path; struct sockaddr_in target;
            if (incoming_path(f,l,&client,&local,&path,&target)) continue;
            c=new_flow(f,l,l->fd,&client,&path,&target);
            if (!c) continue;
        }
        datagram_submit(f,c,0,data,(size_t)bytes);
    }
}
static int stream_event(struct md_network_forward *f,struct flow *c,unsigned leg,uint32_t events) {
    if (c->connecting && leg && (events&(EPOLLOUT|EPOLLERR|EPOLLHUP))) {
        int error=0; socklen_t size=sizeof(error);
        if (getsockopt(c->fd[1],SOL_SOCKET,SO_ERROR,&error,&size) || error) return -ECONNREFUSED;
        c->connecting=0; c->deadline=INT64_MAX;
    }
    if (events&EPOLLERR) return -ECONNRESET;
    if (c->connecting) return interests(f,c);
    if ((events&(EPOLLIN|EPOLLRDHUP|EPOLLHUP)) && !c->eof[leg] && !c->buffer[leg].end) {
        if (check(f,c,leg)) {
            if (events&(EPOLLRDHUP|EPOLLHUP)) return -ECONNRESET;
        } else {
            ssize_t bytes=recv(c->fd[leg],c->buffer[leg].data,sizeof(c->buffer[leg].data),MSG_DONTWAIT);
            if (bytes>0) { c->buffer[leg].end=(size_t)bytes; account(c,leg,(size_t)bytes); }
            else if (!bytes) { c->eof[leg]=1; shutdown(c->fd[1-leg],SHUT_WR); }
            else if (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR) return -errno;
        }
    }
    for (unsigned direction=0;direction<2;++direction) {
        struct stream_buffer *b=&c->buffer[direction];
        if (b->end && !check(f,c,direction)) {
            ssize_t bytes=send(c->fd[1-direction],b->data+b->begin,b->end-b->begin,MSG_DONTWAIT|MSG_NOSIGNAL);
            if (bytes>0) { b->begin+=(size_t)bytes; if (b->begin==b->end) b->begin=b->end=0; }
            else if (bytes<0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR) return -errno;
        }
    }
    return c->eof[0] && c->eof[1] && !c->buffer[0].end && !c->buffer[1].end ? -ECONNRESET : interests(f,c);
}
static void *run(void *context) {
    struct md_network_forward *f=context;
    int timeout=-1;
    for (;;) {
        struct epoll_event events[64];
        /* EVENT_WAIT: socket readiness, ruleset/lifetime change or a UDP/pending
         * connect expiry. Idle listener sets have no periodic wakeup. */
        int count=epoll_wait(f->epoll,events,64,timeout);
        int wait_error=count<0 ? errno : 0;
        pthread_mutex_lock(&f->fabric->lock);
        if (f->stopped) { pthread_mutex_unlock(&f->fabric->lock); return NULL; }
        if (count<0 && wait_error!=EINTR) { pthread_mutex_unlock(&f->fabric->lock); return NULL; }
        for (int i=0;i<count;++i) {
            uint64_t id=events[i].data.u64/4; unsigned leg=(unsigned)(events[i].data.u64%4);
            if (!id) {
                uint64_t value; while (read(f->wake,&value,sizeof(value))>0) {}
                struct flow *c=f->connections;
                while (c) { struct flow *next=c->next; if (interests(f,c)) drop_flow(f,c); c=next; }
            } else if (leg==2) {
                struct listener *l=find_listener(f,id);
                if (l && l->active) {
                    if (l->type==SOCK_STREAM) tcp_accept(f,l);
                    else {
                        if (events[i].events&EPOLLIN) udp_accept(f,l);
                        if (events[i].events&EPOLLOUT) for (struct flow *c=f->connections;c;c=c->next)
                            if (c->borrowed && c->listener==id) datagram_flush(f,c,1);
                    }
                }
            } else {
                struct flow *c=find_flow(f,id);
                if (c) {
                    if (c->type==SOCK_DGRAM) {
                        if (events[i].events&EPOLLIN) udp_receive(f,c,leg);
                        if (events[i].events&EPOLLOUT) datagram_flush(f,c,1-leg);
                        if (events[i].events&EPOLLERR) { int error=0; socklen_t size=sizeof(error); getsockopt(c->fd[leg],SOL_SOCKET,SO_ERROR,&error,&size); }
                    }
                    else if (stream_event(f,c,leg,events[i].events)) drop_flow(f,c);
                }
            }
        }
        int64_t now=now_ms(),deadline=INT64_MAX;
        struct flow *c=f->connections;
        while (c) {
            struct flow *next=c->next;
            if (c->deadline<=now) drop_flow(f,c); else if (c->deadline<deadline) deadline=c->deadline;
            c=next;
        }
        struct listener *l=f->ports;
        while (l) {
            struct listener *next=l->next;
            if (l->deadline<=now) drop_listener(f,l); else if (l->deadline<deadline) deadline=l->deadline;
            l=next;
        }
        timeout=deadline==INT64_MAX ? -1 : (int)(deadline-now);
        pthread_mutex_unlock(&f->fabric->lock);
    }
}
static int ensure(struct md_network_fabric *fabric) {
    if (fabric->forward) return 0;
    struct md_network_forward *f=calloc(1,sizeof(*f));
    if (!f) return -ENOMEM;
    f->fabric=fabric; f->epoll=epoll_create1(EPOLL_CLOEXEC); f->wake=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK);
    int error=0;
    if (f->epoll<0 || f->wake<0) error=-errno;
    if (!error) error=watch(f,EPOLL_CTL_ADD,f->wake,0,0,EPOLLIN);
    if (!error) error=-pthread_create(&f->thread,NULL,run,f);
    if (error) { if (f->wake>=0) close(f->wake); if (f->epoll>=0) close(f->epoll); free(f); return error; }
    fabric->forward=f; return 0;
}
static struct listener *new_listener(struct md_network_forward *f,uint64_t space,int type,struct sockaddr_in address,int external,int listening) {
    if (f->listeners==512 || f->next_id>UINT64_MAX/4) { errno=ENOSPC; return NULL; }
    struct listener *l=calloc(1,sizeof(*l)); if (!l) return NULL;
    l->space=space; l->type=type; l->external=external; l->id=++f->next_id;
    l->address=address;
    if (external && address.sin_addr.s_addr && (ntohl(address.sin_addr.s_addr)>>24)!=127)
        address.sin_addr.s_addr=INADDR_ANY;
    l->fd=socket_bound(type,&address);
    l->address.sin_port=address.sin_port;
    if (l->fd<0) { errno=-l->fd; free(l); return NULL; }
    int error=0;
    if (type==SOCK_STREAM) { if (listening && listen(l->fd,64)) error=-errno; }
    else { int one=1; if (setsockopt(l->fd,IPPROTO_IP,IP_PKTINFO,&one,sizeof(one))) error=-errno; }
    l->listening=type==SOCK_DGRAM || listening;
    if (!error && l->listening) error=watch(f,EPOLL_CTL_ADD,l->fd,l->id,2,EPOLLIN);
    if (error) { close(l->fd); free(l); errno=-error; return NULL; }
    l->deadline=external ? INT64_MAX : now_ms()+30000;
    l->next=f->ports; f->ports=l; ++f->listeners; return l;
}
int md_network_forward_bind(struct md_network_namespace *n,const void *endpoint,int type,
        const struct sockaddr_in *address,struct md_network_port_reservation **out) {
    *out=NULL;
    int error=ensure(n->fabric); if (error) return error;
    struct md_network_port_reservation *r=calloc(1,sizeof(*r));
    if (!r) return -ENOMEM;
    r->owner=n->fabric->forward;
    struct listener *l=r->owner->ports;
    while (l && !(l->external && l->space==n->inode && l->type==type && same(&l->address,address))) l=l->next;
    if (l && l->endpoint==endpoint) { free(r); return 0; }
    if (l && l->endpoint) { free(r); return -EADDRINUSE; }
    if (!l) {
        l=new_listener(r->owner,n->inode,type,*address,1,0);
        if (!l) { error=-errno; free(r); return error; }
        r->created=1;
    }
    r->listener=l; l->endpoint=endpoint; *out=r; return 0;
}
void md_network_forward_bound(struct md_network_port_reservation *r,int success) {
    if (!r) return;
    if (success) r->listener->active=r->listener->listening;
    else {
        r->listener->endpoint=NULL;
        if (r->created) drop_listener(r->owner,r->listener);
    }
    wake(r->owner); free(r);
}
int md_network_forward_listen(struct md_network_namespace *n,const void *endpoint,int backlog) {
    struct md_network_forward *f=n->fabric->forward;
    if (!f) return 0;
    for (struct listener *l=f->ports;l;l=l->next) if (l->endpoint==endpoint && l->external && l->type==SOCK_STREAM) {
        if (listen(l->fd,backlog)) return -errno;
        int error=watch(f,l->listening ? EPOLL_CTL_MOD : EPOLL_CTL_ADD,l->fd,l->id,2,EPOLLIN);
        if (error) return error;
        l->listening=l->active=1; wake(f); return 0;
    }
    return 0;
}
int md_network_forward_prepare(struct md_network_namespace *n,struct md_network_filter *filter,struct md_network_forward_update **out) {
    *out=NULL;
    struct md_filter_port ports[512]; size_t count=0;
    struct md_network_interface *uplink=md_network_interface_find(n,n->default_interface,NULL);
    int error=n->mode==MD_NETWORK_ROUTED ? md_filter_ports(filter,uplink ? uplink->ipv4 : 0,ports,512,&count) : 0;
    if (error) return error;
    if (!count && !n->fabric->forward) return 0;
    error=ensure(n->fabric); if (error) return error;
    struct md_network_forward_update *u=calloc(1,sizeof(*u)); if (!u) return -ENOMEM;
    u->owner=n->fabric->forward; u->space=n->inode;
    for (size_t i=0;!error && i<count;++i) {
        struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=ports[i].address,.sin_port=ports[i].port};
        int type=ports[i].protocol==IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM;
        struct listener *l=u->owner->ports;
        while (l && !(l->external && l->space==n->inode && l->type==type && same(&l->address,&address))) l=l->next;
        if (!l) {
            l=new_listener(u->owner,n->inode,type,address,1,1);
            if (!l) { error=-errno; break; }
            u->created[u->count]=1;
        } else if (!l->listening) {
            error=-EOPNOTSUPP; break;
        }
        u->ports[u->count++]=l;
    }
    if (error) { md_network_forward_abort(u); return error; }
    *out=u; return 0;
}
void md_network_forward_abort(struct md_network_forward_update *u) {
    if (!u) return;
    for (size_t i=0;i<u->count;++i) if (u->created[i]) drop_listener(u->owner,u->ports[i]);
    free(u);
}
void md_network_forward_commit(struct md_network_forward_update *u) {
    if (!u) return;
    struct listener *l=u->owner->ports;
    while (l) {
        struct listener *next=l->next;
        if (l->space==u->space && l->external) {
            size_t i=0; while (i<u->count && u->ports[i]!=l) ++i;
            l->published=i!=u->count;
            if (!l->published && !l->endpoint) drop_listener(u->owner,l);
            else l->active=l->listening;
        }
        l=next;
    }
    wake(u->owner); free(u);
}
void md_network_forward_changed(struct md_network_fabric *fabric) {
    if (!++fabric->policy_generation) ++fabric->policy_generation;
    wake(fabric->forward);
}
int md_network_forward_route(struct md_network_namespace *n,const void *endpoint,int type,const struct sockaddr_in *client,
        const struct sockaddr_in *target,struct md_network_flow_path *path,struct sockaddr_in *destination) {
    int error=ensure(n->fabric); if (error) return error;
    struct md_network_forward *f=n->fabric->forward;
    struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    struct listener *l=new_listener(f,n->inode,type,address,0,1);
    if (!l) return -errno;
    l->endpoint=endpoint; l->client=*client; l->client.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    l->target=*target; l->path=*path; l->active=1;
    *destination=l->address;
    if (type==SOCK_DGRAM) {
        epoll_ctl(f->epoll,EPOLL_CTL_DEL,l->fd,NULL);
        int fd=l->fd;
        struct flow *c=new_flow(f,l,fd,&l->client,path,target);
        if (!c) { drop_listener(f,l); return -errno; }
        l->fd=-1; drop_listener(f,l);
    }
    wake(f); return 0;
}
int md_network_forward_source(struct md_network_namespace *n,int type,struct sockaddr_in *address,uint32_t *local) {
    struct md_network_forward *f=n->fabric->forward;
    if (!f || (ntohl(address->sin_addr.s_addr)>>24)!=127) return 0;
    for (struct flow *c=f->connections;c;c=c->next) {
        if (c->type!=type) continue;
        if (c->remote.sin_port==address->sin_port && c->path.destination==n->inode) {
            if (local) *local=c->path.translated.destination;
            address->sin_addr.s_addr=c->path.translated.source; address->sin_port=c->path.translated.source_port; return 1;
        }
        if (c->gateway.sin_port==address->sin_port && c->space==n->inode && !c->borrowed) {
            if (local) *local=c->path.original.source;
            address->sin_addr.s_addr=c->path.original.destination; address->sin_port=c->path.original.destination_port; return 1;
        }
    }
    return 0;
}
int md_network_forward_destination(struct md_network_namespace *n,const void *endpoint,int type,const struct sockaddr_in *local,
        const struct sockaddr_in *destination,struct sockaddr_in *native) {
    struct md_network_forward *f=n->fabric->forward;
    if (!f) return 0;
    for (struct flow *c=f->connections;c;c=c->next) {
        if (c->type!=type) continue;
        /* Addressed UDP keeps the established mapping too. The relay checks
         * the current generation; sendto must not re-run NEW/NAT each time. */
        if (type==SOCK_DGRAM && c->endpoint==endpoint
                && !c->receiver_closed
                && (!local->sin_addr.s_addr || local->sin_addr.s_addr==c->path.original.source)
                && c->path.original.destination==destination->sin_addr.s_addr
                && c->path.original.destination_port==destination->sin_port) {
            *native=c->gateway; return 1;
        }
        if (c->path.destination==n->inode
                && (type!=SOCK_DGRAM || c->receiver==endpoint)
                && local->sin_port==c->path.translated.destination_port
                && (!local->sin_addr.s_addr || local->sin_addr.s_addr==c->path.translated.destination)
                && destination->sin_addr.s_addr==c->path.translated.source && destination->sin_port==c->path.translated.source_port) {
            *native=c->remote; native->sin_addr.s_addr=htonl(INADDR_LOOPBACK); return 1;
        }
    }
    return 0;
}
void md_network_forward_endpoint_closed(struct md_network_namespace *n,const void *endpoint) {
    struct md_network_forward *f=n->fabric->forward; if (!f) return;
    struct listener *l=f->ports;
    while (l) {
        struct listener *next=l->next;
        if (l->endpoint==endpoint) {
            l->endpoint=NULL;
            if (!l->external || !l->published) drop_listener(f,l);
        }
        l=next;
    }
    struct flow *c=f->connections;
    while (c) {
        struct flow *next=c->next;
        int sender=c->endpoint==endpoint, receiver=c->receiver==endpoint;
        if (sender) c->endpoint=NULL;
        if (receiver) { c->receiver=NULL; c->receiver_closed=1; }
        if ((sender || receiver) && (c->type!=SOCK_DGRAM || (!c->endpoint && !c->receiver && !c->borrowed)))
            drop_flow(f,c);
        /* A surviving private peer may still receive already queued data.
         * Keep its tuple until that peer closes or the existing UDP idle bound;
         * published listeners above are released immediately. */
        c=next;
    }
    wake(f);
}
void md_network_forward_retire(struct md_network_namespace *n) {
    struct md_network_forward *f=n->fabric->forward; if (!f) return;
    struct listener *l=f->ports;
    while (l) { struct listener *next=l->next; if (l->space==n->inode) drop_listener(f,l); l=next; }
    struct flow *c=f->connections;
    while (c) {
        struct flow *next=c->next; int found=c->space==n->inode;
        for (unsigned i=0;i<c->path.count;++i) found|=c->path.steps[i].space==n->inode;
        if (found) drop_flow(f,c);
        c=next;
    }
    wake(f);
}
void md_network_forward_shutdown(struct md_network_fabric *fabric) {
    struct md_network_forward *f=fabric->forward; if (!f) return;
    pthread_mutex_lock(&fabric->lock); f->stopped=1; wake(f); pthread_mutex_unlock(&fabric->lock);
    /* EVENT_WAIT: the exclusively owned relay acknowledges stop before its
     * fabric lock and queue descriptors are destroyed. No guest IO is awaited. */
    pthread_join(f->thread,NULL);
    while (f->ports) drop_listener(f,f->ports);
    while (f->connections) drop_flow(f,f->connections);
    close(f->wake); close(f->epoll); free(f); fabric->forward=NULL;
}

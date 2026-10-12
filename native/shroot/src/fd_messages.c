#define _GNU_SOURCE
#include "fd_messages.h"
#include "fd_receipt.h"
#include "ipc_scope.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

enum { BUCKETS=61 };
struct md_fd_message {
    struct md_fd_message *next;
    struct md_fd_messages *owner;
    struct md_ipc_connection destination;
    struct md_ipc_binding source;
    struct md_fd_message_route route;
    uint64_t cookie;
    atomic_uint references;
    unsigned count, published;
    unsigned export_prepared;
    uint64_t native_exports[(MD_FD_RECEIPT_MAX+63)/64];
    int monitor;
    struct md_fd_object *origins[];
};
struct md_fd_messages {
    struct md_fd_message *buckets[BUCKETS];
    int events;
    unsigned count;
};
int md_fd_messages_new(struct md_fd_messages **out) {
    if (!out || *out) return -EINVAL;
    struct md_fd_messages *s=calloc(1,sizeof(*s));
    if (!s) return -ENOMEM;
    s->events=-1; *out=s; return 0;
}
int md_fd_message_capture(struct md_fd_origins *source, const int *fds, unsigned count,
        struct md_fd_message **out) {
    if (!source || !fds || !count || count>MD_FD_RECEIPT_MAX || !out || *out) return -EINVAL;
    struct md_fd_message *p=calloc(1,sizeof(*p)+count*sizeof(*p->origins));
    if (!p) return -ENOMEM;
    int error=md_fd_origins_capture_objects(source,fds,count,p->origins);
    if (error) { free(p); return error; }
    atomic_init(&p->references,1); p->count=count; p->monitor=-1; *out=p; return 0;
}
struct md_fd_message *md_fd_message_retain(struct md_fd_message *p) {
    if (p) atomic_fetch_add_explicit(&p->references,1,memory_order_relaxed);
    return p;
}
void md_fd_message_release(struct md_fd_message *p) {
    if (!p || atomic_fetch_sub_explicit(&p->references,1,memory_order_acq_rel)!=1) return;
    md_fd_message_export_end(p,0);
    for (unsigned i=0;i<p->count;++i) md_fd_object_release(p->origins[i]);
    md_ipc_binding_release(&p->source);
    free(p);
}
unsigned md_fd_message_count(const struct md_fd_message *p) { return p ? p->count : 0; }
struct md_fd_object *const *md_fd_message_origins(const struct md_fd_message *p) { return p ? p->origins : NULL; }
int md_fd_message_exports_native(const struct md_fd_message *p, unsigned index) {
    return p && index<p->count && !!(p->native_exports[index/64]&(UINT64_C(1)<<(index%64)));
}
void md_fd_message_export_end(struct md_fd_message *p, int escaped) {
    if (!p || !p->export_prepared) return;
    for (unsigned i=0;i<p->count;++i)
        if (md_fd_message_exports_native(p,i)) p->origins[i]->type->export_end(p->origins[i],escaped);
    memset(p->native_exports,0,sizeof(p->native_exports)); p->export_prepared=0;
}
int md_fd_message_export_begin(struct md_fd_message *p) {
    if (!p) return 0;
    if (p->export_prepared) return -EBUSY;
    p->export_prepared=1;
    for (unsigned i=0;i<p->count;++i) {
        struct md_fd_object *o=p->origins[i];
        if (!o || !o->type->export_begin) continue;
        int error=o->type->export_begin(o);
        if (error==-EOPNOTSUPP) continue;
        if (error) { md_fd_message_export_end(p,0); return error; }
        p->native_exports[i/64]|=UINT64_C(1)<<(i%64);
    }
    return 0;
}
int md_fd_message_bind(struct md_fd_message *p, const struct md_ipc_binding *source, const char *id) {
    if (!p || !source || !source->scope || source->connection.side>1
            || !id || strlen(id)!=32 || strspn(id,"0123456789abcdef")!=32) return -EINVAL;
    if (p->published || p->source.scope) return -ESTALE;
    if (source->transport!=MD_IPC_TRANSPORT_ORIGINS_V1) return -ENOTSUP;
    struct md_fd_message_route route={.magic=MD_FD_ROUTE_MAGIC,.version=MD_FD_ROUTE_VERSION,
        .count=p->count,.side=source->connection.side^1};
    memcpy(route.link,source->connection.link,sizeof(route.link));
    memcpy(route.launch,id,sizeof(route.launch));
    ssize_t n=getrandom(route.nonce,sizeof(route.nonce),0);
    if (n!=sizeof(route.nonce)) return n<0 ? -errno : -EIO;
    int r=md_ipc_binding_copy(&p->source,source);
    if (!r) p->route=route;
    return r;
}
int md_fd_message_route(const struct md_fd_message *p, struct md_fd_message_route *out) {
    if (!p || !out) return -EINVAL;
    if (!p->source.scope || !p->published) return -ENODATA;
    *out=p->route; return 0;
}
int md_fd_message_store_root(const struct md_fd_message *p) {
    return p && p->source.scope ? p->source.scope->root : -1;
}
int md_fd_messages_fd(const struct md_fd_messages *s) { return s ? s->events : -1; }
unsigned md_fd_messages_count(const struct md_fd_messages *s) { return s ? s->count : 0; }
static struct md_fd_message **slot(struct md_fd_messages *s, uint64_t cookie) {
    struct md_fd_message **p=&s->buckets[cookie%BUCKETS];
    while (*p && (*p)->cookie!=cookie) p=&(*p)->next;
    return p;
}
static int carrier_cookie(int fd, uint64_t *cookie) {
    int value; socklen_t size=sizeof(value);
    if (getsockopt(fd,SOL_SOCKET,SO_DOMAIN,&value,&size)) return -errno;
    if (value!=AF_UNIX) return -EAFNOSUPPORT;
    size=sizeof(value);
    if (getsockopt(fd,SOL_SOCKET,SO_TYPE,&value,&size)) return -errno;
    if (value!=SOCK_SEQPACKET) return -EPROTOTYPE;
    size=sizeof(*cookie);
    if (getsockopt(fd,SOL_SOCKET,SO_COOKIE,cookie,&size)) return -errno;
    return size==sizeof(*cookie) && *cookie ? 0 : -EPROTO;
}
int md_fd_message_issue(struct md_fd_message *p, int carrier) {
    if (!p || !p->source.scope) return -EINVAL;
    if (p->published) return -ESTALE;
    uint64_t cookie;
    int error=carrier_cookie(carrier,&cookie);
    if (!error) { p->route.cookie=cookie; p->published=1; }
    return error;
}
int md_fd_messages_publish(struct md_fd_messages *s, struct md_fd_message *p,
        const struct md_ipc_connection *destination, int carrier, int reader) {
    if (!s || !p || !destination || destination->side>1) return -EINVAL;
    if (p->published) return -ESTALE;
    if (p->source.scope && (p->route.side!=destination->side
            || memcmp(p->route.link,destination->link,sizeof(destination->link)))) return -EXDEV;
    uint64_t cookie;
    int error=carrier_cookie(carrier,&cookie);
    if (error) return error;
    struct md_fd_message **entry=slot(s,cookie);
    if (*entry) return -EEXIST;
    struct stat identity;
    if (fstat(reader,&identity)) return -errno;
    int flags=fcntl(reader,F_GETFL);
    if (flags<0) return -errno;
    int fd_flags=fcntl(reader,F_GETFD);
    if (fd_flags<0) return -errno;
    if (!S_ISFIFO(identity.st_mode) || (flags&O_ACCMODE)!=O_RDONLY
            || !(flags&O_NONBLOCK) || !(fd_flags&FD_CLOEXEC)) return -EINVAL;
    int events=s->events;
    if (events<0 && (events=epoll_create1(EPOLL_CLOEXEC))<0) return -errno;
    struct epoll_event event={.events=EPOLLIN,.data.u64=cookie};
    if (epoll_ctl(events,EPOLL_CTL_ADD,reader,&event)) {
        error=-errno;
        if (s->events<0) close(events);
        return error;
    }
    s->events=events; p->cookie=cookie; p->destination=*destination;
    p->route.cookie=cookie;
    p->monitor=reader; p->owner=s; p->published=1;
    *entry=md_fd_message_retain(p); ++s->count;
    return 0;
}
static void retire(struct md_fd_messages *s, struct md_fd_message **entry) {
    struct md_fd_message *p=*entry;
    *entry=p->next; --s->count;
    close(p->monitor); p->monitor=-1; p->next=NULL; p->owner=NULL;
    md_fd_message_release(p);
}
int md_fd_messages_withdraw(struct md_fd_messages *s, struct md_fd_message *p) {
    if (!s || !p || p->owner!=s) return -ENOENT;
    if (epoll_ctl(s->events,EPOLL_CTL_DEL,p->monitor,NULL)) return -errno;
    retire(s,slot(s,p->cookie)); return 0;
}
void md_fd_messages_free(struct md_fd_messages *s) {
    if (!s) return;
    if (s->events>=0) close(s->events);
    for (unsigned i=0;i<BUCKETS;++i) while (s->buckets[i]) retire(s,&s->buckets[i]);
    free(s);
}
int md_fd_messages_find(struct md_fd_messages *s, const struct md_ipc_connection *destination,
        int carrier, struct md_fd_message **out) {
    if (!destination || destination->side>1 || !out || *out) return -EINVAL;
    if (!s) return -ENODATA;
    uint64_t cookie;
    int error=carrier_cookie(carrier,&cookie);
    if (error) return error==-ENOTSOCK || error==-EAFNOSUPPORT || error==-EPROTOTYPE ? -ENODATA : error;
    struct md_fd_message *p=*slot(s,cookie);
    if (!p) return -ENODATA;
    if (p->destination.side!=destination->side
            || memcmp(p->destination.link,destination->link,sizeof(destination->link))) return -EXDEV;
    *out=md_fd_message_retain(p); return 0;
}
int md_fd_message_route_read(int carrier, const struct md_ipc_binding *destination,
        struct md_fd_message_route *out) {
    if (!destination || !destination->scope || destination->connection.side>1 || !out) return -EINVAL;
    if (destination->transport!=MD_IPC_TRANSPORT_ORIGINS_V1) return -ENOTSUP;
    uint64_t cookie;
    int r=carrier_cookie(carrier,&cookie);
    if (r) return r;
    struct md_fd_message_route route;
    struct iovec io={&route,sizeof(route)};
    struct msghdr msg={.msg_iov=&io,.msg_iovlen=1};
    ssize_t n=recvmsg(carrier,&msg,MSG_PEEK|MSG_DONTWAIT);
    if (n<0) return -errno;
    if (!n) return -ECONNRESET;
    if (n!=sizeof(route) || (msg.msg_flags&MSG_TRUNC) || route.magic!=MD_FD_ROUTE_MAGIC
            || !route.count || route.count>MD_FD_RECEIPT_MAX || route.side>1) return -EPROTO;
    if (route.version!=MD_FD_ROUTE_VERSION) return -EPROTONOSUPPORT;
    char id[33]; memcpy(id,route.launch,32); id[32]=0;
    if (strspn(id,"0123456789abcdef")!=32) return -EPROTO;
    if (route.cookie!=cookie || route.side!=destination->connection.side
            || memcmp(route.link,destination->connection.link,sizeof(route.link))) return -EXDEV;
    *out=route; return 0;
}
int md_fd_messages_claim(struct md_fd_messages *s, const struct md_ipc_binding *destination,
        int carrier, const struct md_fd_message_route *route, struct md_fd_message **out) {
    if (!destination || !destination->scope || !route || !out || *out) return -EINVAL;
    if (destination->transport!=MD_IPC_TRANSPORT_ORIGINS_V1) return -ENOTSUP;
    struct md_fd_message *p=NULL;
    int r=md_fd_messages_find(s,&destination->connection,carrier,&p);
    if (r) return r;
    if (!md_ipc_binding_same_scope(&p->source,destination)) r=-EXDEV;
    else if (memcmp(&p->route,route,sizeof(*route))) r=-ESTALE;
    if (r) md_fd_message_release(p);
    else *out=p;
    return r;
}
int md_fd_messages_dispatch(struct md_fd_messages *s) {
    if (!s || s->events<0) return 0;
    struct epoll_event events[16];
    /* Readiness drain only; the supervisor owns the blocking event wait. */
    int count=epoll_wait(s->events,events,16,0);
    if (count<0) return errno==EINTR ? 0 : -errno;
    int retired=0, error=0;
    for (int i=0;i<count;++i) {
        struct md_fd_message **entry=slot(s,events[i].data.u64), *p=*entry;
        if (!p) continue;
        char byte;
        ssize_t n=read(p->monitor,&byte,1);
        if (n<0 && (errno==EAGAIN || errno==EINTR)) continue;
        int r=n<0 ? -errno : n ? -EPROTO : md_fd_messages_withdraw(s,p);
        if (r) { if (!error) error=r; }
        else ++retired;
    }
    return error ? error : retired;
}

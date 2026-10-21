#define _GNU_SOURCE
#include "network_endpoint.h"
#include "network_internal.h"
#include "network_forward.h"
#include "fd_selector.h"
#include "guest_identity.h"
#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

struct direct_path { struct direct_path *next; struct md_network_flow_path path; };
struct md_network_endpoint {
    struct md_fd_object object;
    struct md_network_namespace *space;
    struct md_network_endpoint *next;
    int type, protocol, bound, connected, accepted;
    uint32_t source;
    struct sockaddr_in local, native, peer;
    struct direct_path *direct;
    unsigned direct_count;
    uint64_t inode;
    uint32_t uid;
};
static void destroy(struct md_fd_object *object) {
    struct md_network_endpoint *e=(void *)object;
    struct md_network_fabric *f=e->space->fabric;
    pthread_mutex_lock(&f->lock);
    struct md_network_endpoint **at=&f->endpoints;
    while (*at && *at!=e) at=&(*at)->next;
    if (*at) *at=e->next;
    md_network_forward_endpoint_closed(e->space,e);
    while (e->direct) { struct direct_path *p=e->direct; e->direct=p->next; free(p); }
    pthread_mutex_unlock(&f->lock);
    md_network_namespace_release(e->space); free(e);
}
static int direct_path(struct md_network_endpoint *e,const struct md_network_flow_path *path) {
    for (struct direct_path *p=e->direct;p;p=p->next)
        if (p->path.original.destination==path->original.destination
                && p->path.original.destination_port==path->original.destination_port) return 0;
    if (e->direct_count==1024) return -ENOSPC;
    struct direct_path *p=malloc(sizeof(*p));
    if (!p) return -ENOMEM;
    p->path=*path; p->next=e->direct; e->direct=p; ++e->direct_count; return 0;
}
int md_network_endpoint_filter_update(struct md_network_namespace *n,struct md_network_filter *filter) {
    /* Direct kernel streams cannot be moved into a relay after connect. Reject
     * a revoking transaction atomically rather than retain a stale allowance.
     * No per-read/write broker call is added to the ordinary data path. */
    for (struct md_network_endpoint *e=n->fabric->endpoints;e;e=e->next)
        for (struct direct_path *p=e->direct;p;p=p->next) {
            int error=md_network_flow_admits(n,filter,&p->path);
            if (error) return error==-EACCES ? -EBUSY : error;
        }
    return 0;
}
static const struct md_fd_object_type endpoint_type={.destroy=destroy,.selectors=1U<<MD_FD_SELECTOR_PROC};
int md_network_endpoint_is(const struct md_fd_object *o) { return o && o->type==&endpoint_type; }
struct md_network_namespace *md_network_endpoint_namespace(const struct md_fd_object *o) {
    return md_network_endpoint_is(o) ? ((const struct md_network_endpoint *)o)->space : NULL;
}
int md_network_endpoint_enabled(const struct md_network_namespace *n) { return n && n->fabric->endpoints_enabled; }
static struct md_network_endpoint *create(struct md_network_namespace *n,int type,int protocol) {
    struct md_network_endpoint *e=calloc(1,sizeof(*e));
    if (!e) return NULL;
    md_fd_object_init(&e->object,&endpoint_type);
    e->space=md_network_namespace_retain(n); e->type=type; e->protocol=protocol;
    e->local.sin_family=e->native.sin_family=e->peer.sin_family=AF_INET;
    pthread_mutex_lock(&n->fabric->lock);
    e->next=n->fabric->endpoints; n->fabric->endpoints=e;
    pthread_mutex_unlock(&n->fabric->lock); return e;
}
int md_network_endpoint_open(struct md_network_namespace *n,uint32_t uid,int family,int type,int protocol,
        struct md_fd_object **out,int *fd) {
    if (!md_network_endpoint_enabled(n)) return -EOPNOTSUPP;
    if (family!=AF_INET) return -EAFNOSUPPORT;
    int base=type&15;
    if (base!=SOCK_STREAM && base!=SOCK_DGRAM) return -ESOCKTNOSUPPORT;
    int expected=base==SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP;
    if (protocol && protocol!=expected) return -EPROTONOSUPPORT;
    struct md_network_endpoint *e=create(n,base,expected);
    if (!e) return -ENOMEM;
    int native=socket(family,type|SOCK_CLOEXEC,protocol);
    if (native<0) { int error=-errno; md_fd_object_release(&e->object); return error; }
    struct stat st;
    if (fstat(native,&st)) { int error=-errno; close(native); md_fd_object_release(&e->object); return error; }
    pthread_mutex_lock(&n->fabric->lock);
    e->inode=st.st_ino; e->uid=uid;
    pthread_mutex_unlock(&n->fabric->lock);
    *out=&e->object; *fd=native; return 0;
}
static int address(const struct sockaddr *a,socklen_t length,struct sockaddr_in *out) {
    if (length<sizeof(*out)) return -EINVAL;
    if (a->sa_family!=AF_INET) return -EAFNOSUPPORT;
    memcpy(out,a,sizeof(*out)); memset(out->sin_zero,0,sizeof(out->sin_zero)); return 0;
}
static int loopback(uint32_t ip) { return (ntohl(ip)>>24)==127; }
static struct md_network_interface *local_interface(struct md_network_namespace *n,uint32_t ip,int up) {
    /* Logical peers resolve the live catalogue directly. arp_notify needs no
     * gratuitous packet: there is no neighbor cache to invalidate on link or
     * address changes, and no announcement is sent onto Android's network. */
    return md_network_local_interface(n,ip,up);
}
static int conflicts(struct md_network_endpoint *e,const struct sockaddr_in *a) {
    for (struct md_network_endpoint *other=e->space->fabric->endpoints;other;other=other->next)
        if (other!=e && other->space==e->space && other->type==e->type && other->bound && !other->accepted
                && other->local.sin_port==a->sin_port && (!other->local.sin_addr.s_addr
                    || !a->sin_addr.s_addr || other->local.sin_addr.s_addr==a->sin_addr.s_addr)) return 1;
    return 0;
}
static int bind_endpoint(struct md_fd_object *o,int fd,const struct md_identity *identity,
        const struct sockaddr *a,socklen_t length,int external) {
    if (!md_network_endpoint_is(o)) return -EBADF;
    struct md_network_endpoint *e=(void *)o;
    struct sockaddr_in logical;
    int error=address(a,length,&logical); if (error) return error;
    struct md_network_namespace *n=e->space;
    pthread_mutex_lock(&n->fabric->lock);
    if (e->bound) error=-EINVAL;
    else if (logical.sin_addr.s_addr && !local_interface(n,logical.sin_addr.s_addr,0)) error=-EADDRNOTAVAIL;
    else if (logical.sin_port && ntohs(logical.sin_port)<n->unprivileged_port
            && !md_identity_capable_in(identity,n->owner,CAP_NET_BIND_SERVICE)) error=-EACCES;
    else if (logical.sin_port && conflicts(e,&logical)) error=-EADDRINUSE;
    struct sockaddr_in native=logical;
    struct md_network_port_reservation *reservation=NULL;
    struct md_network_interface *bound_link=local_interface(n,logical.sin_addr.s_addr,0);
    int internal=logical.sin_addr.s_addr && !loopback(logical.sin_addr.s_addr)
        && bound_link && bound_link->kind!=MD_LINK_UPLINK;
    int published=external && n->mode==MD_NETWORK_ROUTED && !internal;
    if (!error) {
        native.sin_addr.s_addr=loopback(logical.sin_addr.s_addr) ? htonl(INADDR_LOOPBACK) : INADDR_ANY;
        /* bind/getsockname are nonblocking. Publication and conflict checking
         * share one fabric turn; no guest memory or stream IO is under it. */
        unsigned attempts=logical.sin_port ? 1 : n->local_ports[1]-n->local_ports[0]+1;
        int automatic=!logical.sin_port;
        error=-EADDRINUSE;
        for (unsigned i=0;i<attempts;++i) {
            if (automatic) {
                if (n->next_port<n->local_ports[0] || n->next_port>n->local_ports[1]) n->next_port=n->local_ports[0];
                logical.sin_port=htons((uint16_t)n->next_port++);
                if (conflicts(e,&logical)) continue;
            }
            if (published) {
                error=md_network_forward_bind(n,e,e->type,&logical,&reservation);
                if (error) { if (automatic && error==-EADDRINUSE) continue; break; }
            }
            native.sin_port=0;
            if (!bind(fd,(void *)&native,sizeof(native))) { error=0; break; }
            error=-errno;
            md_network_forward_bound(reservation,0); reservation=NULL;
            if (!automatic || error!=-EADDRINUSE) break;
        }
        if (!error) {
            socklen_t size=sizeof(native);
            if (getsockname(fd,(void *)&native,&size)) error=-errno;
            else {
                e->local=logical; e->native=native; e->bound=1;
            }
        }
    }
    md_network_forward_bound(reservation,!error);
    pthread_mutex_unlock(&n->fabric->lock); return error;
}
int md_network_endpoint_bind(struct md_fd_object *o,int fd,const struct md_identity *identity,
        const struct sockaddr *a,socklen_t length) {
    return bind_endpoint(o,fd,identity,a,length,1);
}
int md_network_endpoint_listen(struct md_fd_object *o,int fd,int backlog) {
    if (!md_network_endpoint_is(o)) return -EBADF;
    struct md_network_endpoint *e=(void *)o;
    pthread_mutex_lock(&e->space->fabric->lock);
    struct md_network_port_reservation *reservation=NULL;
    struct md_network_interface *link=local_interface(e->space,e->local.sin_addr.s_addr,0);
    int external=e->space->mode==MD_NETWORK_ROUTED && (!e->local.sin_addr.s_addr
        || loopback(e->local.sin_addr.s_addr) || (link && link->kind==MD_LINK_UPLINK));
    int error=external ? md_network_forward_bind(e->space,e,e->type,&e->local,&reservation) : 0;
    if (!error) error=listen(fd,backlog) ? -errno : md_network_forward_listen(e->space,e,backlog);
    md_network_forward_bound(reservation,!error);
    pthread_mutex_unlock(&e->space->fabric->lock); return error;
}
int md_network_endpoint_resolve(struct md_network_fabric *f,uint64_t destination,int type,
        const struct sockaddr_in *logical,struct sockaddr_in *native,const void **endpoint) {
    *native=*logical;
    if (endpoint) *endpoint=NULL;
    if (!destination) return 0;
    struct md_network_namespace *n=md_network_space_find(f,destination);
    if (!n) return -ENETUNREACH;
    for (struct md_network_endpoint *e=f->endpoints;e;e=e->next)
        if (e->space==n && e->type==type && e->bound && !e->accepted
                && e->local.sin_port==logical->sin_port && (!e->local.sin_addr.s_addr
                    || e->local.sin_addr.s_addr==logical->sin_addr.s_addr)) {
            if (endpoint) *endpoint=e;
            *native=e->native; native->sin_addr.s_addr=htonl(INADDR_LOOPBACK); return 0;
        }
    return n->mode==MD_NETWORK_ROUTED && loopback(logical->sin_addr.s_addr) ? 0 : -ECONNREFUSED;
}
int md_network_endpoint_destination(struct md_fd_object *o,const struct sockaddr *a,socklen_t length,
        struct sockaddr_storage *out,socklen_t *out_length) {
    return md_network_endpoint_destination_info(o,a,length,NULL,out,out_length);
}
int md_network_endpoint_destination_info(struct md_fd_object *o,const struct sockaddr *a,socklen_t length,
        struct in_pktinfo *info,struct sockaddr_storage *out,socklen_t *out_length) {
    if (!md_network_endpoint_is(o)) return -EBADF;
    struct md_network_endpoint *e=(void *)o;
    struct sockaddr_in logical;
    int error=address(a,length,&logical); if (error) return error;
    struct md_network_namespace *n=e->space;
    pthread_mutex_lock(&n->fabric->lock);
    struct sockaddr_in native=logical;
    struct sockaddr_in local=e->local;
    if (info) {
        struct md_network_interface *link=info->ipi_ifindex
            ? md_network_interface_find(n,(unsigned)info->ipi_ifindex,NULL) : NULL;
        if (info->ipi_ifindex && !link) error=-ENODEV;
        else if (info->ipi_spec_dst.s_addr && !local_interface(n,info->ipi_spec_dst.s_addr,0)) error=-EADDRNOTAVAIL;
        else if (link && info->ipi_spec_dst.s_addr
                && local_interface(n,info->ipi_spec_dst.s_addr,0)!=link) error=-EINVAL;
        if (!error) local.sin_addr.s_addr=info->ipi_spec_dst.s_addr
            ? info->ipi_spec_dst.s_addr : link ? link->ipv4 : local.sin_addr.s_addr;
    }
    if (!error && !md_network_forward_destination(n,e,e->type,&local,&logical,&native)) {
        struct md_filter_packet packet={.source=local.sin_addr.s_addr,.source_port=local.sin_port,
            .destination=logical.sin_addr.s_addr,.destination_port=logical.sin_port,.protocol=e->protocol,.state=8};
        struct md_network_flow_path path;
        error=md_network_flow_route(n,&packet,0,&path);
        /* Interface selection must agree with the supported route. Do not
         * silently accept policy routing which the logical fabric cannot do. */
        if (!error && info && info->ipi_ifindex) {
            struct md_network_interface *route=md_network_route_find(n,logical.sin_addr.s_addr,NULL);
            if (!route || route->info.index!=(unsigned)info->ipi_ifindex) error=-EOPNOTSUPP;
        }
        struct sockaddr_in translated={.sin_family=AF_INET,.sin_addr.s_addr=packet.destination,.sin_port=packet.destination_port};
        if (!error) error=md_network_endpoint_resolve(n->fabric,path.destination,e->type,&translated,&native,NULL);
        /* A private datagram's queued source must outlive the sending socket.
         * The existing bounded flow owner retains both logical directions. */
        if (!error && e->type==SOCK_DGRAM && path.destination) path.mediated=1;
        if (!error && path.mediated) {
            struct sockaddr_in target=native;
            error=md_network_forward_route(n,e,e->type,&e->native,&target,&path,&native);
        } else if (!error) error=direct_path(e,&path);
    }
    if (!error) {
        memcpy(out,&native,sizeof(native)); *out_length=sizeof(native);
        if (info) *info=(struct in_pktinfo){.ipi_spec_dst=e->native.sin_addr};
    }
    pthread_mutex_unlock(&n->fabric->lock); return error;
}
static uint32_t source_address(struct md_network_namespace *n,uint32_t target) {
    struct md_network_interface *l=md_network_route_find(n,target,NULL);
    return l ? l->ipv4 : INADDR_ANY;
}
int md_network_endpoint_autobind(struct md_fd_object *o,int fd,const struct md_identity *identity,
        const struct sockaddr *a,socklen_t length) {
    if (!md_network_endpoint_is(o)) return -EBADF;
    struct md_network_endpoint *e=(void *)o;
    struct sockaddr_in target;
    int error=address(a,length,&target); if (error) return error;
    pthread_mutex_lock(&e->space->fabric->lock);
    int bound=e->bound;
    e->source=source_address(e->space,target.sin_addr.s_addr);
    pthread_mutex_unlock(&e->space->fabric->lock);
    if (!bound) {
        struct sockaddr_in any={.sin_family=AF_INET};
        error=bind_endpoint(o,fd,identity,(void *)&any,sizeof(any),0);
        /* Another operation on the same OFD may have completed autobind. */
        if (error==-EINVAL) {
            pthread_mutex_lock(&e->space->fabric->lock); bound=e->bound; pthread_mutex_unlock(&e->space->fabric->lock);
            if (bound) error=0;
        }
    }
    return error;
}
int md_network_endpoint_connected(struct md_fd_object *o,int fd,const struct sockaddr *a,socklen_t length) {
    if (!md_network_endpoint_is(o)) return -EBADF;
    struct md_network_endpoint *e=(void *)o;
    struct sockaddr_in peer,native; socklen_t size=sizeof(native);
    int error=address(a,length,&peer); if (error) return error;
    if (getsockname(fd,(void *)&native,&size)) return -errno;
    pthread_mutex_lock(&e->space->fabric->lock);
    e->peer=peer; e->connected=1; e->native=native;
    if (!e->bound) { e->local=native; e->local.sin_addr.s_addr=source_address(e->space,peer.sin_addr.s_addr); e->bound=1; }
    else if (!e->local.sin_addr.s_addr) e->local.sin_addr.s_addr=source_address(e->space,peer.sin_addr.s_addr);
    pthread_mutex_unlock(&e->space->fabric->lock); return 0;
}
int md_network_endpoint_name(struct md_fd_object *o,int fd,int peer,struct sockaddr_storage *out,socklen_t *size) {
    if (!md_network_endpoint_is(o)) return -EBADF;
    struct md_network_endpoint *e=(void *)o;
    struct sockaddr_in native; socklen_t length=sizeof(native);
    if ((peer ? getpeername(fd,(void *)&native,&length) : getsockname(fd,(void *)&native,&length))) return -errno;
    pthread_mutex_lock(&e->space->fabric->lock);
    struct sockaddr_in result=peer ? e->peer : e->local;
    if (peer && !e->connected) result=native;
    else if (!peer && !e->bound) result=native;
    memcpy(out,&result,sizeof(result)); *size=sizeof(result);
    pthread_mutex_unlock(&e->space->fabric->lock); return 0;
}
int md_network_endpoint_source(struct md_fd_object *o,struct sockaddr_storage *address,socklen_t *length) {
    return md_network_endpoint_source_info(o,address,length,NULL);
}
int md_network_endpoint_source_info(struct md_fd_object *o,struct sockaddr_storage *address,socklen_t *length,
        struct in_pktinfo *info) {
    if (!md_network_endpoint_is(o)) return -EBADF;
    if (*length!=sizeof(struct sockaddr_in) || address->ss_family!=AF_INET) return -EAFNOSUPPORT;
    struct md_network_endpoint *e=(void *)o;
    struct sockaddr_in *a=(void *)address;
    /* Logical inter-namespace traffic is transported over native loopback.
     * An internet peer sharing a local ephemeral port is still that peer. */
    pthread_mutex_lock(&e->space->fabric->lock);
    uint32_t local=e->local.sin_addr.s_addr;
    if (loopback(a->sin_addr.s_addr) && !md_network_forward_source(e->space,e->type,a,&local))
      for (struct md_network_endpoint *other=e->space->fabric->endpoints;other;other=other->next)
        if (other->bound && !other->accepted && other->type==e->type && other->native.sin_port==a->sin_port
                && (!other->native.sin_addr.s_addr || other->native.sin_addr.s_addr==a->sin_addr.s_addr)) {
            *a=other->local;
            if (!a->sin_addr.s_addr) a->sin_addr.s_addr=other->source ? other->source
                : source_address(other->space,e->local.sin_addr.s_addr);
            if (!local) for (struct direct_path *p=other->direct;p;p=p->next)
                if (p->path.destination==e->space->inode
                        && p->path.translated.destination_port==e->local.sin_port) {
                    local=p->path.translated.destination; break;
                }
            break;
        }
    if (info) {
        if (!local) local=source_address(e->space,a->sin_addr.s_addr);
        struct md_network_interface *link=local_interface(e->space,local,0);
        *info=(struct in_pktinfo){.ipi_ifindex=link ? (int)link->info.index : 0,
            .ipi_spec_dst.s_addr=local,.ipi_addr.s_addr=local};
    }
    pthread_mutex_unlock(&e->space->fabric->lock); return 0;
}
int md_network_endpoint_accept(struct md_fd_object *o,int fd,struct md_fd_object **out) {
    if (!md_network_endpoint_is(o)) return -EBADF;
    struct md_network_endpoint *parent=(void *)o;
    struct sockaddr_storage peer; socklen_t length=sizeof(peer);
    if (getpeername(fd,(void *)&peer,&length)) return -errno;
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    int error=md_network_endpoint_source(o,&peer,&length); if (error) return error;
    struct md_network_endpoint *e=create(parent->space,parent->type,parent->protocol);
    if (!e) return -ENOMEM;
    pthread_mutex_lock(&parent->space->fabric->lock);
    e->local=parent->local; e->native=parent->native; e->bound=e->connected=e->accepted=1;
    e->inode=st.st_ino; e->uid=parent->uid;
    memcpy(&e->peer,&peer,sizeof(e->peer));
    for (struct md_network_endpoint *client=parent->space->fabric->endpoints;client && !error;client=client->next)
        if (client!=e && client->type==SOCK_STREAM)
            for (struct direct_path *p=client->direct;p && !error;p=p->next)
                if (p->path.destination==parent->space->inode
                        && p->path.original.source==e->peer.sin_addr.s_addr && p->path.original.source_port==e->peer.sin_port
                        && p->path.translated.destination_port==e->local.sin_port) error=direct_path(e,&p->path);
    pthread_mutex_unlock(&parent->space->fabric->lock);
    if (error) { md_fd_object_release(&e->object); return error; }
    *out=&e->object; return 0;
}
static int inode_order(const void *left,const void *right) {
    uint64_t a=((const struct md_network_endpoint_info *)left)->inode;
    uint64_t b=((const struct md_network_endpoint_info *)right)->inode;
    return (a>b)-(a<b);
}
int md_network_endpoint_snapshot(struct md_network_namespace *n,int protocol,
        struct md_network_endpoint_info **out,size_t *count) {
    *out=NULL; *count=0;
    if (!md_network_namespace_managed(n)) return -EXDEV;
    pthread_mutex_lock(&n->fabric->lock);
    size_t size=0;
    for (struct md_network_endpoint *e=n->fabric->endpoints;e;e=e->next)
        if (e->space==n && e->protocol==protocol && e->inode && e->bound) ++size;
    struct md_network_endpoint_info *items=size ? calloc(size,sizeof(*items)) : NULL;
    if (size && !items) { pthread_mutex_unlock(&n->fabric->lock); return -ENOMEM; }
    for (struct md_network_endpoint *e=n->fabric->endpoints;e;e=e->next)
        if (e->space==n && e->protocol==protocol && e->inode && e->bound)
            items[(*count)++]=(struct md_network_endpoint_info){
                .inode=e->inode,.uid=e->uid,.local=e->local,.peer=e->peer};
    pthread_mutex_unlock(&n->fabric->lock);
    if (size) qsort(items,size,sizeof(*items),inode_order);
    *out=items; return 0;
}

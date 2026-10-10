#define _GNU_SOURCE
#include "network_endpoint.h"
#include "network_internal.h"
#include "fd_selector.h"
#include "guest_identity.h"
#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct md_network_endpoint {
    struct md_fd_object object;
    struct md_network_namespace *space;
    struct md_network_endpoint *next;
    int type, protocol, bound, connected, accepted;
    uint32_t source;
    struct sockaddr_in local, native, peer;
};
static void destroy(struct md_fd_object *object) {
    struct md_network_endpoint *e=(void *)object;
    struct md_network_fabric *f=e->space->fabric;
    pthread_mutex_lock(&f->lock);
    struct md_network_endpoint **at=&f->endpoints;
    while (*at && *at!=e) at=&(*at)->next;
    if (*at) *at=e->next;
    pthread_mutex_unlock(&f->lock);
    md_network_namespace_release(e->space); free(e);
}
static const struct md_fd_object_type endpoint_type={.destroy=destroy,.selectors=1U<<MD_FD_SELECTOR_PROC};
int md_network_endpoint_is(const struct md_fd_object *o) { return o && o->type==&endpoint_type; }
int md_network_endpoint_enabled(const struct md_network_namespace *n) { return n && n->fabric->routed; }
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
int md_network_endpoint_open(struct md_network_namespace *n,int family,int type,int protocol,
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
    *out=&e->object; *fd=native; return 0;
}
static int address(const struct sockaddr *a,socklen_t length,struct sockaddr_in *out) {
    if (length<sizeof(*out)) return -EINVAL;
    if (a->sa_family!=AF_INET) return -EAFNOSUPPORT;
    memcpy(out,a,sizeof(*out)); memset(out->sin_zero,0,sizeof(out->sin_zero)); return 0;
}
static int loopback(uint32_t ip) { return (ntohl(ip)>>24)==127; }
static struct md_network_interface *local_interface(struct md_network_namespace *n,uint32_t ip,int up) {
    for (unsigned i=0;i<n->count;++i) {
        struct md_network_interface *l=&n->links[i];
        if ((!up || (l->info.flags&IFF_UP)) && (l->ipv4==ip || (l->kind==MD_LINK_LOOPBACK && loopback(ip)))) return l;
    }
    return NULL;
}
static int conflicts(struct md_network_endpoint *e,const struct sockaddr_in *a) {
    for (struct md_network_endpoint *other=e->space->fabric->endpoints;other;other=other->next)
        if (other!=e && other->space==e->space && other->type==e->type && other->bound && !other->accepted
                && other->local.sin_port==a->sin_port && (!other->local.sin_addr.s_addr
                    || !a->sin_addr.s_addr || other->local.sin_addr.s_addr==a->sin_addr.s_addr)) return 1;
    return 0;
}
int md_network_endpoint_bind(struct md_fd_object *o,int fd,const struct md_identity *identity,
        const struct sockaddr *a,socklen_t length) {
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
            native.sin_port=n->mode==MD_NETWORK_PRIVATE ? 0 : logical.sin_port;
            if (!bind(fd,(void *)&native,sizeof(native))) { error=0; break; }
            error=-errno;
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
    pthread_mutex_unlock(&n->fabric->lock); return error;
}
/* A veth attachment must reach an UP bridge or its peer. Namespaces with only
 * a loopback interface never acquire connectivity merely by existing. */
static struct md_network_interface *attachment(struct md_network_namespace *n,struct md_network_interface *l,
        struct md_network_namespace **owner) {
    if (!(l->info.flags&IFF_UP)) return NULL;
    if (l->kind==MD_LINK_UPLINK || l->kind==MD_LINK_BRIDGE) { *owner=n; return l; }
    if (l->kind!=MD_LINK_VETH) return NULL;
    struct md_network_namespace *other=md_network_interface_owner(n->fabric,l->peer);
    struct md_network_interface *peer=other ? md_network_interface_find(other,l->peer,NULL) : NULL;
    if (!peer || !(peer->info.flags&IFF_UP)) return NULL;
    struct md_network_interface *master=peer->master ? md_network_interface_find(other,peer->master,NULL) : peer;
    if (!master || !(master->info.flags&IFF_UP)) return NULL;
    *owner=other; return master;
}
static int reachable(struct md_network_namespace *from,struct md_network_namespace *to,uint32_t ip) {
    if (from==to) return local_interface(to,ip,1)!=NULL;
    struct md_network_interface *out=md_network_route_find(from,ip,NULL), *in=local_interface(to,ip,1);
    struct md_network_namespace *a=NULL,*b=NULL;
    out=out ? attachment(from,out,&a) : NULL;
    in=in ? attachment(to,in,&b) : NULL;
    return out && in && a==b && out->info.index==in->info.index;
}
int md_network_endpoint_destination(struct md_fd_object *o,const struct sockaddr *a,socklen_t length,
        struct sockaddr_storage *out,socklen_t *out_length) {
    if (!md_network_endpoint_is(o)) return -EBADF;
    struct md_network_endpoint *e=(void *)o;
    struct sockaddr_in logical;
    int error=address(a,length,&logical); if (error) return error;
    struct md_network_namespace *n=e->space, *destination=NULL;
    pthread_mutex_lock(&n->fabric->lock);
    if (loopback(logical.sin_addr.s_addr)) destination=n;
    else for (struct md_network_namespace *s=n->fabric->spaces;s;s=s->next)
        if (local_interface(s,logical.sin_addr.s_addr,0)) { destination=s; break; }
    struct sockaddr_in native=logical;
    if (destination) {
        if (!reachable(n,destination,logical.sin_addr.s_addr)) error=-ENETUNREACH;
        else {
            error=-ECONNREFUSED;
            for (struct md_network_endpoint *other=n->fabric->endpoints;other;other=other->next)
                if (other->space==destination && other->type==e->type && other->bound && !other->accepted
                        && other->local.sin_port==logical.sin_port && (!other->local.sin_addr.s_addr
                            || other->local.sin_addr.s_addr==logical.sin_addr.s_addr)) {
                    native=other->native; native.sin_addr.s_addr=htonl(INADDR_LOOPBACK); error=0; break;
                }
            /* The initial routed namespace includes Android's loopback services.
             * Private namespaces never fall through to that host address space. */
            if (error==-ECONNREFUSED && n->mode==MD_NETWORK_ROUTED && destination==n
                    && loopback(logical.sin_addr.s_addr)) error=0;
        }
    } else {
        struct md_network_interface *outgoing=md_network_route_find(n,logical.sin_addr.s_addr,NULL);
        struct md_network_namespace *owner=NULL;
        outgoing=outgoing ? attachment(n,outgoing,&owner) : NULL;
        if (!outgoing || !owner || owner->mode!=MD_NETWORK_ROUTED) error=-ENETUNREACH;
        /* Link-local multicast and broadcast need a packet backend, not an
         * accidental submission to Android's physical network. */
        else if ((ntohl(logical.sin_addr.s_addr)>>28)==14 || logical.sin_addr.s_addr==INADDR_BROADCAST)
            error=-EOPNOTSUPP;
    }
    if (!error) { memcpy(out,&native,sizeof(native)); *out_length=sizeof(native); }
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
        error=md_network_endpoint_bind(o,fd,identity,(void *)&any,sizeof(any));
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
    if (!md_network_endpoint_is(o)) return -EBADF;
    if (*length!=sizeof(struct sockaddr_in) || address->ss_family!=AF_INET) return -EAFNOSUPPORT;
    struct md_network_endpoint *e=(void *)o;
    struct sockaddr_in *a=(void *)address;
    /* Logical inter-namespace traffic is transported over native loopback.
     * An internet peer sharing a local ephemeral port is still that peer. */
    if (!loopback(a->sin_addr.s_addr)) return 0;
    pthread_mutex_lock(&e->space->fabric->lock);
    for (struct md_network_endpoint *other=e->space->fabric->endpoints;other;other=other->next)
        if (other->bound && !other->accepted && other->type==e->type && other->native.sin_port==a->sin_port
                && (!other->native.sin_addr.s_addr || other->native.sin_addr.s_addr==a->sin_addr.s_addr)) {
            *a=other->local;
            if (!a->sin_addr.s_addr) a->sin_addr.s_addr=other->source ? other->source
                : source_address(other->space,e->local.sin_addr.s_addr);
            break;
        }
    pthread_mutex_unlock(&e->space->fabric->lock); return 0;
}
int md_network_endpoint_accept(struct md_fd_object *o,int fd,struct md_fd_object **out) {
    if (!md_network_endpoint_is(o)) return -EBADF;
    struct md_network_endpoint *parent=(void *)o;
    struct sockaddr_storage peer; socklen_t length=sizeof(peer);
    if (getpeername(fd,(void *)&peer,&length)) return -errno;
    int error=md_network_endpoint_source(o,&peer,&length); if (error) return error;
    struct md_network_endpoint *e=create(parent->space,parent->type,parent->protocol);
    if (!e) return -ENOMEM;
    pthread_mutex_lock(&parent->space->fabric->lock);
    e->local=parent->local; e->native=parent->native; e->bound=e->connected=e->accepted=1;
    memcpy(&e->peer,&peer,sizeof(e->peer));
    pthread_mutex_unlock(&parent->space->fabric->lock);
    *out=&e->object; return 0;
}

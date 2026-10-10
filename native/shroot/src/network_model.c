#define _GNU_SOURCE
#include "network_internal.h"
#include "namespace_identity.h"
#include <errno.h>
#include <limits.h>
#include <linux/if_arp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

struct md_network_interface *md_network_interface_find(struct md_network_namespace *n,unsigned index,const char *name) {
    for (unsigned i=0;i<n->count;++i)
        if ((index && n->links[i].info.index==index) || (!index && name && !strcmp(n->links[i].info.name,name)))
            return &n->links[i];
    return NULL;
}
struct md_network_namespace *md_network_interface_owner(struct md_network_fabric *f,unsigned index) {
    if (index==1) return NULL;
    for (struct md_network_namespace *n=f->spaces;n;n=n->next)
        if (md_network_interface_find(n,index,NULL)) return n;
    return NULL;
}
struct md_network_interface *md_network_route_find(struct md_network_namespace *n,uint32_t ip,uint32_t *gateway) {
    struct md_network_interface *best=NULL;
    for (unsigned i=0;i<n->count;++i) {
        struct md_network_interface *l=&n->links[i];
        if (!(l->info.flags&IFF_UP) || !l->ipv4 || !l->prefix) continue;
        uint32_t mask=htonl(UINT32_MAX<<(32-l->prefix));
        if ((l->ipv4&mask)==(ip&mask) && (!best || l->prefix>best->prefix)) best=l;
    }
    if (gateway) *gateway=best ? 0 : n->default_gateway;
    if (!best) {
        best=md_network_interface_find(n,n->default_interface,NULL);
        if (best && (!(best->info.flags&IFF_UP) || !best->ipv4)) best=NULL;
    }
    return best;
}
int md_network_interface_reserve(struct md_network_namespace *n,unsigned extra) {
    if (extra>256-n->count) return -ENOSPC;
    if (n->count+extra<=n->capacity) return 0;
    unsigned capacity=n->capacity ? n->capacity*2 : 4;
    if (capacity<n->count+extra) capacity=n->count+extra;
    if (capacity>256) capacity=256;
    void *links=realloc(n->links,capacity*sizeof(*n->links));
    if (!links) return -ENOMEM;
    n->links=links; n->capacity=capacity; return 0;
}
static int valid_name(const char *name) {
    size_t length=strnlen(name,IFNAMSIZ);
    if (!length || length==IFNAMSIZ || !strcmp(name,".") || !strcmp(name,"..")) return 0;
    for (size_t i=0;i<length;++i)
        if (name[i]=='/' || name[i]==':' || name[i]==' ' || name[i]=='\t' || name[i]=='\n') return 0;
    return 1;
}
int md_network_interface_add(struct md_network_namespace *n,enum md_network_link_kind kind,const char *name,unsigned *index) {
    if (!valid_name(name)) return -EINVAL;
    if (md_network_interface_find(n,0,name)) return -EEXIST;
    if (n->fabric->next_index==INT_MAX) return -ENOSPC;
    int error=md_network_interface_reserve(n,1);
    if (error) return error;
    unsigned id=kind==MD_LINK_LOOPBACK ? 1 : n->fabric->next_index++;
    struct md_network_interface *link=&n->links[n->count++];
    *link=(struct md_network_interface){.kind=kind,.info={.index=id,
        .flags=kind==MD_LINK_LOOPBACK ? IFF_LOOPBACK : IFF_BROADCAST|IFF_MULTICAST,
        .mtu=kind==MD_LINK_LOOPBACK ? 65536 : 1500,
        .type=kind==MD_LINK_LOOPBACK ? ARPHRD_LOOPBACK : ARPHRD_ETHER,.state=IF_OPER_DOWN}};
    memcpy(link->info.name,name,strlen(name)+1);
    if (kind!=MD_LINK_LOOPBACK) {
        link->info.address[0]=2;
        link->info.address[3]=(unsigned char)(id>>16);
        link->info.address[4]=(unsigned char)(id>>8);
        link->info.address[5]=(unsigned char)id;
    }
    *index=id; return 0;
}
static void remove_one(struct md_network_namespace *n,unsigned index) {
    for (unsigned i=0;i<n->count;++i) {
        if (n->links[i].master==index) n->links[i].master=0;
        if (n->links[i].info.index==index) {
            memmove(n->links+i,n->links+i+1,(n->count-i-1)*sizeof(*n->links));
            --n->count; --i;
        }
    }
    if (n->default_interface==index) n->default_interface=n->default_gateway=0;
}
int md_network_interface_remove(struct md_network_namespace *n,unsigned index) {
    struct md_network_interface *link=md_network_interface_find(n,index,NULL);
    if (!link) return -ENODEV;
    if (link->kind==MD_LINK_LOOPBACK || link->kind==MD_LINK_UPLINK) return -EOPNOTSUPP;
    unsigned peer=link->peer;
    struct md_network_namespace *other=md_network_interface_owner(n->fabric,peer);
    remove_one(n,index);
    if (other) remove_one(other,peer);
    return 0;
}
int md_network_interface_move(struct md_network_namespace *from,unsigned index,struct md_network_namespace *to,const char *name) {
    if (from->fabric!=to->fabric) return -EXDEV;
    struct md_network_interface *link=md_network_interface_find(from,index,NULL);
    if (!link) return -ENODEV;
    if (link->kind!=MD_LINK_VETH) return -EOPNOTSUPP;
    if (!name) name=link->info.name;
    if (!valid_name(name)) return -EINVAL;
    struct md_network_interface *collision=md_network_interface_find(to,0,name);
    if (collision && collision!=link) return -EEXIST;
    char renamed[IFNAMSIZ]={0}; memcpy(renamed,name,strlen(name));
    if (from==to) { memcpy(link->info.name,renamed,IFNAMSIZ); return 0; }
    int error=md_network_interface_reserve(to,1);
    if (error) return error;
    struct md_network_interface moved=*link;
    moved.master=0; memcpy(moved.info.name,renamed,IFNAMSIZ);
    remove_one(from,index); to->links[to->count++]=moved;
    return 0;
}
static struct md_network_namespace *create(struct md_user_namespace *owner,enum md_network_mode mode,struct md_network_fabric *fabric) {
    struct md_network_namespace *n=calloc(1,sizeof(*n));
    if (!n) return NULL;
    int error=md_namespace_identity_new(&n->inode);
    if (error) { free(n); errno=-error; return NULL; }
    if (!fabric) {
        fabric=calloc(1,sizeof(*fabric));
        if (!fabric) { free(n); return NULL; }
        error=pthread_mutex_init(&fabric->lock,NULL);
        if (error) { free(n); free(fabric); errno=error; return NULL; }
        atomic_init(&fabric->references,1); fabric->next_index=2;
        fabric->routed=mode==MD_NETWORK_ROUTED;
    } else atomic_fetch_add_explicit(&fabric->references,1,memory_order_relaxed);
    n->fabric=fabric; n->mode=mode; n->owner=md_user_namespace_retain(owner);
    atomic_init(&n->references,1);
    n->unprivileged_port=1024; n->ping_groups[0]=1;
    n->local_ports[0]=32768; n->local_ports[1]=60999;
    pthread_mutex_lock(&fabric->lock);
    unsigned loopback=0;
    error=md_network_interface_add(n,MD_LINK_LOOPBACK,"lo",&loopback);
    if (!error && mode==MD_NETWORK_ROUTED) {
        n->links[0].info.flags|=IFF_UP;
        n->links[0].ipv4=htonl(INADDR_LOOPBACK); n->links[0].prefix=8;
        unsigned uplink=0;
        error=md_network_interface_add(n,MD_LINK_UPLINK,"eth0",&uplink);
        if (!error) {
            struct md_network_interface *link=md_network_interface_find(n,uplink,NULL);
            link->info.flags|=IFF_UP; link->ipv4=htonl(0x0a000264); link->prefix=24;
            n->default_interface=uplink; n->default_gateway=htonl(0x0a000202);
        }
    }
    n->next=fabric->spaces; fabric->spaces=n;
    pthread_mutex_unlock(&fabric->lock);
    if (error) { md_network_namespace_release(n); errno=-error; return NULL; }
    return n;
}
struct md_network_namespace *md_network_namespace_new(struct md_user_namespace *owner,enum md_network_mode mode) {
    if (mode<MD_NETWORK_NATIVE || mode>MD_NETWORK_ROUTED) { errno=EINVAL; return NULL; }
    return create(owner,mode,NULL);
}
struct md_network_namespace *md_network_namespace_copy(struct md_network_namespace *from,struct md_user_namespace *owner) {
    if (!from) { errno=EINVAL; return NULL; }
    return create(owner,MD_NETWORK_PRIVATE,from->fabric);
}
struct md_network_namespace *md_network_namespace_retain(struct md_network_namespace *n) {
    if (n) atomic_fetch_add_explicit(&n->references,1,memory_order_relaxed);
    return n;
}
void md_network_namespace_release(struct md_network_namespace *n) {
    if (!n || atomic_fetch_sub_explicit(&n->references,1,memory_order_acq_rel)!=1) return;
    struct md_network_fabric *f=n->fabric;
    pthread_mutex_lock(&f->lock);
    for (unsigned i=0;i<n->count;++i) {
        struct md_network_namespace *peer=md_network_interface_owner(f,n->links[i].peer);
        if (peer && peer!=n) remove_one(peer,n->links[i].peer);
    }
    struct md_network_namespace **at=&f->spaces;
    while (*at && *at!=n) at=&(*at)->next;
    if (*at) *at=n->next;
    pthread_mutex_unlock(&f->lock);
    if (atomic_fetch_sub_explicit(&f->references,1,memory_order_acq_rel)==1) {
        pthread_mutex_destroy(&f->lock); free(f);
    }
    md_user_namespace_release(n->owner); free(n->links); free(n);
}
uint64_t md_network_namespace_inode(const struct md_network_namespace *n) { return n->inode; }
const struct md_user_namespace *md_network_namespace_owner(const struct md_network_namespace *n) { return n->owner; }
int md_network_namespace_managed(const struct md_network_namespace *n) { return n && n->mode!=MD_NETWORK_NATIVE; }
int md_network_link_info(const struct md_network_namespace *n,unsigned index,struct md_network_link *out) {
    if (!md_network_namespace_managed(n)) return -EOPNOTSUPP;
    pthread_mutex_lock(&n->fabric->lock);
    struct md_network_interface *link=md_network_interface_find((struct md_network_namespace *)n,index,NULL);
    if (link) {
        *out=link->info;
        out->state=(out->flags&IFF_UP) ? IF_OPER_UNKNOWN : IF_OPER_DOWN;
    }
    pthread_mutex_unlock(&n->fabric->lock);
    return link ? 0 : -ENODEV;
}

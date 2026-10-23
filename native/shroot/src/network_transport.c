#include "network_transport.h"
#include <errno.h>

static unsigned lower(unsigned a,unsigned b) { return !a ? b : !b || a<b ? a : b; }
static int set(int fd,int level,int option,int value,int *applied) {
    if (value==*applied) return 0;
    if (setsockopt(fd,level,option,&value,sizeof(value))) return -errno;
    *applied=value; return 0;
}
int md_network_transport_apply(struct md_network_transport *s,int fd,int type,struct md_network_transport_policy route) {
    unsigned mtu=lower(route.mtu,(unsigned)s->user_mtu);
    int hops=s->user_hops>=0 ? s->user_hops : route.hops ? (int)route.hops : -1;
    int error=set(fd,IPPROTO_IPV6,IPV6_UNICAST_HOPS,hops,&s->applied_hops);
    if (!error) error=set(fd,IPPROTO_IPV6,IPV6_MTU,(int)mtu,&s->applied_mtu);
    if (!error && type==SOCK_STREAM) {
        /* Linux's TCP_MAXSEG excludes the IPv6 and minimum TCP headers. Large
         * MTUs need no user MSS clamp; the native route remains authoritative. */
        unsigned mss=mtu && mtu-60<=32767 ? mtu-60 : 0;
        error=set(fd,IPPROTO_TCP,TCP_MAXSEG,(int)lower(mss,(unsigned)s->user_mss),&s->applied_mss);
    }
    if (!error) s->route=route;
    return error;
}
int md_network_transport_set(struct md_network_transport *s,int fd,int type,unsigned level,unsigned option,int value) {
    struct md_network_transport next=*s;
    if (level==IPPROTO_IPV6 && option==IPV6_MTU) {
        if (value && value<1280) return -EINVAL;
        next.user_mtu=value;
    } else if (level==IPPROTO_IPV6 && option==IPV6_UNICAST_HOPS) {
        if (value < -1 || value>255) return -EINVAL;
        next.user_hops=value;
    } else if (level==IPPROTO_TCP && option==TCP_MAXSEG && type==SOCK_STREAM) {
        if (value && (value<88 || value>32767)) return -EINVAL;
        next.user_mss=value;
    } else return -ENOPROTOOPT;
    int error=md_network_transport_apply(&next,fd,type,next.route);
    if (!error) *s=next;
    return error;
}

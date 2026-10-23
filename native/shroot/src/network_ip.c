#define _GNU_SOURCE
#include "network_ip.h"
#include <errno.h>
#include <unistd.h>

int md_inet_decode(const struct sockaddr *address,socklen_t length,struct md_inet_address *out) {
    if (length<sizeof(sa_family_t)) return -EINVAL;
    *out=(struct md_inet_address){.ip=md_ip_any(address->sa_family)};
    if (address->sa_family==AF_INET) {
        if (length<sizeof(struct sockaddr_in)) return -EINVAL;
        struct sockaddr_in a; memcpy(&a,address,sizeof(a));
        out->ip.v4=a.sin_addr.s_addr; out->port=a.sin_port;
    } else if (address->sa_family==AF_INET6) {
        if (length<sizeof(struct sockaddr_in6)) return -EINVAL;
        struct sockaddr_in6 a; memcpy(&a,address,sizeof(a));
        out->ip.v6=a.sin6_addr; out->port=a.sin6_port; out->scope=a.sin6_scope_id;
        if (IN6_IS_ADDR_V4MAPPED(&a.sin6_addr)) {
            out->ip=md_ip_load(AF_INET,a.sin6_addr.s6_addr+12); out->scope=0;
        }
    } else return -EAFNOSUPPORT;
    return 0;
}
int md_inet_encode(const struct md_inet_address *a,unsigned family,struct sockaddr_storage *out,socklen_t *length) {
    memset(out,0,sizeof(*out));
    if (!family) family=a->ip.family;
    if (family==AF_INET) {
        if (a->ip.family!=AF_INET) return -EAFNOSUPPORT;
        struct sockaddr_in native={.sin_family=AF_INET,.sin_port=a->port,.sin_addr.s_addr=a->ip.v4};
        memcpy(out,&native,sizeof(native)); *length=sizeof(native);
    } else if (family==AF_INET6) {
        struct sockaddr_in6 native={.sin6_family=AF_INET6,.sin6_port=a->port,.sin6_scope_id=a->scope};
        if (a->ip.family==AF_INET6) native.sin6_addr=a->ip.v6;
        else if (a->ip.family==AF_INET) {
            native.sin6_addr.s6_addr[10]=native.sin6_addr.s6_addr[11]=0xff;
            memcpy(native.sin6_addr.s6_addr+12,&a->ip.v4,4);
        } else return -EAFNOSUPPORT;
        memcpy(out,&native,sizeof(native)); *length=sizeof(native);
    } else return -EAFNOSUPPORT;
    return 0;
}
int md_inet_bind(int fd,const struct md_inet_address *a,unsigned family) {
    struct sockaddr_storage native; socklen_t size;
    int error=md_inet_encode(a,family,&native,&size);
    if (error) { errno=-error; return -1; }
    return bind(fd,(void *)&native,size);
}
int md_inet_connect(int fd,const struct md_inet_address *a,unsigned family) {
    struct sockaddr_storage native; socklen_t size;
    int error=md_inet_encode(a,family,&native,&size);
    if (error) { errno=-error; return -1; }
    return connect(fd,(void *)&native,size);
}
int md_inet_name(int fd,int peer,struct md_inet_address *out) {
    struct sockaddr_storage native; socklen_t size=sizeof(native);
    if (peer ? getpeername(fd,(void *)&native,&size) : getsockname(fd,(void *)&native,&size)) return -1;
    int error=md_inet_decode((void *)&native,size,out);
    if (error) { errno=-error; return -1; }
    return 0;
}
int md_inet_accept(int fd,struct md_inet_address *out,int flags) {
    struct sockaddr_storage native; socklen_t size=sizeof(native);
    int accepted=accept4(fd,(void *)&native,&size,flags);
    if (accepted<0) return -1;
    int error=md_inet_decode((void *)&native,size,out);
    if (error) { close(accepted); errno=-error; return -1; }
    return accepted;
}
ssize_t md_inet_sendto(int fd,const void *data,size_t size,int flags,const struct md_inet_address *a,unsigned family) {
    struct sockaddr_storage native; socklen_t length;
    int error=md_inet_encode(a,family,&native,&length);
    if (error) { errno=-error; return -1; }
    return sendto(fd,data,size,flags,(void *)&native,length);
}
ssize_t md_inet_recvfrom(int fd,void *data,size_t size,int flags,struct md_inet_address *out) {
    struct sockaddr_storage native; socklen_t length=sizeof(native);
    ssize_t received=recvfrom(fd,data,size,flags,(void *)&native,&length);
    if (received<0) return -1;
    int error=md_inet_decode((void *)&native,length,out);
    if (error) { errno=-error; return -1; }
    return received;
}

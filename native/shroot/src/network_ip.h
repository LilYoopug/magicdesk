#ifndef MD_NETWORK_IP_H
#define MD_NETWORK_IP_H
#include <netinet/in.h>
#include <string.h>

/* Logical addresses never contain Android interface indices. IPv4-mapped
 * socket addresses normalize to IPv4 here; the socket owns its ABI family. */
struct md_ip_address {
    unsigned family;
    union { uint32_t v4, words[4]; struct in6_addr v6; unsigned char bytes[16]; };
};
struct md_inet_address {
    struct md_ip_address ip;
    uint32_t scope;
    uint16_t port;
};
static inline struct md_ip_address md_ip_any(unsigned family) {
    return (struct md_ip_address){.family=family};
}
static inline struct md_ip_address md_ip_v4(uint32_t address) {
    return (struct md_ip_address){.family=AF_INET,.v4=address};
}
static inline struct in6_addr md_ip_in6(struct md_ip_address a) {
    if (a.family==AF_INET6) return a.v6;
    struct in6_addr out={0};
    out.s6_addr[10]=out.s6_addr[11]=0xff; memcpy(out.s6_addr+12,&a.v4,4); return out;
}
static inline unsigned md_ip_size(struct md_ip_address a) { return a.family==AF_INET6 ? 16 : 4; }
static inline struct md_ip_address md_ip_load(unsigned family,const void *bytes) {
    struct md_ip_address a=md_ip_any(family);
    memcpy(a.bytes,bytes,md_ip_size(a)); return a;
}
static inline int md_ip_equal(struct md_ip_address a,struct md_ip_address b) {
    return a.family==b.family && (a.family==AF_INET ? a.v4==b.v4
        : !((a.words[0]^b.words[0])|(a.words[1]^b.words[1])|(a.words[2]^b.words[2])|(a.words[3]^b.words[3])));
}
static inline int md_ip_unspecified(struct md_ip_address a) {
    return a.family==AF_INET ? !a.v4 : IN6_IS_ADDR_UNSPECIFIED(&a.v6);
}
static inline int md_ip_is_loopback(struct md_ip_address a) {
    return a.family==AF_INET ? (ntohl(a.v4)>>24)==127 : IN6_IS_ADDR_LOOPBACK(&a.v6);
}
static inline int md_ip_multicast(struct md_ip_address a) {
    return a.family==AF_INET ? (ntohl(a.v4)>>28)==14 : IN6_IS_ADDR_MULTICAST(&a.v6);
}
static inline int md_ip_linklocal(struct md_ip_address a) {
    return a.family==AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&a.v6);
}
static inline struct md_ip_address md_ip_loopback(unsigned family) {
    struct md_ip_address a=md_ip_any(family);
    if (family==AF_INET) a.v4=htonl(INADDR_LOOPBACK); else a.bytes[15]=1;
    return a;
}
static inline struct md_ip_address md_ip_network(struct md_ip_address a,unsigned prefix) {
    unsigned size=md_ip_size(a);
    if (prefix>size*8) return md_ip_any(a.family);
    unsigned bytes=prefix/8,bits=prefix%8;
    if (bits) a.bytes[bytes++]&=(unsigned char)(0xffU<<(8-bits));
    memset(a.bytes+bytes,0,size-bytes); return a;
}
static inline int md_ip_prefix(struct md_ip_address a,struct md_ip_address b,unsigned prefix) {
    return prefix<=md_ip_size(a)*8 && md_ip_equal(md_ip_network(a,prefix),md_ip_network(b,prefix));
}
static inline int md_inet_equal(const struct md_inet_address *a,const struct md_inet_address *b) {
    return a->port==b->port && md_ip_equal(a->ip,b->ip)
        && (!md_ip_linklocal(a->ip) || a->scope==b->scope);
}
int md_inet_decode(const struct sockaddr *,socklen_t,struct md_inet_address *);
int md_inet_encode(const struct md_inet_address *,unsigned,struct sockaddr_storage *,socklen_t *);
/* Native wrappers retain socket errno conventions and convert only at the ABI
 * boundary. The data-plane owner still performs readiness and queue handling. */
int md_inet_bind(int,const struct md_inet_address *,unsigned);
int md_inet_connect(int,const struct md_inet_address *,unsigned);
int md_inet_name(int,int,struct md_inet_address *);
int md_inet_accept(int,struct md_inet_address *,int);
ssize_t md_inet_sendto(int,const void *,size_t,int,const struct md_inet_address *,unsigned);
ssize_t md_inet_recvfrom(int,void *,size_t,int,struct md_inet_address *);
#endif

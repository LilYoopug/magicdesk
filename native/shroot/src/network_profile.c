#include "network_profile.h"
#include <errno.h>
#include <stddef.h>

static int equal(const char *a,const char *b) {
    while (*a && *a==*b) { ++a; ++b; }
    return *a==*b;
}
static int decimal(const char **at,unsigned limit,unsigned *out) {
    const char *p=*at;
    if (*p<'0' || *p>'9') return -EINVAL;
    unsigned value=0;
    do {
        unsigned digit=(unsigned)(*p++-'0');
        if (value>(limit-digit)/10) return -EINVAL;
        value=value*10+digit;
    } while (*p>='0' && *p<='9');
    *at=p; *out=value; return 0;
}
static int address(const char **at,uint32_t *out) {
    unsigned char *bytes=(void *)out;
    for (unsigned i=0;i<4;++i) {
        unsigned value=0;
        int error=decimal(at,255,&value);
        if (error) return error;
        bytes[i]=(unsigned char)value;
        if (i<3 && *(*at)++!='.') return -EINVAL;
    }
    return 0;
}
int md_network_profile_ipv4(const char *text,uint32_t *out) {
    int error=address(&text,out);
    return error ? error : *text ? -EINVAL : 0;
}
int md_network_profile_ip(const char *text,struct md_ip_address *out) {
    int v6=0;
    for (const char *p=text;*p;++p) if (*p==':') v6=1;
    *out=md_ip_any(v6 ? AF_INET6 : AF_INET);
    if (!v6) return md_network_profile_ipv4(text,&out->v4);
    unsigned char bytes[16]={0}; unsigned used=0; int gap=-1;
    const char *p=text;
    if (*p==':') { if (*++p!=':') return -EINVAL; gap=0; ++p; }
    while (*p) {
        const char *start=p; unsigned value=0,digits=0;
        while ((*p>='0' && *p<='9') || (*p>='a' && *p<='f') || (*p>='A' && *p<='F')) {
            unsigned digit=*p<='9' ? *p-'0' : (*p|32)-'a'+10;
            if (++digits>4) return -EINVAL;
            value=(value<<4)|digit; ++p;
        }
        if (*p=='.') {
            uint32_t tail=0;
            if (used>12 || md_network_profile_ipv4(start,&tail)) return -EINVAL;
            const unsigned char *v=(const void *)&tail;
            for (unsigned i=0;i<4;++i) bytes[used++]=v[i];
            while (*p) ++p;
            break;
        }
        if (!digits || used>14) return -EINVAL;
        bytes[used++]=(unsigned char)(value>>8); bytes[used++]=(unsigned char)value;
        if (!*p) break;
        if (*p++!=':') return -EINVAL;
        if (*p==':') { if (gap>=0) return -EINVAL; gap=(int)used; ++p; }
        else if (!*p) return -EINVAL;
    }
    if (gap<0 && used!=16) return -EINVAL;
    if (gap>=0) {
        if (used==16) return -EINVAL;
        unsigned tail=used-(unsigned)gap;
        for (unsigned i=0;i<tail;++i) bytes[15-i]=bytes[used-1-i];
        for (unsigned i=(unsigned)gap;i<16-tail;++i) bytes[i]=0;
    }
    for (unsigned i=0;i<16;++i) out->bytes[i]=bytes[i];
    return 0;
}
int md_network_profile_option(const char *option) {
    return equal(option,"--network") || equal(option,"--publish") || equal(option,"-p") || equal(option,"--dns")
        || equal(option,"--subnet") || equal(option,"--ip") || equal(option,"--ip6") || equal(option,"--gateway");
}
static int subnet(const char *text,struct md_ip_address *ip,unsigned *prefix) {
    char literal[46]; unsigned size=0;
    while (*text && *text!='/' && size<sizeof(literal)-1) literal[size++]=*text++;
    literal[size]=0;
    if (*text++!='/') return -EINVAL;
    int error=md_network_profile_ip(literal,ip);
    if (!error) error=decimal(&text,ip->family==AF_INET ? 32 : 128,prefix);
    if (error || *text) return error ? error : -EINVAL;
    return md_ip_equal(*ip,md_ip_network(*ip,*prefix)) ? 0 : -EINVAL;
}
static int unicast(struct md_ip_address ip) {
    return !md_ip_unspecified(ip) && !md_ip_is_loopback(ip) && !md_ip_multicast(ip)
        && !md_ip_linklocal(ip) && (ip.family==AF_INET ? ip.bytes[0] && ip.bytes[0]<224
            : !IN6_IS_ADDR_V4MAPPED(&ip.v6));
}
static struct md_ip_address next_address(struct md_ip_address ip) {
    for (unsigned i=md_ip_size(ip);i && !++ip.bytes[i-1];--i) {}
    return ip;
}
static int usable(struct md_network_family_config *c,struct md_ip_address ip) {
    if (!unicast(ip) || !md_ip_prefix(ip,c->subnet,c->prefix)) return 0;
    unsigned bits=8*md_ip_size(ip);
    if (c->prefix==bits-1) return 1;
    if (md_ip_equal(ip,c->subnet)) return 0;
    return ip.family!=AF_INET || !md_ip_equal(md_ip_network(next_address(ip),c->prefix),next_address(ip));
}
int md_network_profile_family(const struct md_network_profile *p,unsigned family,struct md_network_family_config *c) {
    if (family!=AF_INET && family!=AF_INET6) return -EAFNOSUPPORT;
    unsigned index=family==AF_INET6;
    const struct md_network_family_options *o=&p->families[index];
    *c=(struct md_network_family_config){0};
    int error=subnet(o->subnet ? o->subnet : index ? "fd6d:6473:1::/64" : "10.88.0.0/24",&c->subnet,&c->prefix);
    unsigned bits=index ? 128 : 32;
    if (error || c->subnet.family!=family || c->prefix>=bits) return -EINVAL;
    /* The launch gateway already owns this uplink; overlapping connected
     * routes would make the private bridge ambiguous. */
    struct md_ip_address uplink; unsigned uplink_prefix;
    subnet(index ? "fd6d:6473::/64" : "10.0.2.0/24",&uplink,&uplink_prefix);
    if (md_ip_prefix(c->subnet,uplink,c->prefix<uplink_prefix ? c->prefix : uplink_prefix)) return -EADDRINUSE;
    struct md_ip_address first=c->prefix==bits-1 ? c->subnet : next_address(c->subnet);
    c->address=md_ip_any(family); c->gateway=first;
    if (o->address) error=md_network_profile_ip(o->address,&c->address);
    if (!error && o->gateway) error=md_network_profile_ip(o->gateway,&c->gateway);
    if (!o->gateway && md_ip_equal(c->gateway,c->address)) c->gateway=next_address(c->gateway);
    if (!o->address) c->address=md_ip_equal(first,c->gateway) ? next_address(first) : first;
    if (error || c->address.family!=family || c->gateway.family!=family) return -EINVAL;
    if (!usable(c,c->address) || !usable(c,c->gateway) || md_ip_equal(c->address,c->gateway)) return -EADDRNOTAVAIL;
    return 0;
}
static int addressing(struct md_network_profile *p,const char *option,const char *value) {
    struct md_ip_address ip; unsigned prefix;
    int is_subnet=equal(option,"--subnet");
    int error=is_subnet ? subnet(value,&ip,&prefix) : md_network_profile_ip(value,&ip);
    if (error) return error;
    if ((equal(option,"--ip") && ip.family!=AF_INET) || (equal(option,"--ip6") && ip.family!=AF_INET6)) return -EAFNOSUPPORT;
    struct md_network_family_options *o=&p->families[ip.family==AF_INET6];
    const char **slot=is_subnet ? &o->subnet : equal(option,"--gateway") ? &o->gateway : &o->address;
    if (*slot) return -EEXIST;
    *slot=value; return 0;
}
static int publication(const char *text,struct md_network_public_port *port) {
    const char *p=text;
    *port=(struct md_network_public_port){.address={.family=AF_INET},.protocol=6,.argument=text};
    int error=0;
    if (*p=='[') {
        char ip[46]; unsigned size=0; ++p;
        while (*p && *p!=']' && size<sizeof(ip)-1) ip[size++]=*p++;
        ip[size]=0;
        if (*p++!=']' || *p++!=':') return -EINVAL;
        error=md_network_profile_ip(ip,&port->address);
        if (error || port->address.family!=AF_INET6) return -EINVAL;
    } else {
        unsigned separators=0;
        for (const char *c=text;*c;++c) if (*c==':') ++separators;
        if (separators>2) return -EAFNOSUPPORT;
        if (separators<1) return -EINVAL;
        if (separators==2) {
            error=address(&p,&port->address.v4);
            if (error || *p++!=':') return -EINVAL;
        }
    }
    if (md_ip_multicast(port->address) || md_ip_linklocal(port->address)
            || (port->address.family==AF_INET && (port->address.bytes[0]>=224
                || (!port->address.bytes[0] && port->address.v4)))) return -EADDRNOTAVAIL;
    unsigned host=0,guest=0;
    error=decimal(&p,65535,&host);
    if (error || !host || *p++!=':') return -EINVAL;
    error=decimal(&p,65535,&guest);
    if (error || !guest) return -EINVAL;
    if (*p) {
        if (equal(p,"/udp")) port->protocol=17;
        else if (!equal(p,"/tcp")) return -EPROTONOSUPPORT;
    }
    unsigned char *bytes=(void *)&port->host;
    bytes[0]=(unsigned char)(host>>8); bytes[1]=(unsigned char)host;
    bytes=(void *)&port->guest;
    bytes[0]=(unsigned char)(guest>>8); bytes[1]=(unsigned char)guest;
    return 0;
}
int md_network_profile_add(struct md_network_profile *p,const char *option,const char *value) {
    if (!value || !*value) return -EINVAL;
    if (equal(option,"--network")) {
        if (p->selected) return -EEXIST;
        enum md_network_policy policy;
        if (equal(value,"host")) policy=MD_NETWORK_HOST;
        else if (equal(value,"none")) policy=MD_NETWORK_NONE;
        else if (equal(value,"bridge")) policy=MD_NETWORK_BRIDGE;
        else if (equal(value,"routed")) policy=MD_NETWORK_BACKEND_ROUTED;
        else return -EINVAL;
        p->policy=policy; p->selected=1; return 0;
    }
    if (equal(option,"--dns")) {
        struct md_ip_address ip;
        int error=md_network_profile_ip(value,&ip);
        if (error) return error;
        if (md_ip_unspecified(ip) || md_ip_is_loopback(ip) || md_ip_multicast(ip) || md_ip_linklocal(ip)
                || (ip.family==AF_INET && (!ip.bytes[0] || ip.bytes[0]>=224))) return -EADDRNOTAVAIL;
        if (p->dns_count==MD_NETWORK_DNS_MAX) return -E2BIG;
        for (unsigned i=0;i<p->dns_count;++i) {
            struct md_ip_address prior; md_network_profile_ip(p->dns[i],&prior);
            if (md_ip_equal(ip,prior)) return -EEXIST;
        }
        p->dns[p->dns_count++]=value; return 0;
    }
    if (equal(option,"--subnet") || equal(option,"--gateway") || equal(option,"--ip") || equal(option,"--ip6"))
        return addressing(p,option,value);
    if (!equal(option,"-p") && !equal(option,"--publish")) return -EINVAL;
    struct md_network_public_port port;
    int error=publication(value,&port);
    if (error) return error;
    if (p->count==MD_NETWORK_PUBLICATIONS_MAX) return -E2BIG;
    for (unsigned i=0;i<p->count;++i) {
        const struct md_network_public_port *prior=&p->ports[i];
        if (prior->host==port.host && prior->protocol==port.protocol
                && prior->address.family==port.address.family
                && (md_ip_unspecified(prior->address) || md_ip_unspecified(port.address)
                    || md_ip_equal(prior->address,port.address))) return -EADDRINUSE;
    }
    p->ports[p->count++]=port; return 0;
}
int md_network_profile_validate(const struct md_network_profile *p) {
    if (!p || (unsigned)p->policy>MD_NETWORK_BACKEND_ROUTED || p->count>MD_NETWORK_PUBLICATIONS_MAX
            || p->dns_count>MD_NETWORK_DNS_MAX) return -EINVAL;
    if (p->count && p->policy!=MD_NETWORK_BRIDGE) return -EINVAL;
    if (p->dns_count && p->policy==MD_NETWORK_NONE) return -EINVAL;
    for (unsigned i=0;i<2;++i) {
        const struct md_network_family_options *o=&p->families[i];
        if ((o->subnet || o->address || o->gateway) && p->policy!=MD_NETWORK_BRIDGE) return -EINVAL;
        if (p->policy==MD_NETWORK_BRIDGE) {
            struct md_network_family_config c;
            int error=md_network_profile_family(p,i ? AF_INET6 : AF_INET,&c);
            if (error) return error;
        }
    }
    return 0;
}
unsigned md_network_profile_arguments(const struct md_network_profile *p,char **out) {
    unsigned count=2*(p->selected+p->count+p->dns_count);
    for (unsigned i=0;i<2;++i) count+=2*(!!p->families[i].subnet+!!p->families[i].address+!!p->families[i].gateway);
    if (!out) return count;
    unsigned n=0;
    if (p->selected) {
        const char *names[]={"host","none","bridge","routed"};
        out[n++]="--network"; out[n++]=(char *)names[p->policy];
    }
    for (unsigned i=0;i<p->count;++i) { out[n++]="-p"; out[n++]=(char *)p->ports[i].argument; }
    for (unsigned i=0;i<p->dns_count;++i) { out[n++]="--dns"; out[n++]=(char *)p->dns[i]; }
    for (unsigned i=0;i<2;++i) {
        const struct md_network_family_options *o=&p->families[i];
        if (o->subnet) { out[n++]="--subnet"; out[n++]=(char *)o->subnet; }
        if (o->address) { out[n++]=i ? "--ip6" : "--ip"; out[n++]=(char *)o->address; }
        if (o->gateway) { out[n++]="--gateway"; out[n++]=(char *)o->gateway; }
    }
    return n;
}

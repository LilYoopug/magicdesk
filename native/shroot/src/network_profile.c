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
int md_network_profile_option(const char *option) {
    return equal(option,"--network") || equal(option,"--publish") || equal(option,"-p") || equal(option,"--dns");
}
static int publication(const char *text,struct md_network_public_port *port) {
    const char *p=text;
    unsigned separators=0;
    for (const char *c=text;*c;++c) if (*c==':') ++separators;
    if (separators>2 || *p=='[') return -EAFNOSUPPORT;
    if (separators<1) return -EINVAL;
    *port=(struct md_network_public_port){.protocol=6,.argument=text};
    int error=0;
    if (separators==2) {
        error=address(&p,&port->address);
        if (error || *p++!=':') return -EINVAL;
        unsigned first=((const unsigned char *)&port->address)[0];
        if (first>=224 || (!first && port->address)) return -EADDRNOTAVAIL;
    }
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
        uint32_t ip=0;
        int error=md_network_profile_ipv4(value,&ip);
        if (error) return error;
        unsigned first=((const unsigned char *)&ip)[0];
        if (!first || first==127 || first>=224) return -EADDRNOTAVAIL;
        if (p->dns_count==MD_NETWORK_DNS_MAX) return -E2BIG;
        for (unsigned i=0;i<p->dns_count;++i) {
            uint32_t prior=0; md_network_profile_ipv4(p->dns[i],&prior);
            if (ip==prior) return -EEXIST;
        }
        p->dns[p->dns_count++]=value; return 0;
    }
    if (!equal(option,"-p") && !equal(option,"--publish")) return -EINVAL;
    struct md_network_public_port port;
    int error=publication(value,&port);
    if (error) return error;
    if (p->count==MD_NETWORK_PUBLICATIONS_MAX) return -E2BIG;
    for (unsigned i=0;i<p->count;++i) {
        const struct md_network_public_port *prior=&p->ports[i];
        if (prior->host==port.host && prior->protocol==port.protocol
                && (!prior->address || !port.address || prior->address==port.address)) return -EADDRINUSE;
    }
    p->ports[p->count++]=port; return 0;
}
int md_network_profile_validate(const struct md_network_profile *p) {
    if (!p || (unsigned)p->policy>MD_NETWORK_BACKEND_ROUTED || p->count>MD_NETWORK_PUBLICATIONS_MAX
            || p->dns_count>MD_NETWORK_DNS_MAX) return -EINVAL;
    if (p->count && p->policy!=MD_NETWORK_BRIDGE) return -EINVAL;
    if (p->dns_count && p->policy==MD_NETWORK_NONE) return -EINVAL;
    return 0;
}
unsigned md_network_profile_arguments(const struct md_network_profile *p,char **out) {
    unsigned count=2*(p->selected+p->count+p->dns_count);
    if (!out) return count;
    unsigned n=0;
    if (p->selected) {
        const char *names[]={"host","none","bridge","routed"};
        out[n++]="--network"; out[n++]=(char *)names[p->policy];
    }
    for (unsigned i=0;i<p->count;++i) { out[n++]="-p"; out[n++]=(char *)p->ports[i].argument; }
    for (unsigned i=0;i<p->dns_count;++i) { out[n++]="--dns"; out[n++]=(char *)p->dns[i]; }
    return n;
}

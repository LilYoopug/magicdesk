#include "network_flow.h"
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>

struct md_network_namespace *md_network_space_find(struct md_network_fabric *f,uint64_t inode) {
    for (struct md_network_namespace *n=f->spaces;n;n=n->next) if (n->inode==inode) return n;
    return NULL;
}
struct md_network_interface *md_network_local_interface(struct md_network_namespace *n,uint32_t ip,int up) {
    for (unsigned i=0;i<n->count;++i) {
        struct md_network_interface *l=&n->links[i];
        if ((!up || (l->info.flags&IFF_UP)) && (l->ipv4==ip
                || (l->kind==MD_LINK_LOOPBACK && (ntohl(ip)>>24)==127))) return l;
    }
    return NULL;
}
static void interface(struct md_filter_packet *p,const struct md_network_interface *link,int input) {
    char *name=input ? p->input_name : p->output_name;
    memset(name,0,16);
    if (input) p->input=link ? link->info.index : 0;
    else { p->output=link ? link->info.index : 0; p->masquerade_address=link ? link->ipv4 : 0; }
    if (link) memcpy(name,link->info.name,strnlen(link->info.name,15));
}
static int can_deny(const struct md_network_filter *f,const struct md_filter_chain *c,unsigned depth) {
    if (c->hook>=0 && c->policy==NF_DROP) return 1;
    if (depth>16) return 1;
    for (size_t i=0;i<f->rule_count;++i) if (f->rules[i].chain==c->handle)
        for (unsigned j=0;j<f->rules[i].count;++j) {
            const struct md_filter_expression *e=&f->rules[i].expressions[j];
            if (e->code!=MD_FILTER_VERDICT) continue;
            if (e->operation==NF_DROP) return 1;
            if ((int)e->operation==NFT_JUMP || (int)e->operation==NFT_GOTO)
                for (size_t k=0;k<f->chain_count;++k)
                    if (f->chains[k].handle==e->target && can_deny(f,&f->chains[k],depth+1)) return 1;
        }
    return 0;
}
static unsigned reverse_hook(unsigned hook) {
    switch (hook) {
    case NF_INET_PRE_ROUTING: return NF_INET_POST_ROUTING;
    case NF_INET_POST_ROUTING: return NF_INET_PRE_ROUTING;
    case NF_INET_LOCAL_IN: return NF_INET_LOCAL_OUT;
    case NF_INET_LOCAL_OUT: return NF_INET_LOCAL_IN;
    default: return hook;
    }
}
static int hook(struct md_network_namespace *n,unsigned which,struct md_filter_packet *p,struct md_network_flow_path *path) {
    if (path->count==16) return -ELOOP;
    struct md_network_flow_step *step=&path->steps[path->count++];
    *step=(struct md_network_flow_step){.space=n->inode,.hook=which,.packet=*p};
    struct md_network_filter *f=n->filter;
    if (!f || !f->chain_count) return 0;
    /* Native connected IO bypasses both directions. A policy on replies also
     * requires mediation, even when every outbound hook accepts the request. */
    for (size_t i=0;i<f->chain_count;++i)
        if ((f->chains[i].hook==(int)which || f->chains[i].hook==(int)reverse_hook(which))
                && !f->chains[i].nat && can_deny(f,&f->chains[i],0)) path->mediated=1;
    int error=md_filter_evaluate(f,which,p);
    if (p->snat || p->dnat) path->mediated=1;
    return error;
}
static struct md_network_interface *bridge_peer(struct md_network_namespace *n,const struct md_network_interface *bridge,
        uint32_t destination,struct md_network_namespace **space) {
    for (struct md_network_namespace *s=n->fabric->spaces;s;s=s->next) {
        struct md_network_interface *in=md_network_local_interface(s,destination,1);
        if (!in || in->kind!=MD_LINK_VETH) continue;
        struct md_network_interface *peer=md_network_interface_find(n,in->peer,NULL);
        if (peer && peer->master==bridge->info.index && (peer->info.flags&IFF_UP)) { *space=s; return in; }
    }
    return NULL;
}
int md_network_flow_route(struct md_network_namespace *from,struct md_filter_packet *p,int external,
        struct md_network_flow_path *path) {
    *path=(struct md_network_flow_path){0};
    struct md_network_namespace *n=from;
    struct md_network_interface *out=md_network_route_find(n,p->destination,NULL);
    if (!external && !p->source) p->source=out ? out->ipv4 : 0;
    interface(p,out,0);
    p->fib_type=external || md_network_local_interface(n,p->destination,0) ? RTN_LOCAL : RTN_UNICAST;
    path->original=*p;
    int arrived=external;
    if (external) interface(p,md_network_interface_find(n,(ntohl(p->source)>>24)==127 ? 1 : n->default_interface,NULL),1);
    int error=hook(n,external ? NF_INET_PRE_ROUTING : NF_INET_LOCAL_OUT,p,path);
    while (!error) {
        struct md_network_interface *local=md_network_local_interface(n,p->destination,1);
        if (local || (external && n==from && !p->dnat)) {
            interface(p,NULL,0);
            if (!arrived) interface(p,local,1);
            error=hook(n,NF_INET_LOCAL_IN,p,path);
            path->destination=n->inode; break;
        }
        out=md_network_route_find(n,p->destination,NULL);
        if (!out || !(out->info.flags&IFF_UP)) { error=-ENETUNREACH; break; }
        interface(p,out,0);
        if (arrived) {
            if (!n->ipv4_forward) { error=-ENETUNREACH; break; }
            error=hook(n,NF_INET_FORWARD,p,path);
        }
        if (!error) error=hook(n,NF_INET_POST_ROUTING,p,path);
        if (error) break;
        if (out->kind==MD_LINK_UPLINK) {
            if (n->mode!=MD_NETWORK_ROUTED) error=-ENETUNREACH;
            else if ((ntohl(p->destination)>>28)==14 || p->destination==INADDR_BROADCAST) error=-EOPNOTSUPP;
            break;
        }
        struct md_network_namespace *next=NULL;
        struct md_network_interface *input=NULL;
        if (out->kind==MD_LINK_VETH) {
            next=md_network_interface_owner(n->fabric,out->peer);
            input=next ? md_network_interface_find(next,out->peer,NULL) : NULL;
            if (input && input->master) input=md_network_interface_find(next,input->master,NULL);
        } else if (out->kind==MD_LINK_BRIDGE) input=bridge_peer(n,out,p->destination,&next);
        if (!next || !input || !(input->info.flags&IFF_UP)) { error=-ENETUNREACH; break; }
        error=md_network_ingress(next,input,p->source,p->destination);
        if (error) break;
        n=next; arrived=1; external=0;
        interface(p,input,1); interface(p,md_network_route_find(n,p->destination,NULL),0);
        p->fib_type=md_network_local_interface(n,p->destination,0) ? RTN_LOCAL : RTN_UNICAST;
        error=hook(n,NF_INET_PRE_ROUTING,p,path);
    }
    path->translated=*p; return error;
}
static int check_path(struct md_network_fabric *f,struct md_network_flow_path *path,int reverse,
        struct md_network_namespace *override,struct md_network_filter *filter) {
    unsigned mark=0;
    for (unsigned k=0;k<path->count;++k) {
        unsigned i=reverse ? path->count-k-1 : k;
        struct md_network_flow_step *s=&path->steps[i];
        struct md_network_namespace *n=md_network_space_find(f,s->space);
        if (!n) { if (override) continue; return -ENETUNREACH; }
        struct md_filter_packet p=s->packet;
        p.state=2; p.ctmark=path->translated.ctmark; p.status=path->translated.status; p.mark=mark;
        struct md_network_interface *input=md_network_interface_find(n,p.input,NULL);
        struct md_network_interface *output=md_network_interface_find(n,p.output,NULL);
        if (!override && ((p.input && (!input || !(input->info.flags&IFF_UP)))
                || (p.output && (!output || !(output->info.flags&IFF_UP))))) return -ENETUNREACH;
        interface(&p,input,1); interface(&p,output,0);
        unsigned hook=s->hook;
        if (reverse) {
            uint32_t address=p.source; p.source=p.destination; p.destination=address;
            uint16_t port=p.source_port; p.source_port=p.destination_port; p.destination_port=port;
            interface(&p,md_network_interface_find(n,s->packet.output,NULL),1);
            interface(&p,md_network_interface_find(n,s->packet.input,NULL),0);
            hook=reverse_hook(hook);
        }
        if (!override && hook==NF_INET_FORWARD && !n->ipv4_forward) return -ENETUNREACH;
        int error=md_filter_evaluate(n==override ? filter : n->filter,hook,&p);
        if (error) return error;
        path->translated.ctmark=p.ctmark;
        mark=p.mark;
    }
    return 0;
}
int md_network_flow_check(struct md_network_fabric *f,struct md_network_flow_path *path,int reverse) {
    return check_path(f,path,reverse,NULL,NULL);
}
int md_network_flow_admits(struct md_network_namespace *n,struct md_network_filter *filter,const struct md_network_flow_path *path) {
    int affected=0;
    for (unsigned i=0;i<path->count;++i) affected|=path->steps[i].space==n->inode;
    if (!affected) return 0;
    struct md_network_flow_path copy=*path;
    int error=check_path(n->fabric,&copy,0,n,filter);
    if (!error) error=check_path(n->fabric,&copy,1,n,filter);
    return error;
}

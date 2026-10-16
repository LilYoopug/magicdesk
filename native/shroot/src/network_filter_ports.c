#include "network_filter.h"
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <string.h>

static int unique(uint32_t *values,size_t *count,size_t limit,uint32_t value) {
    for (size_t i=0;i<*count;++i) if (values[i]==value) return 0;
    if (*count==limit) return -ENOSPC;
    values[(*count)++]=value; return 0;
}
enum { ADDRESS=1, PORT=2 };
static int all(const unsigned char *bytes,unsigned size,unsigned value) {
    for (unsigned i=0;i<size;++i) if (bytes[i]!=value) return 0;
    return 1;
}
/* Publication reserves a finite superset of possible external destinations.
 * Unknown source/interface/mark predicates must not be sampled with a dummy
 * packet: that would omit valid source-restricted forwards. Actual admission
 * always runs the full evaluator with the real connection coordinates. */
static int may_translate(struct md_network_filter *f,const struct md_filter_chain *chain,
        uint32_t address,uint16_t port,unsigned protocol,int unknown_port,unsigned *budget,unsigned depth) {
    if (depth>16) return -ELOOP;
    for (size_t i=0;i<f->rule_count;++i) {
        const struct md_filter_rule *r=&f->rules[i];
        if (r->chain!=chain->handle) continue;
        unsigned char values[64]={0},known[64]={0},tags[64]={0};
        int possible=1,uncertain=0;
        for (unsigned j=0;j<r->count && possible;++j) {
            if (!*budget) return -E2BIG;
            --*budget;
            const struct md_filter_expression *e=&r->expressions[j];
            unsigned char *value=values+e->dst,*k=known+e->dst,*tag=tags+e->dst;
            unsigned size=e->size;
            uint32_t number=0;
            if (e->code==MD_FILTER_IMMEDIATE || e->code==MD_FILTER_META || e->code==MD_FILTER_CT
                    || e->code==MD_FILTER_PAYLOAD || e->code==MD_FILTER_FIB) {
                unsigned padded=(size+3)&~3U;
                memset(value,0,padded); memset(k,0,padded); memset(tag,0,padded);
                memset(k+size,1,padded-size);
            }
            switch (e->code) {
            case MD_FILTER_TRANSPORT: {
                const struct md_filter_transport *t=&e->transport;
                int unrestricted=t->destination[0]==0 && t->destination[1]==UINT16_MAX;
                possible=protocol==t->protocol && (unknown_port ? unrestricted!=!!(t->inversion&MD_FILTER_INVERT_DESTINATION)
                    : md_filter_port_matches(ntohs(port),t->destination,t->inversion&MD_FILTER_INVERT_DESTINATION));
                uncertain=1; break;
            }
            case MD_FILTER_IMMEDIATE: memcpy(value,e->value,size); memset(k,1,size); break;
            case MD_FILTER_META:
                if (e->key==NFT_META_NFPROTO || e->key==NFT_META_L4PROTO) {
                    number=e->key==NFT_META_NFPROTO ? NFPROTO_IPV4 : protocol;
                    memcpy(value,&number,4); memset(k,1,4);
                }
                break;
            case MD_FILTER_CT:
                if (e->key==NFT_CT_STATE) { number=8; memcpy(value,&number,4); memset(k,1,4); }
                break;
            case MD_FILTER_FIB:
                if (e->operation!=NFTA_FIB_F_SADDR) { number=RTN_LOCAL; memcpy(value,&number,4); memset(k,1,4); }
                break;
            case MD_FILTER_PAYLOAD:
                for (unsigned b=0;b<size;++b) {
                    unsigned offset=e->aux+b;
                    if (e->key==NFT_PAYLOAD_NETWORK_HEADER && offset==9) { value[b]=protocol; k[b]=1; }
                    else if (e->key==NFT_PAYLOAD_NETWORK_HEADER && offset>=16 && offset<20) {
                        if (address) { value[b]=((unsigned char *)&address)[offset-16]; k[b]=1; }
                        else tag[b]=ADDRESS;
                    } else if (e->key==NFT_PAYLOAD_TRANSPORT_HEADER && offset>=2 && offset<4) {
                        if (!unknown_port) { value[b]=((unsigned char *)&port)[offset-2]; k[b]=1; }
                        else tag[b]=PORT;
                    }
                }
                break;
            case MD_FILTER_BITWISE: {
                unsigned char result[16],valid[16];
                for (unsigned b=0;b<size;++b) {
                    result[b]=(values[e->src+b]&e->mask[b])^e->value[b];
                    valid[b]=known[e->src+b] || !e->mask[b];
                }
                memcpy(value,result,size); memcpy(k,valid,size); memset(tag,0,(size+3)&~3U);
                memset(value+size,0,((size+3)&~3U)-size); memset(k+size,1,((size+3)&~3U)-size);
                break;
            }
            case MD_FILTER_COMPARE: {
                int mismatch=0;
                for (unsigned b=0;b<size;++b) if (known[e->src+b] && values[e->src+b]!=e->value[b]) mismatch=1;
                int excluded=(size==4 && all(tags+e->src,size,ADDRESS)) || (size==2 && all(tags+e->src,size,PORT));
                if (mismatch || excluded) possible=e->operation==NFT_CMP_NEQ;
                else if (all(known+e->src,size,1)) possible=e->operation==NFT_CMP_EQ;
                else uncertain=1;
                break;
            }
            case MD_FILTER_RANGE:
                if (size==2 && all(tags+e->src,size,PORT)) possible=e->operation==NFT_RANGE_NEQ;
                else if (all(known+e->src,size,1)) {
                    int inside=memcmp(values+e->src,e->value,size)>=0 && memcmp(values+e->src,e->mask,size)<=0;
                    possible=e->operation==NFT_RANGE_EQ ? inside : !inside;
                } else uncertain=1;
                break;
            case MD_FILTER_LOOKUP:
                if ((size==2 && all(tags+e->src,size,PORT)) || (size==4 && all(tags+e->src,size,ADDRESS))) possible=!!e->operation;
                else if (all(known+e->src,size,1)) {
                    struct md_filter_set *set=md_filter_set_find(f,0,NULL,e->target,0);
                    if (!set) return -ENOENT;
                    int found=0;
                    for (size_t b=0;b<set->count;++b) if (!memcmp(values+e->src,set->elements[b].key,size)) { found=1; break; }
                    possible=e->operation ? !found : found;
                } else uncertain=1;
                break;
            case MD_FILTER_NAT: if (e->operation==NFT_NAT_DNAT) return 1; possible=0; break;
            case MD_FILTER_MASQUERADE: possible=0; break;
            case MD_FILTER_VERDICT_MAP: {
                struct md_filter_set *s=md_filter_set_find(f,chain->table,NULL,e->target,0);
                if (!s) return -ENOENT;
                int known_key=all(known+e->src,size,1);
                for (size_t b=0;b<s->count;++b) {
                    if (!*budget) return -E2BIG;
                    --*budget;
                    if (known_key && memcmp(values+e->src,s->elements[b].key,size)) continue;
                    struct md_filter_verdict v=s->elements[b].verdict;
                    if ((int)v.operation!=NFT_JUMP && (int)v.operation!=NFT_GOTO) continue;
                    struct md_filter_chain *target=md_filter_chain_find(f,chain->table,NULL,v.target,0);
                    if (!target) return -ENOENT;
                    int found=may_translate(f,target,address,port,protocol,unknown_port,budget,depth+1);
                    if (found) return found;
                }
                uncertain=1; break;
            }
            case MD_FILTER_VERDICT:
                if ((int)e->operation==NFT_JUMP || (int)e->operation==NFT_GOTO) {
                    struct md_filter_chain *target=md_filter_chain_find(f,0,NULL,e->target,0);
                    if (!target) return -ENOENT;
                    int found=may_translate(f,target,address,port,protocol,unknown_port,budget,depth+1);
                    if (found) return found;
                    uncertain=1;
                } else if ((int)e->operation!=NFT_CONTINUE) {
                    if (!uncertain && (int)e->operation!=NFT_BREAK) return 0;
                    possible=0;
                }
                break;
            case MD_FILTER_META_SET: case MD_FILTER_CT_SET: case MD_FILTER_COUNTER: break;
            }
        }
    }
    return 0;
}
static int publication(struct md_network_filter *f,uint32_t address,uint16_t port,unsigned protocol,
        int unknown_port,unsigned *budget) {
    for (size_t i=0;i<f->chain_count;++i) if (f->chains[i].hook==NF_INET_PRE_ROUTING && f->chains[i].nat) {
        int found=may_translate(f,&f->chains[i],address,port,protocol,unknown_port,budget,0);
        if (found) return found;
    }
    return 0;
}
int md_filter_ports(struct md_network_filter *f,uint32_t uplink,struct md_filter_port *ports,size_t limit,size_t *count) {
    uint32_t candidates[1024],addresses[256]={0,htonl(INADDR_LOOPBACK)};
    size_t nc=0,na=2; int dnat=0;
    *count=0;
    if (!f) return 0;
    for (size_t i=0;i<f->rule_count;++i) for (unsigned j=0;j<f->rules[i].count;++j) {
        const struct md_filter_expression *e=&f->rules[i].expressions[j];
        if (e->code==MD_FILTER_NAT && e->operation==NFT_NAT_DNAT) dnat=1;
    }
    if (!dnat) return 0;
    for (size_t i=0;i<f->rule_count;++i) {
        const struct md_filter_rule *r=&f->rules[i];
        unsigned char tags[64]={0};
        for (unsigned j=0;j<r->count;++j) {
            const struct md_filter_expression *e=&r->expressions[j];
            unsigned size=e->size;
            if (e->code==MD_FILTER_TRANSPORT && !(e->transport.inversion&MD_FILTER_INVERT_DESTINATION)) {
                if (!e->transport.destination[0] && e->transport.destination[1]==UINT16_MAX) continue;
                for (unsigned p=e->transport.destination[0];p<=e->transport.destination[1];++p) {
                    int error=unique(candidates,&nc,1024,htons((uint16_t)p)); if (error) return error;
                }
            } else if (e->code==MD_FILTER_PAYLOAD) {
                memset(tags+e->dst,0,size);
                if (e->key==NFT_PAYLOAD_TRANSPORT_HEADER && e->aux<=2 && e->aux+size>=4) {
                    tags[e->dst+2-e->aux]=1; tags[e->dst+3-e->aux]=1;
                } else if (e->key==NFT_PAYLOAD_NETWORK_HEADER && e->aux==16 && size==4) memset(tags+e->dst,2,4);
            } else if (e->code==MD_FILTER_COMPARE && e->operation==NFT_CMP_EQ && tags[e->src]==2 && size==4) {
                uint32_t address; memcpy(&address,e->value,4);
                int error=unique(addresses,&na,256,address); if (error) return error;
            } else if ((e->code==MD_FILTER_COMPARE && e->operation==NFT_CMP_EQ)
                    || (e->code==MD_FILTER_RANGE && e->operation==NFT_RANGE_EQ)) {
                if (size!=2 || tags[e->src]!=1 || tags[e->src+1]!=1) continue;
                uint16_t first,last; memcpy(&first,e->value,2);
                if (e->code==MD_FILTER_RANGE) memcpy(&last,e->mask,2); else last=first;
                for (unsigned p=ntohs(first);p<=ntohs(last);++p) {
                    int error=unique(candidates,&nc,1024,htons((uint16_t)p)); if (error) return error;
                }
            } else if (e->code==MD_FILTER_LOOKUP && !e->operation && ((size==2 && tags[e->src]==1 && tags[e->src+1]==1)
                    || (size==4 && tags[e->src]==2))) {
                struct md_filter_set *s=md_filter_set_find(f,0,NULL,e->target,0);
                if (!s) return -ENOENT;
                for (size_t k=0;k<s->count;++k) {
                    uint32_t item=0; memcpy(&item,s->elements[k].key,size);
                    int error=size==2 ? unique(candidates,&nc,1024,item) : unique(addresses,&na,256,item);
                    if (error) return error;
                }
            } else if (e->code==MD_FILTER_IMMEDIATE || e->code==MD_FILTER_META || e->code==MD_FILTER_CT
                    || e->code==MD_FILTER_FIB || e->code==MD_FILTER_BITWISE) memset(tags+e->dst,0,size);
        }
    }
    /* Native publication needs a finite listener set. Unbounded port matching
     * cannot silently claim a host-wide packet interception facility. */
    unsigned budget=4000000;
    for (size_t a=0;a<na;++a) for (unsigned protocol=0;protocol<2;++protocol) {
        int found=publication(f,addresses[a],0,protocol ? IPPROTO_UDP : IPPROTO_TCP,1,&budget);
        if (found) return found<0 ? found : -EOPNOTSUPP;
    }
    for (size_t i=0;i<nc;++i) for (unsigned protocol=0;protocol<2;++protocol) {
        int wildcard=0;
        for (size_t a=0;a<na && !wildcard;++a) {
            if (addresses[a] && addresses[a]!=uplink && (ntohl(addresses[a])>>24)!=127) continue;
            unsigned transport=protocol ? IPPROTO_UDP : IPPROTO_TCP;
            int found=publication(f,addresses[a],(uint16_t)candidates[i],transport,0,&budget);
            if (found<0) return found;
            if (!found) continue;
            if (!candidates[i]) return -EOPNOTSUPP;
            if (*count==limit) return -ENOSPC;
            ports[(*count)++]=(struct md_filter_port){.address=addresses[a],.port=(uint16_t)candidates[i],.protocol=transport};
            wildcard=!addresses[a];
        }
    }
    return 0;
}

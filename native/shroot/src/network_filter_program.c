#include "network_filter.h"
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <string.h>

static int chain_index(const struct md_network_filter *f,uint64_t handle) {
    for (size_t i=0;i<f->chain_count;++i) if (f->chains[i].handle==handle) return (int)i;
    return -1;
}
static int validate_chain(const struct md_network_filter *f,size_t chain,unsigned char *state,
        unsigned char *height,unsigned depth) {
    if (state[chain]==1 || depth>16) return -ELOOP;
    if (state[chain]==2) return depth+height[chain]>16 ? -ELOOP : 0;
    state[chain]=1;
    const struct md_filter_chain *c=&f->chains[chain];
    for (size_t i=0;i<f->rule_count;++i) if (f->rules[i].chain==c->handle) {
        const struct md_filter_rule *r=&f->rules[i];
        for (unsigned j=0;j<r->count;++j) {
            const struct md_filter_expression *e=&r->expressions[j];
            for (size_t k=0;k<md_filter_verdict_count(f,e);++k) {
                struct md_filter_verdict v=md_filter_verdict_at(f,e,k);
                if ((int)v.operation!=NFT_JUMP && (int)v.operation!=NFT_GOTO) continue;
                int target=chain_index(f,v.target);
                if (target<0) return -ENOENT;
                if (f->chains[target].table!=c->table || f->chains[target].hook>=0) return -EOPNOTSUPP;
                int error=validate_chain(f,(size_t)target,state,height,depth+1);
                if (error) return error;
                if (height[target]+1>height[chain]) height[chain]=height[target]+1;
            }
            if (e->code==MD_FILTER_LOOKUP || e->code==MD_FILTER_VERDICT_MAP) {
                int found=0;
                for (size_t k=0;k<f->set_count;++k)
                    if (f->sets[k].handle==e->target && f->sets[k].table==c->table) found=1;
                if (!found) return -ENOENT;
            }
        }
    }
    state[chain]=2; return 0;
}
int md_filter_validate(const struct md_network_filter *f) {
    unsigned char state[256]={0};
    unsigned char height[256]={0};
    unsigned contexts[256]={0};
    for (size_t i=0;i<f->chain_count;++i) {
        int error=validate_chain(f,i,state,height,0);
        if (error) return error;
        if (f->chains[i].hook>=0) contexts[i]=f->chains[i].nat ? 1U<<f->chains[i].hook : 1U<<NF_INET_NUMHOOKS;
    }
    /* A regular chain inherits every hook from which it is reachable. Validate
     * NAT there too, so a jump cannot admit NAT in a filter/incorrect hook. */
    for (unsigned changed=1;changed;) {
        changed=0;
        for (size_t i=0;i<f->rule_count;++i) {
            const struct md_filter_rule *r=&f->rules[i];
            int source=chain_index(f,r->chain);
            if (source<0) return -ENOENT;
            for (unsigned j=0;j<r->count;++j) {
                const struct md_filter_expression *e=&r->expressions[j];
                for (size_t k=0;k<md_filter_verdict_count(f,e);++k) {
                    struct md_filter_verdict v=md_filter_verdict_at(f,e,k);
                    if ((int)v.operation!=NFT_JUMP && (int)v.operation!=NFT_GOTO) continue;
                    int target=chain_index(f,v.target);
                    unsigned added=contexts[source]&~contexts[target];
                    contexts[target]|=added; changed|=added;
                }
            }
        }
    }
    for (size_t i=0;i<f->rule_count;++i) {
        const struct md_filter_rule *r=&f->rules[i];
        unsigned context=contexts[chain_index(f,r->chain)];
        for (unsigned j=0;j<r->count;++j) {
            const struct md_filter_expression *e=&r->expressions[j];
            unsigned allowed;
            if (e->code==MD_FILTER_MASQUERADE) allowed=1U<<NF_INET_POST_ROUTING;
            else if (e->code==MD_FILTER_NAT) allowed=e->operation==NFT_NAT_DNAT
                ? (1U<<NF_INET_PRE_ROUTING)|(1U<<NF_INET_LOCAL_OUT)
                : (1U<<NF_INET_POST_ROUTING)|(1U<<NF_INET_LOCAL_IN);
            else continue;
            if (context&~allowed) return -EOPNOTSUPP;
        }
    }
    return 0;
}
static int account_counter(struct md_filter_packet *p,struct md_filter_counter *counter) {
    if (p->unmediated) return -EBUSY;
    struct md_filter_accounting *a=p->accounting;
    if (!a) return 0;
    int error=md_filter_reserve((void **)&a->cells,&a->capacity,a->count+1,sizeof(*a->cells),1024);
    if (!error) a->cells[a->count++]=counter;
    return error;
}
static int evaluate_chain(struct md_network_filter *f,const struct md_filter_chain *c,
        struct md_filter_packet *p,unsigned depth) {
    if (depth>16) return -ELOOP;
    for (size_t i=0;i<f->rule_count;++i) {
        struct md_filter_rule *r=&f->rules[i];
        if (r->chain!=c->handle) continue;
        unsigned char registers[64]={0};
        int match=1;
        for (unsigned j=0;j<r->count && match;++j) {
            struct md_filter_expression *e=&r->expressions[j];
            unsigned char *src=registers+e->src,*dst=registers+e->dst;
            uint32_t value=0;
            switch (e->code) {
            case MD_FILTER_TRANSPORT: {
                const struct md_filter_transport *t=&e->transport;
                match=p->protocol==t->protocol
                    && md_filter_port_matches(ntohs(p->source_port),t->source,t->inversion&MD_FILTER_INVERT_SOURCE)
                    && md_filter_port_matches(ntohs(p->destination_port),t->destination,t->inversion&MD_FILTER_INVERT_DESTINATION);
                break;
            }
            case MD_FILTER_COUNTER: {
                int error=account_counter(p,&e->counter);
                if (error) return error;
                break;
            }
            case MD_FILTER_IMMEDIATE:
                memset(dst,0,(e->size+3)&~3U); memcpy(dst,e->value,e->size); break;
            case MD_FILTER_COMPARE: {
                int same=!memcmp(src,e->value,e->size);
                match=e->operation==NFT_CMP_EQ ? same : !same; break;
            }
            case MD_FILTER_RANGE: {
                int inside=memcmp(src,e->value,e->size)>=0 && memcmp(src,e->mask,e->size)<=0;
                match=e->operation==NFT_RANGE_EQ ? inside : !inside; break;
            }
            case MD_FILTER_BITWISE: {
                unsigned char result[16];
                for (unsigned k=0;k<e->size;++k) result[k]=(src[k]&e->mask[k])^e->value[k];
                memcpy(dst,result,e->size);
                memset(dst+e->size,0,((e->size+3)&~3U)-e->size);
                break;
            }
            case MD_FILTER_PAYLOAD: {
                unsigned char header[40]={0};
                if (e->key==NFT_PAYLOAD_NETWORK_HEADER) {
                    if (p->destination.family==AF_INET6) {
                        header[0]=0x60; header[6]=(unsigned char)p->protocol;
                        memcpy(header+8,p->source.bytes,16); memcpy(header+24,p->destination.bytes,16);
                    } else {
                        header[0]=0x45; header[9]=(unsigned char)p->protocol;
                        memcpy(header+12,p->source.bytes,4); memcpy(header+16,p->destination.bytes,4);
                    }
                } else { memcpy(header,&p->source_port,2); memcpy(header+2,&p->destination_port,2); }
                if (e->aux+e->size>(e->key==NFT_PAYLOAD_NETWORK_HEADER
                        ? (p->destination.family==AF_INET6 ? 40U : 20U) : 4U)) { match=0; break; }
                memset(dst,0,(e->size+3)&~3U); memcpy(dst,header+e->aux,e->size); break;
            }
            case MD_FILTER_META:
                switch (e->key) {
                case NFT_META_NFPROTO: value=p->destination.family==AF_INET6 ? NFPROTO_IPV6 : NFPROTO_IPV4; break;
                case NFT_META_L4PROTO: value=p->protocol; break;
                case NFT_META_MARK: value=p->mark; break;
                case NFT_META_IIF: value=p->input; break;
                case NFT_META_OIF: value=p->output; break;
                case NFT_META_IIFNAME: memcpy(dst,p->input_name,16); break;
                case NFT_META_OIFNAME: memcpy(dst,p->output_name,16); break;
                }
                if (e->size<=4) memcpy(dst,&value,4);
                break;
            case MD_FILTER_META_SET:
                if (p->unmediated) return -EBUSY;
                if (e->constant) {
                    uint32_t mask;
                    memcpy(&value,e->value,4); memcpy(&mask,e->mask,4);
                    p->mark=(p->mark&~mask)^value;
                } else memcpy(&p->mark,src,4);
                break;
            case MD_FILTER_CT:
                value=e->key==NFT_CT_STATE ? p->state : e->key==NFT_CT_MARK ? p->ctmark : p->status;
                memcpy(dst,&value,4); break;
            case MD_FILTER_CT_SET:
                if (p->unmediated) return -EBUSY;
                memcpy(&p->ctmark,src,4); break;
            case MD_FILTER_STATE_MATCH: match=!!(p->state&e->key)!=!!e->operation; break;
            case MD_FILTER_MARK_MATCH: match=((p->mark&e->aux)==e->key)!=!!e->operation; break;
            case MD_FILTER_ADDRESS_TYPE:
                match=(!e->key || (!!(e->key&(1U<<p->source_fib_type))!=!!(e->operation&MD_FILTER_INVERT_SOURCE)))
                    && (!e->aux || (!!(e->aux&(1U<<p->fib_type))!=!!(e->operation&MD_FILTER_INVERT_DESTINATION)));
                break;
            case MD_FILTER_FIB:
                value=e->operation==NFTA_FIB_F_SADDR ? p->source_fib_type : p->fib_type;
                memcpy(dst,&value,4); break;
            case MD_FILTER_LOOKUP: {
                struct md_filter_set *s=md_filter_set_find(f,c->table,NULL,e->target,0);
                int found=0;
                if (!s) return -ENOENT;
                for (size_t k=0;k<s->count;++k) if (!memcmp(src,s->elements[k].key,s->key_size)) { found=1; break; }
                match=e->operation ? !found : found; break;
            }
            case MD_FILTER_NAT:
                if (e->family && e->family!=p->destination.family) { match=0; break; }
                if (e->operation==NFT_NAT_DNAT) {
                    if (e->key) memcpy(p->destination.bytes,e->constant ? e->value : registers+e->dst,md_ip_size(p->destination));
                    if (e->aux) memcpy(&p->destination_port,e->constant ? (const void *)&e->nat_port : registers+e->src,2);
                    p->dnat=1; p->status|=1U<<5;
                } else {
                    if (e->key) memcpy(p->source.bytes,e->constant ? e->value : registers+e->dst,md_ip_size(p->source));
                    if (e->aux) memcpy(&p->source_port,e->constant ? (const void *)&e->nat_port : registers+e->src,2);
                    p->snat=1; p->status|=1U<<4;
                }
                return NF_ACCEPT;
            case MD_FILTER_MASQUERADE:
                p->source=p->masquerade_address; p->snat=p->masquerade=1; p->status|=1U<<4;
                return NF_ACCEPT;
            case MD_FILTER_VERDICT_MAP:
            case MD_FILTER_VERDICT: {
                struct md_filter_verdict v={e->operation,e->target};
                if (e->code==MD_FILTER_VERDICT_MAP) {
                    struct md_filter_set *s=md_filter_set_find(f,c->table,NULL,e->target,0);
                    if (!s) return -ENOENT;
                    size_t k=0;
                    while (k<s->count && memcmp(src,s->elements[k].key,s->key_size)) ++k;
                    if (k==s->count) { match=0; break; }
                    v=s->elements[k].verdict;
                }
                if ((int)v.operation==NFT_JUMP || (int)v.operation==NFT_GOTO) {
                    struct md_filter_chain *target=md_filter_chain_find(f,c->table,NULL,v.target,0);
                    if (!target) return -ENOENT;
                    int verdict=evaluate_chain(f,target,p,depth+1);
                    if (verdict!=NFT_RETURN || (int)v.operation==NFT_GOTO) return verdict;
                } else if ((int)v.operation==NFT_BREAK) match=0;
                else if ((int)v.operation!=NFT_CONTINUE) return (int)v.operation;
                break;
            }
            }
        }
    }
    return NFT_RETURN;
}
int md_filter_evaluate(struct md_network_filter *f,unsigned hook,struct md_filter_packet *p) {
    return md_filter_evaluate_transition(f,hook,p,NULL,NULL);
}
int md_filter_chain_applies(const struct md_network_filter *f,const struct md_filter_chain *c,unsigned family) {
    unsigned protocol=family==AF_INET6 ? NFPROTO_IPV6 : NFPROTO_IPV4;
    for (size_t i=0;i<f->count;++i) if (f->tables[i].handle==c->table)
        return f->tables[i].family==NFPROTO_INET || f->tables[i].family==protocol;
    return 0;
}
int md_filter_evaluate_transition(struct md_network_filter *f,unsigned hook,struct md_filter_packet *p,
        const struct md_filter_rewrite *rewrite,int *nat_priority) {
    /* Order is stable for equal priorities. NF_ACCEPT ends a chain, not the
     * hook: a later base chain may still deny the flow. */
    int previous_priority=INT32_MIN;
    size_t previous_index=0;
    int started=0,retained=rewrite!=NULL;
    for (;;) {
        size_t count=f ? f->chain_count : 0,selected=count;
        for (size_t i=0;i<count;++i) {
            struct md_filter_chain *c=&f->chains[i];
            if (!md_filter_chain_applies(f,c,p->destination.family) || c->hook!=(int)hook || (started && (c->priority<previous_priority
                    || (c->priority==previous_priority && i<=previous_index)))) continue;
            if (selected==count || c->priority<f->chains[selected].priority) selected=i;
        }
        /* Retained conntrack translation is a hook-stage operation, not an
         * already-rewritten input tuple. Early raw rules see the wire address;
         * later filters see the translated destination/source. */
        if (rewrite && (selected==count || f->chains[selected].priority>=rewrite->priority)) {
            p->source=rewrite->source; p->destination=rewrite->destination;
            p->source_port=rewrite->source_port; p->destination_port=rewrite->destination_port;
            p->fib_type=rewrite->fib_type; p->source_fib_type=rewrite->source_fib_type;
            rewrite=NULL;
        }
        if (selected==count) return 0;
        struct md_filter_chain *c=&f->chains[selected];
        int mapped=(hook==NF_INET_PRE_ROUTING || hook==NF_INET_LOCAL_OUT) ? p->dnat : p->snat;
        int verdict=c->nat && (retained || p->state!=8 || mapped) ? NF_ACCEPT : evaluate_chain(f,c,p,0);
        if (nat_priority && c->nat && !mapped && (p->dnat || p->snat)) *nat_priority=c->priority;
        if (verdict==NFT_RETURN) {
            if (c->counters) {
                int error=account_counter(p,&c->counter);
                if (error) return error;
            }
            verdict=(int)c->policy;
        }
        if (verdict!=NF_ACCEPT) return verdict==NF_DROP ? -EACCES : verdict<0 ? verdict : -EOPNOTSUPP;
        previous_priority=c->priority; previous_index=selected; started=1;
    }
}

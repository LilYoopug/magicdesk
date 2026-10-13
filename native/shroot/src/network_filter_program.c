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
            if (e->code==MD_FILTER_VERDICT && ((int)e->operation==NFT_JUMP || (int)e->operation==NFT_GOTO)) {
                int target=chain_index(f,e->target);
                if (target<0) return -ENOENT;
                if (f->chains[target].table!=c->table || f->chains[target].hook>=0) return -EOPNOTSUPP;
                int error=validate_chain(f,(size_t)target,state,height,depth+1);
                if (error) return error;
                if (height[target]+1>height[chain]) height[chain]=height[target]+1;
            } else if (e->code==MD_FILTER_LOOKUP) {
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
                if (e->code!=MD_FILTER_VERDICT || ((int)e->operation!=NFT_JUMP && (int)e->operation!=NFT_GOTO)) continue;
                int target=chain_index(f,e->target);
                unsigned added=contexts[source]&~contexts[target];
                contexts[target]|=added; changed|=added;
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
                unsigned char header[20]={0};
                if (e->key==NFT_PAYLOAD_NETWORK_HEADER) {
                    header[0]=0x45; header[9]=(unsigned char)p->protocol;
                    memcpy(header+12,&p->source,4); memcpy(header+16,&p->destination,4);
                } else { memcpy(header,&p->source_port,2); memcpy(header+2,&p->destination_port,2); }
                memset(dst,0,(e->size+3)&~3U); memcpy(dst,header+e->aux,e->size); break;
            }
            case MD_FILTER_META:
                switch (e->key) {
                case NFT_META_NFPROTO: value=NFPROTO_IPV4; break;
                case NFT_META_L4PROTO: value=p->protocol; break;
                case NFT_META_MARK: value=p->mark; break;
                case NFT_META_IIF: value=p->input; break;
                case NFT_META_OIF: value=p->output; break;
                case NFT_META_IIFNAME: memcpy(dst,p->input_name,16); break;
                case NFT_META_OIFNAME: memcpy(dst,p->output_name,16); break;
                }
                if (e->size<=4) memcpy(dst,&value,4);
                break;
            case MD_FILTER_META_SET: memcpy(&p->mark,src,4); break;
            case MD_FILTER_CT:
                value=e->key==NFT_CT_STATE ? p->state : e->key==NFT_CT_MARK ? p->ctmark : p->status;
                memcpy(dst,&value,4); break;
            case MD_FILTER_CT_SET: memcpy(&p->ctmark,src,4); break;
            case MD_FILTER_FIB: memcpy(dst,&p->fib_type,4); break;
            case MD_FILTER_LOOKUP: {
                struct md_filter_set *s=md_filter_set_find(f,c->table,NULL,e->target,0);
                int found=0;
                if (!s) return -ENOENT;
                for (size_t k=0;k<s->count;++k) if (!memcmp(src,s->elements[k].key,s->key_size)) { found=1; break; }
                match=e->operation ? !found : found; break;
            }
            case MD_FILTER_NAT:
                if (e->operation==NFT_NAT_DNAT) {
                    if (e->key) memcpy(&p->destination,registers+e->dst,4);
                    if (e->aux) memcpy(&p->destination_port,registers+e->src,2);
                    p->dnat=1; p->status|=1U<<5;
                } else {
                    if (e->key) memcpy(&p->source,registers+e->dst,4);
                    if (e->aux) memcpy(&p->source_port,registers+e->src,2);
                    p->snat=1; p->status|=1U<<4;
                }
                return NF_ACCEPT;
            case MD_FILTER_MASQUERADE:
                p->source=p->masquerade_address; p->snat=p->masquerade=1; p->status|=1U<<4;
                return NF_ACCEPT;
            case MD_FILTER_VERDICT:
                if ((int)e->operation==NFT_JUMP || (int)e->operation==NFT_GOTO) {
                    struct md_filter_chain *target=md_filter_chain_find(f,c->table,NULL,e->target,0);
                    if (!target) return -ENOENT;
                    int verdict=evaluate_chain(f,target,p,depth+1);
                    if (verdict!=NFT_RETURN || (int)e->operation==NFT_GOTO) return verdict;
                } else if ((int)e->operation==NFT_BREAK) match=0;
                else if ((int)e->operation!=NFT_CONTINUE) return (int)e->operation;
                break;
            }
        }
    }
    return c->hook>=0 ? (int)c->policy : NFT_RETURN;
}
int md_filter_evaluate(struct md_network_filter *f,unsigned hook,struct md_filter_packet *p) {
    if (!f || !f->chain_count) return 0;
    /* Order is stable for equal priorities. NF_ACCEPT ends a chain, not the
     * hook: a later base chain may still deny the flow. */
    int previous_priority=INT32_MIN;
    size_t previous_index=0;
    int started=0;
    for (;;) {
        size_t selected=f->chain_count;
        for (size_t i=0;i<f->chain_count;++i) {
            struct md_filter_chain *c=&f->chains[i];
            if (c->hook!=(int)hook || (started && (c->priority<previous_priority
                    || (c->priority==previous_priority && i<=previous_index)))) continue;
            if (selected==f->chain_count || c->priority<f->chains[selected].priority) selected=i;
        }
        if (selected==f->chain_count) return 0;
        struct md_filter_chain *c=&f->chains[selected];
        int mapped=(hook==NF_INET_PRE_ROUTING || hook==NF_INET_LOCAL_OUT) ? p->dnat : p->snat;
        int verdict=c->nat && (p->state!=8 || mapped) ? NF_ACCEPT : evaluate_chain(f,c,p,0);
        if (verdict==NFT_RETURN) verdict=(int)c->policy;
        if (verdict!=NF_ACCEPT) return verdict==NF_DROP ? -EACCES : verdict<0 ? verdict : -EOPNOTSUPP;
        previous_priority=c->priority; previous_index=selected; started=1;
    }
}

#include "network_nft_expression.h"
#include "network_nft_objects.h"
#include "network_nft_attr.h"
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nf_nat.h>
#include <stdlib.h>

static int data_value(const struct attribute *a,void *value,unsigned *size) {
    struct attribute attrs[NFTA_DATA_MAX+1];
    int error=nested(a,BIT(NFTA_DATA_VALUE),attrs,NFTA_DATA_MAX+1);
    if (error) return error;
    const struct attribute *v=&attrs[NFTA_DATA_VALUE];
    if (!v->data || v->flags || !v->size || v->size>16) return -EINVAL;
    memcpy(value,v->data,v->size); *size=(unsigned)v->size; return 0;
}
static int reg(const struct attribute *a,unsigned size,unsigned *offset,uint64_t *initialized,int write) {
    uint32_t id;
    int error=required_number(a,&id); if (error) return error;
    unsigned start=id>=NFT_REG_1 && id<=NFT_REG_4 ? (id-NFT_REG_1)*16
        : id>=NFT_REG32_00 && id<=NFT_REG32_15 ? (id-NFT_REG32_00)*4 : 64;
    if (!size || size>16 || start>64-size) return -EINVAL;
    unsigned covered=write ? (size+3)&~3U : size;
    uint64_t mask=((UINT64_C(1)<<covered)-1)<<start;
    if (!write && (*initialized&mask)!=mask) return -EINVAL;
    if (write) *initialized|=mask;
    *offset=start; return 0;
}
static int expression(struct md_network_filter *f,uint64_t table,
        const char *name,const struct attribute *data,struct md_filter_expression *e,uint64_t *initialized) {
    struct attribute a[32]; int error;
    uint32_t value=0;
#define FIELDS(mask) do { error=nested(data,(mask),a,32); if (error) return error; } while (0)
#define NUM(key,dst) do { error=required_number(&a[key],&(dst)); if (error) return error; } while (0)
#define REG(key,size,dst,write) do { error=reg(&a[key],size,&(dst),initialized,write); if (error) return error; } while (0)
    if (!strcmp(name,"immediate")) {
        FIELDS(BIT(NFTA_IMMEDIATE_DREG)|BIT(NFTA_IMMEDIATE_DATA));
        NUM(NFTA_IMMEDIATE_DREG,value);
        if (value==NFT_REG_VERDICT) {
            struct attribute b[NFTA_DATA_MAX+1],v[NFTA_VERDICT_MAX+1];
            error=nested(&a[NFTA_IMMEDIATE_DATA],BIT(NFTA_DATA_VERDICT),b,NFTA_DATA_MAX+1);
            if (!error) error=nested(&b[NFTA_DATA_VERDICT],BIT(NFTA_VERDICT_CODE)|BIT(NFTA_VERDICT_CHAIN)|BIT(NFTA_VERDICT_CHAIN_ID),v,NFTA_VERDICT_MAX+1);
            if (!error) error=required_number(&v[NFTA_VERDICT_CODE],&e->operation);
            if (error) return error;
            e->code=MD_FILTER_VERDICT;
            if ((int)e->operation==NFT_JUMP || (int)e->operation==NFT_GOTO) {
                const char *chain=NULL; uint64_t id=0;
                error=string(&v[NFTA_VERDICT_CHAIN],&chain);
                if (!error) error=number(&v[NFTA_VERDICT_CHAIN_ID],&id,0);
                if (error) return error;
                struct md_filter_chain *c=md_filter_chain_find(f,table,chain,0,(uint32_t)id);
                if (!c) return -ENOENT;
                if (c->hook>=0) return -EOPNOTSUPP;
                e->target=c->handle;
            } else if ((int)e->operation!=NFT_RETURN && (int)e->operation!=NFT_CONTINUE
                    && (int)e->operation!=NFT_BREAK && e->operation!=NF_ACCEPT && e->operation!=NF_DROP) return -EOPNOTSUPP;
        } else {
            e->code=MD_FILTER_IMMEDIATE;
            error=data_value(&a[NFTA_IMMEDIATE_DATA],e->value,&e->size); if (error) return error;
            REG(NFTA_IMMEDIATE_DREG,e->size,e->dst,1);
        }
    } else if (!strcmp(name,"meta")) {
        FIELDS(BIT(NFTA_META_KEY)|BIT(NFTA_META_DREG)|BIT(NFTA_META_SREG));
        NUM(NFTA_META_KEY,e->key);
        e->code=a[NFTA_META_SREG].data ? MD_FILTER_META_SET : MD_FILTER_META;
        e->size=(e->key==NFT_META_NFPROTO || e->key==NFT_META_L4PROTO) ? 1
            : (e->key==NFT_META_IIFNAME || e->key==NFT_META_OIFNAME) ? 16 : 4;
        if (e->code==MD_FILTER_META_SET) {
            if (e->key!=NFT_META_MARK || a[NFTA_META_DREG].data) return -EOPNOTSUPP;
            REG(NFTA_META_SREG,4,e->src,0);
        } else {
            if (e->key!=NFT_META_NFPROTO && e->key!=NFT_META_L4PROTO && e->key!=NFT_META_MARK
                    && e->key!=NFT_META_IIF && e->key!=NFT_META_OIF && e->key!=NFT_META_IIFNAME && e->key!=NFT_META_OIFNAME) return -EOPNOTSUPP;
            REG(NFTA_META_DREG,e->size,e->dst,1);
        }
    } else if (!strcmp(name,"payload")) {
        FIELDS(BIT(NFTA_PAYLOAD_DREG)|BIT(NFTA_PAYLOAD_BASE)|BIT(NFTA_PAYLOAD_OFFSET)|BIT(NFTA_PAYLOAD_LEN));
        e->code=MD_FILTER_PAYLOAD;
        NUM(NFTA_PAYLOAD_BASE,e->key); NUM(NFTA_PAYLOAD_OFFSET,e->aux); NUM(NFTA_PAYLOAD_LEN,e->size);
        if (e->key==NFT_PAYLOAD_NETWORK_HEADER) {
            if (!((e->aux==9 && e->size==1) || (e->aux>=12 && e->aux<20 && e->size<=20-e->aux))) return -EOPNOTSUPP;
        } else if (e->key!=NFT_PAYLOAD_TRANSPORT_HEADER || e->aux>=4 || e->size>4-e->aux) return -EOPNOTSUPP;
        REG(NFTA_PAYLOAD_DREG,e->size,e->dst,1);
    } else if (!strcmp(name,"cmp")) {
        FIELDS(BIT(NFTA_CMP_SREG)|BIT(NFTA_CMP_OP)|BIT(NFTA_CMP_DATA));
        e->code=MD_FILTER_COMPARE; NUM(NFTA_CMP_OP,e->operation);
        if (e->operation!=NFT_CMP_EQ && e->operation!=NFT_CMP_NEQ) return -EOPNOTSUPP;
        error=data_value(&a[NFTA_CMP_DATA],e->value,&e->size); if (error) return error;
        REG(NFTA_CMP_SREG,e->size,e->src,0);
    } else if (!strcmp(name,"range")) {
        FIELDS(BIT(NFTA_RANGE_SREG)|BIT(NFTA_RANGE_OP)|BIT(NFTA_RANGE_FROM_DATA)|BIT(NFTA_RANGE_TO_DATA));
        e->code=MD_FILTER_RANGE; NUM(NFTA_RANGE_OP,e->operation);
        if (e->operation!=NFT_RANGE_EQ && e->operation!=NFT_RANGE_NEQ) return -EOPNOTSUPP;
        error=data_value(&a[NFTA_RANGE_FROM_DATA],e->value,&e->size);
        if (!error) error=data_value(&a[NFTA_RANGE_TO_DATA],e->mask,&value);
        if (error) return error;
        if (value!=e->size || memcmp(e->value,e->mask,e->size)>0) return -EINVAL;
        REG(NFTA_RANGE_SREG,e->size,e->src,0);
    } else if (!strcmp(name,"bitwise")) {
        FIELDS(BIT(NFTA_BITWISE_SREG)|BIT(NFTA_BITWISE_DREG)|BIT(NFTA_BITWISE_LEN)|BIT(NFTA_BITWISE_MASK)|BIT(NFTA_BITWISE_XOR)|BIT(NFTA_BITWISE_OP));
        e->code=MD_FILTER_BITWISE; NUM(NFTA_BITWISE_LEN,e->size);
        uint64_t operation=0; error=number(&a[NFTA_BITWISE_OP],&operation,0);
        if (error) return error;
        if (operation!=NFT_BITWISE_BOOL) return -EOPNOTSUPP;
        error=data_value(&a[NFTA_BITWISE_MASK],e->mask,&value);
        if (error) return error;
        if (value!=e->size) return -EINVAL;
        error=data_value(&a[NFTA_BITWISE_XOR],e->value,&value);
        if (error) return error;
        if (value!=e->size) return -EINVAL;
        REG(NFTA_BITWISE_SREG,e->size,e->src,0); REG(NFTA_BITWISE_DREG,e->size,e->dst,1);
    } else if (!strcmp(name,"ct")) {
        FIELDS(BIT(NFTA_CT_KEY)|BIT(NFTA_CT_DREG)|BIT(NFTA_CT_SREG));
        NUM(NFTA_CT_KEY,e->key); e->size=4;
        e->code=a[NFTA_CT_SREG].data ? MD_FILTER_CT_SET : MD_FILTER_CT;
        if (e->code==MD_FILTER_CT_SET) {
            if (e->key!=NFT_CT_MARK || a[NFTA_CT_DREG].data) return -EOPNOTSUPP;
            REG(NFTA_CT_SREG,4,e->src,0);
        } else {
            if (e->key!=NFT_CT_STATE && e->key!=NFT_CT_MARK && e->key!=NFT_CT_STATUS) return -EOPNOTSUPP;
            REG(NFTA_CT_DREG,4,e->dst,1);
        }
    } else if (!strcmp(name,"fib")) {
        FIELDS(BIT(NFTA_FIB_DREG)|BIT(NFTA_FIB_RESULT)|BIT(NFTA_FIB_FLAGS));
        NUM(NFTA_FIB_RESULT,e->key); NUM(NFTA_FIB_FLAGS,e->operation);
        if (e->key!=NFT_FIB_RESULT_ADDRTYPE || e->operation!=NFTA_FIB_F_DADDR) return -EOPNOTSUPP;
        e->code=MD_FILTER_FIB; e->size=4; REG(NFTA_FIB_DREG,4,e->dst,1);
    } else if (!strcmp(name,"lookup")) {
        FIELDS(BIT(NFTA_LOOKUP_SET)|BIT(NFTA_LOOKUP_SET_ID)|BIT(NFTA_LOOKUP_SREG)|BIT(NFTA_LOOKUP_FLAGS));
        const char *name=NULL; uint64_t id=0,flags=0;
        error=string(&a[NFTA_LOOKUP_SET],&name);
        if (!error) error=number(&a[NFTA_LOOKUP_SET_ID],&id,0);
        if (!error) error=number(&a[NFTA_LOOKUP_FLAGS],&flags,0);
        if (error) return error;
        if (flags&~NFT_LOOKUP_F_INV) return -EOPNOTSUPP;
        struct md_filter_set *s=md_filter_set_find(f,table,id ? NULL : name,0,(uint32_t)id);
        if (!s) return -ENOENT;
        e->code=MD_FILTER_LOOKUP; e->target=s->handle; e->size=s->key_size; e->operation=flags;
        REG(NFTA_LOOKUP_SREG,e->size,e->src,0);
    } else if (!strcmp(name,"nat")) {
        FIELDS(BIT(NFTA_NAT_TYPE)|BIT(NFTA_NAT_FAMILY)|BIT(NFTA_NAT_REG_ADDR_MIN)|BIT(NFTA_NAT_REG_ADDR_MAX)
            |BIT(NFTA_NAT_REG_PROTO_MIN)|BIT(NFTA_NAT_REG_PROTO_MAX)|BIT(NFTA_NAT_FLAGS));
        NUM(NFTA_NAT_TYPE,e->operation); NUM(NFTA_NAT_FAMILY,value);
        uint64_t flags=0; error=number(&a[NFTA_NAT_FLAGS],&flags,0);
        if (error) return error;
        if (value!=NFPROTO_IPV4 || e->operation>NFT_NAT_DNAT
                || (flags&~(NF_NAT_RANGE_MAP_IPS|NF_NAT_RANGE_PROTO_SPECIFIED))) return -EOPNOTSUPP;
        e->code=MD_FILTER_NAT;
        if (a[NFTA_NAT_REG_ADDR_MIN].data) {
            REG(NFTA_NAT_REG_ADDR_MIN,4,e->dst,0); e->key=1;
            if (a[NFTA_NAT_REG_ADDR_MAX].data) { unsigned other; REG(NFTA_NAT_REG_ADDR_MAX,4,other,0); if (other!=e->dst) return -EOPNOTSUPP; }
        } else if (a[NFTA_NAT_REG_ADDR_MAX].data) return -EINVAL;
        if (a[NFTA_NAT_REG_PROTO_MIN].data) {
            REG(NFTA_NAT_REG_PROTO_MIN,2,e->src,0); e->aux=1;
            if (a[NFTA_NAT_REG_PROTO_MAX].data) { unsigned other; REG(NFTA_NAT_REG_PROTO_MAX,2,other,0); if (other!=e->src) return -EOPNOTSUPP; }
        } else if (a[NFTA_NAT_REG_PROTO_MAX].data) return -EINVAL;
        if (!e->key && !e->aux) return -EINVAL;
        if (((flags&NF_NAT_RANGE_MAP_IPS) && !e->key)
                || ((flags&NF_NAT_RANGE_PROTO_SPECIFIED) && !e->aux)) return -EINVAL;
    } else if (!strcmp(name,"masq")) {
        FIELDS(BIT(NFTA_MASQ_FLAGS)); uint64_t flags=0;
        error=number(&a[NFTA_MASQ_FLAGS],&flags,0); if (error) return error;
        if (flags) return -EOPNOTSUPP;
        e->code=MD_FILTER_MASQUERADE;
    } else return -EOPNOTSUPP;
    return 0;
#undef FIELDS
#undef NUM
#undef REG
}
int md_nft_expressions(struct md_network_filter *f,uint64_t table,struct md_filter_rule *r,const void *data,size_t size) {
    uint64_t initialized=0;
    for (size_t offset=0;offset<size;) {
        if (size-offset<sizeof(struct nlattr)) return -EINVAL;
        const struct nlattr *item=(const void *)((const char *)data+offset);
        if (item->nla_len<sizeof(*item) || NLA_ALIGN(item->nla_len)>size-offset
                || (item->nla_type&NLA_TYPE_MASK)!=NFTA_LIST_ELEM || (item->nla_type&~(NLA_TYPE_MASK|NLA_F_NESTED))) return -EINVAL;
        struct attribute a[NFTA_EXPR_MAX+1];
        int error=fields(item+1,item->nla_len-sizeof(*item),BIT(NFTA_EXPR_NAME)|BIT(NFTA_EXPR_DATA),a,NFTA_EXPR_MAX+1);
        const char *name=NULL;
        if (!error) error=string(&a[NFTA_EXPR_NAME],&name);
        if (error) return error;
        if (!name || r->count==64) return -E2BIG;
        struct md_filter_expression *e=&r->expressions[r->count];
        error=expression(f,table,name,&a[NFTA_EXPR_DATA],e,&initialized);
        if (error) return error;
        ++r->count; offset+=NLA_ALIGN(item->nla_len);
    }
    if (size) {
        r->wire=malloc(size); if (!r->wire) return -ENOMEM;
        memcpy(r->wire,data,size); r->wire_size=size;
    }
    return 0;
}
static int u32(struct md_network_message *o,unsigned type,uint32_t value) {
    value=htonl(value); return md_network_message_attribute(o,type,&value,4);
}
static unsigned wire_register(unsigned offset) { return NFT_REG32_00+offset/4; }
int md_nft_emit_expressions(struct md_network_filter *f,const struct md_filter_rule *r,struct md_network_message *o) {
    size_t list=0,offset=0;
    int error=md_network_message_nest(o,NFTA_RULE_EXPRESSIONS,&list);
#define PUT(call) do { if (!error) error=(call); } while (0)
    for (unsigned i=0;!error && i<r->count;++i) {
        const struct md_filter_expression *e=&r->expressions[i];
        const struct nlattr *item=(const void *)((const char *)r->wire+offset);
        struct attribute a[NFTA_EXPR_MAX+1];
        error=fields(item+1,item->nla_len-sizeof(*item),BIT(NFTA_EXPR_NAME)|BIT(NFTA_EXPR_DATA),a,NFTA_EXPR_MAX+1);
        size_t entry=0,data=0;
        PUT(md_network_message_nest(o,NFTA_LIST_ELEM,&entry));
        PUT(md_network_message_attribute(o,NFTA_EXPR_NAME,a[NFTA_EXPR_NAME].data,a[NFTA_EXPR_NAME].size));
        if (e->code==MD_FILTER_LOOKUP) {
            struct md_filter_set *s=md_filter_set_find(f,0,NULL,e->target,0);
            if (!s) return -ENOENT;
            PUT(md_network_message_nest(o,NFTA_EXPR_DATA,&data));
            PUT(md_network_message_attribute(o,NFTA_LOOKUP_SET,s->name,strlen(s->name)+1));
            PUT(u32(o,NFTA_LOOKUP_SREG,wire_register(e->src)));
            if (e->operation) PUT(u32(o,NFTA_LOOKUP_FLAGS,e->operation));
            PUT(md_network_message_end_nest(o,data));
        } else if (e->code==MD_FILTER_VERDICT && ((int)e->operation==NFT_JUMP || (int)e->operation==NFT_GOTO)) {
            struct md_filter_chain *c=md_filter_chain_find(f,0,NULL,e->target,0);
            if (!c) return -ENOENT;
            size_t value=0,verdict=0;
            PUT(md_network_message_nest(o,NFTA_EXPR_DATA,&data));
            PUT(u32(o,NFTA_IMMEDIATE_DREG,NFT_REG_VERDICT));
            PUT(md_network_message_nest(o,NFTA_IMMEDIATE_DATA,&value));
            PUT(md_network_message_nest(o,NFTA_DATA_VERDICT,&verdict));
            PUT(u32(o,NFTA_VERDICT_CODE,e->operation));
            PUT(md_network_message_attribute(o,NFTA_VERDICT_CHAIN,c->name,strlen(c->name)+1));
            PUT(md_network_message_end_nest(o,verdict)); PUT(md_network_message_end_nest(o,value));
            PUT(md_network_message_end_nest(o,data));
        } else PUT(md_network_message_attribute(o,NFTA_EXPR_DATA|NLA_F_NESTED,a[NFTA_EXPR_DATA].data,a[NFTA_EXPR_DATA].size));
        PUT(md_network_message_end_nest(o,entry)); offset+=NLA_ALIGN(item->nla_len);
    }
    PUT(md_network_message_end_nest(o,list)); return error;
#undef PUT
}

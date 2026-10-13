#ifndef MD_NETWORK_NFT_ATTR_H
#define MD_NETWORK_NFT_ATTR_H
#include <errno.h>
#include <endian.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

struct attribute { const void *data; size_t size; unsigned flags; };
#define BIT(n) (UINT64_C(1)<<(n))
static inline int fields(const void *data,size_t size,uint64_t allowed,struct attribute *out,size_t count) {
    memset(out,0,count*sizeof(*out));
    for (size_t offset=0;offset<size;) {
        if (size-offset<sizeof(struct nlattr)) return -EINVAL;
        const struct nlattr *a=(const void *)((const char *)data+offset);
        if (a->nla_len<sizeof(*a) || a->nla_len>size-offset) return -EINVAL;
        unsigned type=a->nla_type&NLA_TYPE_MASK;
        if (type>=count || type>=64 || !(allowed&BIT(type))) return -EOPNOTSUPP;
        if (out[type].data) return -EINVAL;
        out[type]=(struct attribute){.data=a+1,.size=a->nla_len-sizeof(*a),.flags=a->nla_type&~NLA_TYPE_MASK};
        size_t step=NLA_ALIGN(a->nla_len);
        if (step>size-offset) return -EINVAL;
        offset+=step;
    }
    return 0;
}
static inline int attributes(const struct nlmsghdr *h,uint64_t allowed,struct attribute *out,size_t count) {
    size_t offset=NLMSG_LENGTH(sizeof(struct nfgenmsg));
    if (h->nlmsg_len<offset) return -EINVAL;
    return fields((const char *)h+offset,h->nlmsg_len-offset,allowed,out,count);
}
static inline int nested(const struct attribute *a,uint64_t allowed,struct attribute *out,size_t count) {
    if (!a->data || (a->flags&~NLA_F_NESTED)) return -EINVAL;
    return fields(a->data,a->size,allowed,out,count);
}
static inline int string(const struct attribute *a,const char **out) {
    *out=NULL;
    if (!a->data) return 0;
    if (a->flags || a->size<2 || a->size>256 || ((const char *)a->data)[a->size-1]
            || strnlen(a->data,a->size)!=a->size-1) return -EINVAL;
    *out=a->data; return 0;
}
static inline int number(const struct attribute *a,uint64_t *out,int wide) {
    *out=0;
    if (!a->data) return 0;
    if ((a->flags&~NLA_F_NET_BYTEORDER) || a->size!=(wide ? 8U : 4U)) return -EINVAL;
    if (wide) { uint64_t value; memcpy(&value,a->data,sizeof(value)); *out=be64toh(value); }
    else { uint32_t value; memcpy(&value,a->data,sizeof(value)); *out=ntohl(value); }
    return 0;
}
static inline int required_number(const struct attribute *a,uint32_t *out) {
    uint64_t value;
    if (!a->data) return -EINVAL;
    int error=number(a,&value,0);
    if (!error) *out=(uint32_t)value;
    return error;
}
#endif

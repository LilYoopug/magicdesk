#ifndef MD_NETLINK_ATTRIBUTES_H
#define MD_NETLINK_ATTRIBUTES_H
#include <errno.h>
#include <linux/netlink.h>
#include <stddef.h>
#include <string.h>

/* Framing only. Route, generic and netfilter owners retain their distinct
 * policies for types, flags, duplicates, byte order and nested sequences. */
struct md_netlink_cursor { const void *data; size_t size; };
struct md_netlink_attribute {
    const void *wire, *data;
    size_t size;
    unsigned type, flags;
};
/* 1 record, 0 end, negative error. A malformed record does not advance. */
static inline int md_netlink_attribute_next(struct md_netlink_cursor *cursor,
        struct md_netlink_attribute *out) {
    if (!cursor->size) return 0;
    if (!cursor->data || cursor->size<sizeof(struct nlattr)) return -EINVAL;
    struct nlattr h; memcpy(&h,cursor->data,sizeof(h));
    size_t span=NLA_ALIGN(h.nla_len);
    if (h.nla_len<sizeof(h) || span>cursor->size) return -EINVAL;
    *out=(struct md_netlink_attribute){.wire=cursor->data,
        .data=(const char *)cursor->data+sizeof(h),.size=h.nla_len-sizeof(h),
        .type=h.nla_type&NLA_TYPE_MASK,.flags=h.nla_type&~NLA_TYPE_MASK};
    cursor->data=(const char *)cursor->data+span; cursor->size-=span;
    return 1;
}
#endif

#include "netlink_attributes.h"
#include "network_nft_attr.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    unsigned char bytes[65540]={0};
    struct md_netlink_attribute a;
    struct md_netlink_cursor empty={0};
    assert(!md_netlink_attribute_next(&empty,&a));
    empty.size=4; assert(md_netlink_attribute_next(&empty,&a)==-EINVAL);
    /* Every wire length, including unaligned input and missing padding. */
    for (unsigned length=0;length<=UINT16_MAX;++length) {
        struct nlattr h={.nla_len=(uint16_t)length,.nla_type=17|NLA_F_NESTED|NLA_F_NET_BYTEORDER};
        memcpy(bytes+1,&h,sizeof(h));
        size_t span=NLA_ALIGN(length);
        struct md_netlink_cursor cursor={bytes+1,span};
        int result=md_netlink_attribute_next(&cursor,&a);
        if (!length) assert(!result);
        else if (length<sizeof(h)) assert(result==-EINVAL && cursor.size==span);
        else {
            assert(result==1 && !cursor.size && a.type==17 && a.flags==(NLA_F_NESTED|NLA_F_NET_BYTEORDER));
            assert(a.size==length-sizeof(h) && a.data==bytes+1+sizeof(h));
            assert(!md_netlink_attribute_next(&cursor,&a));
            cursor=(struct md_netlink_cursor){bytes+1,span-1};
            assert(md_netlink_attribute_next(&cursor,&a)==-EINVAL && cursor.data==bytes+1 && cursor.size==span-1);
        }
    }
    struct nlattr h={.nla_len=4,.nla_type=1};
    memcpy(bytes,&h,4); memcpy(bytes+4,&h,4);
    struct attribute map[3];
    assert(fields(bytes,4,BIT(1),map,3)==0 && map[1].data==bytes+4 && !map[1].size);
    assert(fields(bytes,8,BIT(1),map,3)==-EINVAL);
    assert(fields(bytes,4,BIT(2),map,3)==-EOPNOTSUPP);
    h.nla_type=2; memcpy(bytes+4,&h,4);
    assert(!fields(bytes,8,BIT(1)|BIT(2),map,3) && map[2].data==bytes+8);
    assert(fields(bytes,9,BIT(1)|BIT(2),map,3)==-EINVAL);
    puts("PASS netlink framing: all 16-bit lengths, unaligned headers, truncation, padding, flags and duplicate policy");
}

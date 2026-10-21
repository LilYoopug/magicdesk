#include "network_generic.h"
#include "netlink_attributes.h"
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>
#include <string.h>

static int lookup(const struct nlmsghdr *h,int dump) {
    const struct genlmsghdr *g=NLMSG_DATA(h);
    if (g->cmd!=CTRL_CMD_GETFAMILY) return -EOPNOTSUPP;
    if (dump) return 0;
    struct md_netlink_cursor cursor={(const char *)g+GENL_HDRLEN,h->nlmsg_len-NLMSG_LENGTH(GENL_HDRLEN)};
    struct md_netlink_attribute a; int result;
    int id=-EINVAL,name=-EINVAL;
    unsigned seen=0;
    while ((result=md_netlink_attribute_next(&cursor,&a))>0) {
        unsigned type=a.type;
        if (type!=CTRL_ATTR_FAMILY_ID && type!=CTRL_ATTR_FAMILY_NAME) return -EOPNOTSUPP;
        if (seen&(1U<<type)) return -EINVAL;
        seen|=1U<<type;
        if (type==CTRL_ATTR_FAMILY_ID) {
            uint16_t value;
            if (a.size!=sizeof(value)) return -EINVAL;
            memcpy(&value,a.data,sizeof(value));
            id=value==GENL_ID_CTRL ? 0 : -ENOENT;
        } else {
            size_t size=a.size;
            const char *value=a.data;
            if (!size || size>GENL_NAMSIZ || value[size-1] || strnlen(value,size)!=size-1) return -EINVAL;
            name=!strcmp(value,"nlctrl") ? 0 : -ENOENT;
        }
    }
    if (result<0) return result;
    return seen&(1U<<CTRL_ATTR_FAMILY_NAME) ? name : id;
}
static int describe(struct md_network_message *out,const struct nlmsghdr *h,uint32_t port,int dump) {
    struct genlmsghdr header={.cmd=CTRL_CMD_NEWFAMILY,.version=2};
    uint16_t id=GENL_ID_CTRL;
    uint32_t version=2,zero=0,maximum=CTRL_ATTR_FAMILY_NAME;
    int error=md_network_message_begin(out,h,port,GENL_ID_CTRL,dump,&header,sizeof(header));
    if (!error) error=md_network_message_attribute(out,CTRL_ATTR_FAMILY_NAME,"nlctrl",7);
    if (!error) error=md_network_message_attribute(out,CTRL_ATTR_FAMILY_ID,&id,sizeof(id));
    if (!error) error=md_network_message_attribute(out,CTRL_ATTR_VERSION,&version,sizeof(version));
    if (!error) error=md_network_message_attribute(out,CTRL_ATTR_HDRSIZE,&zero,sizeof(zero));
    if (!error) error=md_network_message_attribute(out,CTRL_ATTR_MAXATTR,&maximum,sizeof(maximum));
    /* Fixed family metadata is encoded with the same attribute writer as
     * route messages; nested lengths exclude their outer netlink header. */
    union { struct nlmsghdr align; unsigned char bytes[128]; } nested={0};
    struct md_network_message inner={.data=nested.bytes,.capacity=sizeof(nested),.message=&nested.align,.size=NLMSG_HDRLEN};
    uint32_t command=CTRL_CMD_GETFAMILY,flags=GENL_CMD_CAP_DO|GENL_CMD_CAP_DUMP|GENL_CMD_CAP_HASPOL;
    if (!error) error=md_network_message_attribute(&inner,CTRL_ATTR_OP_ID,&command,sizeof(command));
    if (!error) error=md_network_message_attribute(&inner,CTRL_ATTR_OP_FLAGS,&flags,sizeof(flags));
    union { struct nlmsghdr align; unsigned char bytes[144]; } group={0};
    struct md_network_message outer={.data=group.bytes,.capacity=sizeof(group),.message=&group.align,.size=NLMSG_HDRLEN};
    if (!error) error=md_network_message_attribute(&outer,1,nested.bytes+NLMSG_HDRLEN,inner.size-NLMSG_HDRLEN);
    if (!error) error=md_network_message_attribute(out,CTRL_ATTR_OPS,group.bytes+NLMSG_HDRLEN,outer.size-NLMSG_HDRLEN);
    inner.size=outer.size=NLMSG_HDRLEN;
    uint32_t notify=MD_NETWORK_GENERIC_NOTIFY;
    if (!error) error=md_network_message_attribute(&inner,CTRL_ATTR_MCAST_GRP_ID,&notify,sizeof(notify));
    if (!error) error=md_network_message_attribute(&inner,CTRL_ATTR_MCAST_GRP_NAME,"notify",7);
    if (!error) error=md_network_message_attribute(&outer,1,nested.bytes+NLMSG_HDRLEN,inner.size-NLMSG_HDRLEN);
    if (!error) error=md_network_message_attribute(out,CTRL_ATTR_MCAST_GROUPS,group.bytes+NLMSG_HDRLEN,outer.size-NLMSG_HDRLEN);
    return error;
}
long md_network_generic(const struct nlmsghdr *h,size_t size,uint32_t port,int capped,void *data,size_t capacity) {
    if (size<sizeof(*h) || h->nlmsg_len!=size || !(h->nlmsg_flags&NLM_F_REQUEST)) return -EINVAL;
    int dump=(h->nlmsg_flags&NLM_F_DUMP)==NLM_F_DUMP;
    int error=h->nlmsg_type!=GENL_ID_CTRL ? -ENOENT : size<NLMSG_LENGTH(GENL_HDRLEN) ? -EINVAL : lookup(h,dump);
    struct md_network_message out={.data=data,.capacity=capacity};
    if (!error) error=describe(&out,h,port,dump);
    if (error) out.size=0;
    int encoded=md_network_message_done(&out,h,port,error,dump,capped);
    return encoded ? encoded : (long)out.size;
}

#include "network_message.h"
#include <errno.h>
#include <linux/rtnetlink.h>
#include <string.h>

static int append(struct md_network_message *o,const void *data,size_t length) {
    size_t size=NLMSG_ALIGN(length);
    if (size<length || size>o->capacity-o->size) return -EMSGSIZE;
    if (length) memcpy(o->data+o->size,data,length);
    memset(o->data+o->size+length,0,size-length); o->size+=size; return 0;
}
int md_network_message_begin(struct md_network_message *o,const struct nlmsghdr *request,
        uint32_t port,unsigned type,int multi,const void *payload,size_t size) {
    if (size>UINT32_MAX-NLMSG_HDRLEN || NLMSG_SPACE(size)>o->capacity-o->size) return -EMSGSIZE;
    struct nlmsghdr h={.nlmsg_len=NLMSG_LENGTH(size),.nlmsg_type=type,.nlmsg_flags=multi ? NLM_F_MULTI : 0,
        .nlmsg_seq=request->nlmsg_seq,.nlmsg_pid=port};
    o->message=(void *)(o->data+o->size);
    append(o,&h,sizeof(h)); return append(o,payload,size);
}
int md_network_message_attribute(struct md_network_message *o,unsigned type,const void *data,size_t size) {
    if (size>UINT16_MAX-RTA_LENGTH(0) || RTA_SPACE(size)>o->capacity-o->size) return -EMSGSIZE;
    struct rtattr h={.rta_type=type,.rta_len=RTA_LENGTH(size)};
    append(o,&h,sizeof(h)); append(o,data,size);
    o->message->nlmsg_len+=RTA_SPACE(size); return 0;
}
int md_network_message_nest(struct md_network_message *o,unsigned type,size_t *offset) {
    *offset=o->size;
    return md_network_message_attribute(o,type|NLA_F_NESTED,NULL,0);
}
int md_network_message_end_nest(struct md_network_message *o,size_t offset) {
    if (offset>o->size || o->size-offset<sizeof(struct nlattr) || o->size-offset>UINT16_MAX) return -EMSGSIZE;
    struct nlattr *a=(void *)(o->data+offset);
    a->nla_len=(uint16_t)(o->size-offset); return 0;
}
int md_network_message_done(struct md_network_message *o,const struct nlmsghdr *request,
        uint32_t port,int error,int dump,int capped) {
    if (dump && !error) {
        int zero=0; return md_network_message_begin(o,request,port,NLMSG_DONE,1,&zero,sizeof(zero));
    }
    if (error || (request->nlmsg_flags&NLM_F_ACK)) {
        struct nlmsgerr e={.error=error,.msg=*request};
        int result=md_network_message_begin(o,request,port,NLMSG_ERROR,0,&e,sizeof(e));
        if (result) return result;
        if (!error || capped) o->message->nlmsg_flags|=NLM_F_CAPPED;
        else {
            size_t payload=request->nlmsg_len-sizeof(*request);
            result=append(o,NLMSG_DATA(request),payload);
            if (!result) o->message->nlmsg_len+=payload;
        }
        return result;
    }
    return 0;
}

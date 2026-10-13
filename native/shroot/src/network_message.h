#ifndef MD_NETWORK_MESSAGE_H
#define MD_NETWORK_MESSAGE_H
#include <linux/netlink.h>
#include <stddef.h>
#include <stdint.h>

struct md_network_message {
    unsigned char *data;
    size_t size, capacity;
    struct nlmsghdr *message;
};
int md_network_message_begin(struct md_network_message *,const struct nlmsghdr *,uint32_t,
    unsigned,int,const void *,size_t);
int md_network_message_attribute(struct md_network_message *,unsigned,const void *,size_t);
int md_network_message_done(struct md_network_message *,const struct nlmsghdr *,uint32_t,int,int,int);
#endif

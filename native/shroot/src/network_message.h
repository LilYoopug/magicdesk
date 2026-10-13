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
/* Called under the fabric lock. Publication must not block or access guest
 * memory; failure leaves a prepared control-plane mutation uncommitted. */
struct md_network_publication {
    void *context;
    int (*publish)(void *,const void *,size_t);
};
int md_network_message_nest(struct md_network_message *,unsigned,size_t *);
int md_network_message_end_nest(struct md_network_message *,size_t);
int md_network_message_begin(struct md_network_message *,const struct nlmsghdr *,uint32_t,
    unsigned,int,const void *,size_t);
int md_network_message_attribute(struct md_network_message *,unsigned,const void *,size_t);
int md_network_message_done(struct md_network_message *,const struct nlmsghdr *,uint32_t,int,int,int);
#endif

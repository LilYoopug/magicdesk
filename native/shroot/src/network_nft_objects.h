#ifndef MD_NETWORK_NFT_OBJECTS_H
#define MD_NETWORK_NFT_OBJECTS_H
#include "network_filter.h"
#include "network_message.h"
int md_nft_objects(struct md_network_filter *,const struct nlmsghdr *,uint32_t,struct md_network_message *);
int md_nft_emit_expressions(struct md_network_filter *,const struct md_filter_rule *,struct md_network_message *);
#endif

#ifndef MD_NETWORK_NFT_EXPRESSION_H
#define MD_NETWORK_NFT_EXPRESSION_H
#include "network_filter.h"
struct attribute;
struct md_network_message;
int md_nft_compat_supported(unsigned,const char *,unsigned,unsigned);
int md_nft_verdict(struct md_network_filter *,uint64_t,const struct attribute *,struct md_filter_verdict *);
int md_nft_emit_verdict(struct md_network_filter *,uint64_t,const struct md_filter_verdict *,struct md_network_message *);
int md_nft_expressions(struct md_network_filter *,uint64_t,struct md_filter_rule *,const void *,size_t);
#endif

#ifndef MD_NETWORK_NFT_H
#define MD_NETWORK_NFT_H
#include "network_namespace.h"
#include "network_message.h"

/* One complete nfnetlink datagram, including batch begin/end. No partial
 * transaction survives a failed request or a closed control socket. */
long md_network_nft(struct md_network_namespace *,const struct md_identity *,const void *,size_t,
    uint32_t,int,void *,size_t,const struct md_network_publication *);
#endif

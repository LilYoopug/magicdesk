#ifndef MD_NETWORK_GENERIC_H
#define MD_NETWORK_GENERIC_H
#include "network_message.h"

enum { MD_NETWORK_GENERIC_NOTIFY=16 };
/* Only the namespace's implemented generic families are discoverable. No
 * host hardware family or Android control socket is exported to the guest. */
long md_network_generic(const struct nlmsghdr *,size_t,uint32_t,int,void *,size_t);
#endif

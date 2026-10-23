#ifndef MD_NETWORK_AUTOCONF_H
#define MD_NETWORK_AUTOCONF_H
#include "network_internal.h"
/* Fabric lock held. Control-plane updates only, never packet processing. */
int md_network_address_refresh(struct md_network_namespace *,struct md_network_interface *,int64_t);
#endif

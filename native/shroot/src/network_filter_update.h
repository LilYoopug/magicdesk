#ifndef MD_NETWORK_FILTER_UPDATE_H
#define MD_NETWORK_FILTER_UPDATE_H
struct md_network_namespace;
struct md_network_filter;
struct md_network_forward_update;
/* Fabric lock held. Preparation reserves backing ports without publishing a
 * ruleset. The caller can still fail its reply and abort the prepared update.
 * Commit consumes next/update and returns the replaced catalogue. */
int md_network_filter_prepare(struct md_network_namespace *,struct md_network_filter *,struct md_network_forward_update **);
struct md_network_filter *md_network_filter_commit(struct md_network_namespace *,struct md_network_filter *,struct md_network_forward_update *);
#endif

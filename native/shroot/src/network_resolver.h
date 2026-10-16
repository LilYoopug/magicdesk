#ifndef MD_NETWORK_RESOLVER_H
#define MD_NETWORK_RESOLVER_H
struct md_filesystem;
struct md_network_profile;
/* Worker startup only, before publishing the launch's mount namespace. */
int md_network_resolver_prepare(struct md_filesystem *,const struct md_network_profile *);
#endif

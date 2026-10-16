#ifndef MD_NETWORK_LAUNCH_H
#define MD_NETWORK_LAUNCH_H
#include "network_profile.h"
struct md_network_namespace;
struct md_user_namespace;
/* Keeps the private gateway alive without a namespace/fabric reference cycle.
 * The application takes its own reference to space; close releases the launch
 * and its publications after the owned process tree has been reaped. */
struct md_network_launch {
    struct md_network_namespace *gateway, *space;
};
int md_network_launch_open(const struct md_network_profile *,struct md_user_namespace *,struct md_network_launch *);
void md_network_launch_close(struct md_network_launch *);
#endif

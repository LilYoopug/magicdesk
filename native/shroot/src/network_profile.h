#ifndef MD_NETWORK_PROFILE_H
#define MD_NETWORK_PROFILE_H
#include <stdint.h>

enum md_network_policy { MD_NETWORK_HOST, MD_NETWORK_NONE, MD_NETWORK_BRIDGE, MD_NETWORK_BACKEND_ROUTED };
#define MD_NETWORK_PUBLICATIONS_MAX 128
#define MD_NETWORK_DNS_MAX 3
struct md_network_public_port {
    uint32_t address;
    uint16_t host, guest;
    unsigned protocol;
    const char *argument;
};
/* Argument storage is borrowed for the launch lifetime. Wire coordinates are
 * network byte order; parsing is shared with the freestanding runner. */
struct md_network_profile {
    enum md_network_policy policy;
    unsigned selected, count, dns_count;
    struct md_network_public_port ports[MD_NETWORK_PUBLICATIONS_MAX];
    const char *dns[MD_NETWORK_DNS_MAX];
};
int md_network_profile_option(const char *);
int md_network_profile_add(struct md_network_profile *, const char *, const char *);
int md_network_profile_validate(const struct md_network_profile *);
unsigned md_network_profile_arguments(const struct md_network_profile *, char **);
int md_network_profile_ipv4(const char *, uint32_t *);
#endif

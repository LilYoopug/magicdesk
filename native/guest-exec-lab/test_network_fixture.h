#ifndef MD_TEST_NETWORK_FIXTURE_H
#define MD_TEST_NETWORK_FIXTURE_H
#include "network_internal.h"
#include <assert.h>
#include <linux/if_addr.h>
#include <linux/rtnetlink.h>

static inline void test_network_v4(struct md_network_interface *link,uint32_t ip,unsigned prefix) {
    assert(!md_network_interface_address(link,(struct md_network_ip_assignment){.address=md_ip_v4(ip),.prefix=prefix,
        .scope=link->kind==MD_LINK_LOOPBACK ? RT_SCOPE_HOST : RT_SCOPE_UNIVERSE,.flags=IFA_F_PERMANENT},0,0));
}
static inline struct md_network_route_entry *test_network_default(struct md_network_namespace *n,unsigned family) {
    for (unsigned i=0;i<n->route_count;++i) if (!n->routes[i].prefix && n->routes[i].destination.family==family) return &n->routes[i];
    return NULL;
}
#endif

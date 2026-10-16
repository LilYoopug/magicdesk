#include "network_filter_update.h"
#include "network_filter.h"
#include "network_internal.h"
#include "network_endpoint.h"
#include "network_forward.h"

int md_network_filter_prepare(struct md_network_namespace *n,struct md_network_filter *next,
        struct md_network_forward_update **update) {
    int error=md_filter_validate(next);
    if (!error) error=md_network_endpoint_filter_update(n,next);
    if (!error) error=md_network_forward_prepare(n,next,update);
    return error;
}
struct md_network_filter *md_network_filter_commit(struct md_network_namespace *n,
        struct md_network_filter *next,struct md_network_forward_update *update) {
    for (size_t i=0;i<next->chain_count;++i) next->chains[i].id=0;
    for (size_t i=0;i<next->rule_count;++i) next->rules[i].id=0;
    for (size_t i=0;i<next->set_count;++i) next->sets[i].id=0;
    struct md_network_filter *old=n->filter;
    n->filter=next;
    md_network_forward_changed(n->fabric);
    md_network_forward_commit(update);
    return old;
}

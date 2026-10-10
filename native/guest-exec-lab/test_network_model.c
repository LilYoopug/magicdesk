#include "network_internal.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

void test_network_model(void) {
    struct md_network_namespace *root=md_network_namespace_new(NULL,MD_NETWORK_ROUTED);
    assert(root && root->count==2 && root->default_interface);
    struct md_network_namespace *child=md_network_namespace_copy(root,NULL);
    struct md_network_namespace *foreign=md_network_namespace_new(NULL,MD_NETWORK_PRIVATE);
    assert(child && foreign && child->fabric==root->fabric && foreign->fabric!=root->fabric);
    assert(child->count==1 && !child->default_interface && !child->links[0].ipv4);
    unsigned first=0,second=0,bridge=0;
    pthread_mutex_lock(&root->fabric->lock);
    assert(!md_network_interface_add(root,MD_LINK_BRIDGE,"bridge0",&bridge));
    assert(!md_network_interface_add(root,MD_LINK_VETH,"host-end",&first));
    assert(!md_network_interface_add(root,MD_LINK_VETH,"guest-end",&second));
    assert(first!=second && second!=bridge && first!=bridge);
    struct md_network_interface *a=md_network_interface_find(root,first,NULL);
    struct md_network_interface *b=md_network_interface_find(root,second,NULL);
    a->peer=second; a->master=bridge; b->peer=first;
    assert(md_network_interface_move(root,second,foreign,"eth0")==-EXDEV);
    assert(md_network_interface_move(root,second,child,"lo")==-EEXIST);
    assert(md_network_interface_find(root,second,NULL));
    assert(!md_network_interface_move(root,second,child,"eth0"));
    assert(!md_network_interface_find(root,second,NULL));
    assert(md_network_interface_find(child,second,NULL)->peer==first);
    assert(md_network_interface_owner(root->fabric,second)==child);
    assert(md_network_interface_add(root,MD_LINK_BRIDGE,"bad/name",&bridge)==-EINVAL);
    assert(md_network_interface_add(root,MD_LINK_BRIDGE,"bridge0",&bridge)==-EEXIST);
    assert(md_network_interface_remove(child,1)==-EOPNOTSUPP);
    assert(!md_network_interface_remove(root,bridge));
    assert(!md_network_interface_find(root,first,NULL)->master);
    pthread_mutex_unlock(&root->fabric->lock);
    md_network_namespace_release(child);
    pthread_mutex_lock(&root->fabric->lock);
    assert(!md_network_interface_find(root,first,NULL) && root->count==2);
    pthread_mutex_unlock(&root->fabric->lock);
    child=md_network_namespace_copy(root,NULL); assert(child);
    md_network_namespace_release(root);
    struct md_network_link loopback;
    assert(!md_network_link_info(child,1,&loopback) && !strcmp(loopback.name,"lo"));
    md_network_namespace_release(child); md_network_namespace_release(foreign);
    puts("PASS network topology: private births, owned uplink, veth moves, collisions and peer teardown");
}

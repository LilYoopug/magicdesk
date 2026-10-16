#include "network_launch.h"
#include "network_internal.h"
#include "network_filter.h"
#include "network_filter_update.h"
#include "network_forward.h"
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>

static void configure(struct md_network_namespace *n,unsigned index,uint32_t ip,unsigned prefix) {
    struct md_network_interface *link=md_network_interface_find(n,index,NULL);
    link->info.flags|=IFF_UP; link->ipv4=ip; link->prefix=prefix;
}
static int topology(struct md_network_launch *launch) {
    struct md_network_namespace *gateway=launch->gateway,*guest=launch->space;
    unsigned bridge=0,local=0,peer=0;
    int error=md_network_interface_add(gateway,MD_LINK_BRIDGE,"shroot0",&bridge);
    if (!error) error=md_network_interface_add(gateway,MD_LINK_VETH,"veth0",&local);
    if (!error) error=md_network_interface_add(guest,MD_LINK_VETH,"eth0",&peer);
    if (error) return error;
    configure(gateway,bridge,htonl(0x0a580001),24);
    configure(gateway,local,0,0);
    configure(guest,peer,htonl(0x0a580002),24);
    struct md_network_interface *left=md_network_interface_find(gateway,local,NULL);
    struct md_network_interface *right=md_network_interface_find(guest,peer,NULL);
    left->master=bridge; left->peer=peer; right->peer=local;
    guest->default_interface=peer; guest->default_gateway=htonl(0x0a580001);
    /* Published loopback listeners enter through the private bridge. This is
     * scoped to this launch, never a host sysctl change. */
    guest->all.route_localnet=1; gateway->all.route_localnet=1;
    return 0;
}
static void compare(struct md_filter_rule *rule,unsigned size,const void *value) {
    struct md_filter_expression *e=&rule->expressions[rule->count++];
    *e=(struct md_filter_expression){.code=MD_FILTER_COMPARE,.size=size,.operation=NFT_CMP_EQ};
    memcpy(e->value,value,size);
}
static int publications(struct md_network_namespace *gateway,const struct md_network_profile *profile) {
    if (!profile->count) return 0;
    struct md_network_filter *filter=md_network_filter_copy(NULL);
    if (!filter) return -ENOMEM;
    int error=md_network_filter_add(filter,NFPROTO_IPV4,"shroot",NULL,0);
    if (!error) error=md_filter_reserve((void **)&filter->chains,&filter->chain_capacity,1,sizeof(*filter->chains),256);
    if (!error) error=md_filter_reserve((void **)&filter->rules,&filter->rule_capacity,profile->count,sizeof(*filter->rules),1024);
    if (!error) {
        struct md_filter_chain chain={.table=filter->tables[0].handle,.handle=filter->next_handle++,
            .name="publish",.hook=NF_INET_PRE_ROUTING,.priority=-100,.nat=1,.policy=NF_ACCEPT};
        filter->chains[filter->chain_count++]=chain;
        for (unsigned i=0;i<profile->count;++i) {
            const struct md_network_public_port *port=&profile->ports[i];
            struct md_filter_rule *r=&filter->rules[filter->rule_count++];
            *r=(struct md_filter_rule){.chain=chain.handle,.handle=filter->next_handle++};
            r->expressions[r->count++]=(struct md_filter_expression){.code=MD_FILTER_META,.key=NFT_META_L4PROTO,.size=1};
            unsigned char protocol=(unsigned char)port->protocol;
            compare(r,1,&protocol);
            if (port->address) {
                r->expressions[r->count++]=(struct md_filter_expression){.code=MD_FILTER_PAYLOAD,
                    .key=NFT_PAYLOAD_NETWORK_HEADER,.aux=16,.size=4};
                compare(r,4,&port->address);
            }
            r->expressions[r->count++]=(struct md_filter_expression){.code=MD_FILTER_PAYLOAD,
                .key=NFT_PAYLOAD_TRANSPORT_HEADER,.aux=2,.size=2};
            compare(r,2,&port->host);
            struct md_filter_expression *address=&r->expressions[r->count++];
            *address=(struct md_filter_expression){.code=MD_FILTER_IMMEDIATE,.dst=4,.size=4};
            uint32_t destination=htonl(0x0a580002);
            memcpy(address->value,&destination,4);
            struct md_filter_expression *translated=&r->expressions[r->count++];
            *translated=(struct md_filter_expression){.code=MD_FILTER_IMMEDIATE,.dst=8,.size=2};
            memcpy(translated->value,&port->guest,2);
            r->expressions[r->count++]=(struct md_filter_expression){.code=MD_FILTER_NAT,
                .operation=NFT_NAT_DNAT,.key=1,.aux=1,.src=8,.dst=4};
        }
    }
    struct md_network_forward_update *update=NULL;
    if (!error) error=md_network_filter_prepare(gateway,filter,&update);
    if (!error) filter=md_network_filter_commit(gateway,filter,update);
    else md_network_forward_abort(update);
    md_network_filter_free(filter); return error;
}
int md_network_launch_open(const struct md_network_profile *profile,struct md_user_namespace *owner,
        struct md_network_launch *launch) {
    if (!launch || launch->space || launch->gateway) return -EINVAL;
    int error=md_network_profile_validate(profile);
    if (error || profile->policy==MD_NETWORK_HOST) return error;
    if (profile->policy==MD_NETWORK_BRIDGE) {
        launch->gateway=md_network_namespace_new(owner,MD_NETWORK_ROUTED);
        if (!launch->gateway) return -errno;
        launch->space=md_network_namespace_copy(launch->gateway,owner);
    } else launch->space=md_network_namespace_new(owner,
        profile->policy==MD_NETWORK_BACKEND_ROUTED ? MD_NETWORK_ROUTED : MD_NETWORK_PRIVATE);
    if (!launch->space) { error=-errno; md_network_launch_close(launch); return error; }
    struct md_network_fabric *fabric=launch->space->fabric;
    pthread_mutex_lock(&fabric->lock);
    fabric->endpoints_enabled=1;
    configure(launch->space,1,htonl(INADDR_LOOPBACK),8);
    if (launch->gateway) {
        error=topology(launch);
        if (!error) error=publications(launch->gateway,profile);
    }
    pthread_mutex_unlock(&fabric->lock);
    if (error) md_network_launch_close(launch);
    return error;
}
void md_network_launch_close(struct md_network_launch *launch) {
    if (!launch) return;
    md_network_namespace_release(launch->space);
    md_network_namespace_release(launch->gateway);
    *launch=(struct md_network_launch){0};
}

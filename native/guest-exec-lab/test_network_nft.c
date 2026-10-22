#define _GNU_SOURCE
#include "network_nft.h"
#include "network_filter.h"
#include "network_nft_expression.h"
#include "network_nft_objects.h"
#include "network_flow.h"
#include "network_internal.h"
#include "guest_identity.h"
#include <assert.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables_compat.h>
#include <linux/netfilter/nf_nat.h>
#include <linux/netfilter/xt_tcpudp.h>
#include <linux/netfilter/xt_comment.h>
#include <linux/netfilter/xt_conntrack.h>
#include <linux/netfilter/xt_mark.h>
#include <linux/netfilter/xt_addrtype.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

struct packet { _Alignas(struct nlmsghdr) unsigned char data[8192]; };
static struct nlmsghdr *add(struct md_network_message *o,unsigned type,unsigned flags,unsigned family) {
    struct nlmsghdr request={.nlmsg_seq=(unsigned)o->size+1};
    struct nfgenmsg nf={.nfgen_family=family,.version=NFNETLINK_V0};
    if (type==NFNL_MSG_BATCH_BEGIN) nf.res_id=htons(NFNL_SUBSYS_NFTABLES);
    assert(!md_network_message_begin(o,&request,0,type,0,&nf,sizeof(nf)));
    o->message->nlmsg_flags=NLM_F_REQUEST|flags;
    return o->message;
}
static void begin(struct md_network_message *o,uint32_t generation) {
    add(o,NFNL_MSG_BATCH_BEGIN,0,AF_UNSPEC);
    if (generation) {
        generation=htonl(generation);
        assert(!md_network_message_attribute(o,NFNL_BATCH_GENID,&generation,sizeof(generation)));
    }
}
static void end(struct md_network_message *o) { add(o,NFNL_MSG_BATCH_END,0,AF_UNSPEC); }
static struct nlmsghdr *table(struct md_network_message *o,unsigned type,unsigned flags,unsigned family,const char *name) {
    struct nlmsghdr *h=add(o,(NFNL_SUBSYS_NFTABLES<<8)|type,NLM_F_ACK|flags,family);
    if (name) assert(!md_network_message_attribute(o,NFTA_TABLE_NAME,name,strlen(name)+1));
    return h;
}
static long run(struct md_network_namespace *n,const struct md_identity *identity,const struct md_network_message *o,
        struct packet *reply,const struct md_network_publication *publication) {
    memset(reply,0,sizeof(*reply));
    return md_network_nft(n,identity,o->data,o->size,43,0,reply->data,sizeof(reply->data),publication);
}
static int result(struct md_network_namespace *n,const struct md_identity *identity,const struct md_network_message *o) {
    struct packet reply;
    long length=run(n,identity,o,&reply,NULL);
    assert(length>0);
    struct nlmsghdr *h=(void *)reply.data;
    assert(NLMSG_OK(h,length) && h->nlmsg_type==NLMSG_ERROR && h->nlmsg_pid==43);
    return ((struct nlmsgerr *)NLMSG_DATA(h))->error;
}
static int fail_publish(void *context,const void *data,size_t size) {
    (void)context; (void)data; assert(size); return -EAGAIN;
}
static void reverse_policy(void) {
    struct md_network_namespace *n=md_network_namespace_new(NULL,MD_NETWORK_ROUTED);
    assert(n);
    struct md_network_filter_table table={.handle=1,.family=NFPROTO_IPV4};
    struct md_filter_chain chain={.table=1,.handle=2,.hook=NF_INET_LOCAL_IN,.policy=NF_DROP};
    struct md_network_filter filter={.tables=&table,.count=1,.chains=&chain,.chain_count=1};
    n->filter=&filter;
    struct md_filter_packet packet={.destination=htonl(0xc0000201),.destination_port=htons(53),
        .source_port=htons(32800),.protocol=IPPROTO_UDP,.state=8};
    struct md_network_flow_path path;
    assert(!md_network_flow_route(n,&packet,0,&path) && path.mediated);
    assert(!md_network_flow_check(n->fabric,&path,0));
    assert(md_network_flow_check(n->fabric,&path,1)==-EACCES);
    chain.policy=NF_ACCEPT;
    assert(!md_network_flow_route(n,&packet,0,&path) && !path.mediated);
    assert(!md_network_flow_check(n->fabric,&path,1));
    n->filter=NULL;
    md_network_namespace_release(n);
    puts("PASS nft reply policy: outbound native bypass requires both directions to allow IO");
}
static void nat_hook_order(void) {
    struct md_network_namespace *n=md_network_namespace_new(NULL,MD_NETWORK_ROUTED);
    assert(n);
    uint32_t private=htonl(0x0a5c0002),uplink=htonl(0x0a000264);
    struct md_filter_chain chains[4]={
        {.table=1,.handle=2,.hook=NF_INET_POST_ROUTING,.priority=100,.nat=1,.policy=NF_ACCEPT},
        {.table=1,.handle=3,.hook=NF_INET_PRE_ROUTING,.priority=-300,.policy=NF_ACCEPT},
        {.table=1,.handle=4,.hook=NF_INET_PRE_ROUTING,.priority=0,.policy=NF_DROP},
        {.table=1,.handle=5,.hook=NF_INET_POST_ROUTING,.priority=200,.policy=NF_DROP}};
    struct md_filter_rule rules[4]={
        {.chain=2,.count=1,.expressions={{.code=MD_FILTER_MASQUERADE}}},
        {.chain=3,.count=3}, {.chain=4,.count=3}, {.chain=5,.count=3}};
    for (unsigned i=1;i<4;++i) {
        rules[i].expressions[0]=(struct md_filter_expression){.code=MD_FILTER_PAYLOAD,
            .key=NFT_PAYLOAD_NETWORK_HEADER,.aux=i==3 ? 12 : 16,.size=4};
        rules[i].expressions[1]=(struct md_filter_expression){.code=MD_FILTER_COMPARE,.operation=NFT_CMP_EQ,.size=4};
        memcpy(rules[i].expressions[1].value,i==3 ? &uplink : &private,4);
        rules[i].expressions[2]=(struct md_filter_expression){.code=MD_FILTER_VERDICT,.operation=i==1 ? NF_DROP : NF_ACCEPT};
    }
    struct md_network_filter f={.chains=chains,.chain_count=4,.rules=rules,.rule_count=4};
    n->filter=&f;
    for (unsigned transport=0;transport<2;++transport) {
        struct md_filter_packet p={.source=private,.destination=htonl(0xc0000201),.source_port=htons(32000),
            .destination_port=htons(80),.protocol=transport ? IPPROTO_UDP : IPPROTO_TCP,.state=8};
        struct md_network_flow_path path;
        assert(!md_network_flow_route(n,&p,0,&path) && p.snat && p.source==uplink);
        assert(!md_network_flow_check(n->fabric,&path,0));
        assert(!md_network_flow_check(n->fabric,&path,1));
        /* Raw rules must see the real incoming tuple and remain enforceable. */
        memcpy(rules[1].expressions[1].value,&uplink,4);
        assert(md_network_flow_check(n->fabric,&path,1)==-EACCES);
        memcpy(rules[1].expressions[1].value,&private,4);
        /* Even removal of the allocating NAT chain retains this connection's mapping. */
        chains[0].hook=-1;
        ++n->fabric->policy_generation;
        assert(!md_network_flow_check(n->fabric,&path,0));
        assert(!md_network_flow_check(n->fabric,&path,1));
        struct md_filter_accounting accounting={0};
        assert(!md_network_flow_accounting(n->fabric,&path,0,1,&accounting));
        free(accounting.cells);
        chains[0].hook=NF_INET_POST_ROUTING;
        /* Adding NAT after admission cannot retarget the first payload either. */
        chains[0].hook=chains[3].hook=-1;
        p=(struct md_filter_packet){.source=private,.destination=htonl(0xc0000201),
            .source_port=htons(32000),.destination_port=htons(80),
            .protocol=transport ? IPPROTO_UDP : IPPROTO_TCP,.state=8};
        assert(!md_network_flow_route(n,&p,0,&path) && !p.snat);
        chains[0].hook=chains[3].hook=NF_INET_POST_ROUTING;
        memcpy(rules[3].expressions[1].value,&private,4);
        ++n->fabric->policy_generation;
        accounting=(struct md_filter_accounting){0};
        assert(!md_network_flow_accounting(n->fabric,&path,0,1,&accounting));
        free(accounting.cells);
        memcpy(rules[3].expressions[1].value,&uplink,4);
    }
    n->filter=NULL; md_network_namespace_release(n);
    puts("PASS retained NAT hook order: raw wire tuple, reverse translation, post-NAT filter, TCP/UDP and policy changes before first payload");
}
static void native_nat_update(void) {
    struct md_network_namespace *n=md_network_namespace_new(NULL,MD_NETWORK_ROUTED);
    assert(n);
    const int hooks[]={NF_INET_PRE_ROUTING,NF_INET_LOCAL_OUT,NF_INET_POST_ROUTING};
    for (unsigned transport=0;transport<2;++transport) for (unsigned h=0;h<3;++h) {
        struct md_filter_packet packet={.destination=htonl(0xc0000201),.destination_port=htons(80),
            .source_port=htons(32800),.protocol=transport ? IPPROTO_UDP : IPPROTO_TCP,.state=8};
        struct md_network_flow_path path;
        assert(!md_network_flow_route(n,&packet,0,&path) && !path.mediated);
        struct md_filter_chain chains[]={
            {.handle=1,.hook=hooks[h],.nat=1,.policy=NF_ACCEPT,.counters=1},
            {.handle=2,.hook=-1,.policy=NF_ACCEPT},
            {.handle=3,.hook=NF_INET_LOCAL_OUT,.policy=NF_ACCEPT}};
        struct md_filter_rule rules[]={
            {.chain=1,.count=1,.expressions={{.code=MD_FILTER_VERDICT,.operation=NFT_JUMP,.target=2}}},
            {.chain=2,.count=1,.expressions={{.code=MD_FILTER_COUNTER}}},
            {.chain=3,.count=1,.expressions={{.code=MD_FILTER_VERDICT,.operation=NFT_JUMP,.target=2}}}};
        struct md_network_filter filter={.chains=chains,.chain_count=2,.rules=rules,.rule_count=2};
        /* Newly installed NAT counters do not require moving already native
         * streams into a relay; their admitted tuple must not be rewritten. */
        assert(!md_network_flow_admits(n,&filter,&path));
        chains[0].counters=0;
        assert(!md_network_flow_admits(n,&filter,&path));
        chains[0].policy=NF_DROP;
        assert(!md_network_flow_admits(n,&filter,&path));
        struct md_filter_packet first=packet;
        assert(md_filter_evaluate(&filter,hooks[h],&first)==-EACCES);
        chains[0].policy=NF_ACCEPT;
        chains[0].nat=0;
        assert(md_network_flow_admits(n,&filter,&path)==-EBUSY);
        chains[0].nat=1; filter.chain_count=3; filter.rule_count=3;
        /* A regular chain reaching the same counter still requires mediation. */
        assert(md_network_flow_admits(n,&filter,&path)==-EBUSY);
        rules[2].expressions[0]=(struct md_filter_expression){.code=MD_FILTER_VERDICT,.operation=NF_DROP};
        assert(md_network_flow_admits(n,&filter,&path)==-EBUSY);
        assert(!chains[0].counter.packets && !rules[1].expressions[0].counter.packets);
    }
    md_network_namespace_release(n);
    puts("PASS native flow updates: retained NAT in both directions, counters, shared jump chains and filter revocation");
}
static void program(void) {
    struct md_network_filter_table table={.handle=1,.family=NFPROTO_IPV4};
    struct md_filter_chain chains[2]={
        {.table=1,.handle=2,.hook=NF_INET_PRE_ROUTING,.nat=1,.policy=NF_ACCEPT},
        {.table=1,.handle=3,.hook=-1,.policy=NF_ACCEPT}};
    struct md_filter_rule rules[2]={{.chain=2,.count=1},{.chain=3,.count=7}};
    struct md_network_filter f={.tables=&table,.count=1,.chains=chains,.chain_count=2,.rules=rules,.rule_count=2};
    rules[0].expressions[0]=(struct md_filter_expression){.code=MD_FILTER_VERDICT,.operation=NFT_JUMP,.target=3};
    struct md_filter_expression *e=rules[1].expressions;
    e[0]=(struct md_filter_expression){.code=MD_FILTER_PAYLOAD,.key=NFT_PAYLOAD_NETWORK_HEADER,.aux=12,.size=4};
    e[1]=(struct md_filter_expression){.code=MD_FILTER_COMPARE,.operation=NFT_CMP_EQ,.size=4};
    uint32_t source=htonl(0x7f00002a),destination=htonl(0x7f000001);
    memcpy(e[1].value,&source,4);
    e[2]=(struct md_filter_expression){.code=MD_FILTER_PAYLOAD,.key=NFT_PAYLOAD_TRANSPORT_HEADER,.aux=2,.size=2};
    e[3]=(struct md_filter_expression){.code=MD_FILTER_COMPARE,.operation=NFT_CMP_EQ,.size=2};
    uint16_t port=htons(39281); memcpy(e[3].value,&port,2);
    e[4]=(struct md_filter_expression){.code=MD_FILTER_IMMEDIATE,.dst=4,.size=4};
    memcpy(e[4].value,&destination,4);
    e[5]=(struct md_filter_expression){.code=MD_FILTER_IMMEDIATE,.dst=8,.size=2};
    uint16_t translated=htons(39282); memcpy(e[5].value,&translated,2);
    e[6]=(struct md_filter_expression){.code=MD_FILTER_NAT,.operation=NFT_NAT_DNAT,.key=1,.aux=1,.src=8,.dst=4};
    assert(!md_filter_validate(&f));
    struct md_filter_port ports[4]; size_t count=0;
    assert(!md_filter_ports(&f,htonl(0x0a000264),ports,4,&count) && count==2);
    assert(!ports[0].address && ports[0].port==port && !ports[1].address && ports[1].port==port);
    chains[0].hook=NF_INET_LOCAL_OUT;
    assert(!md_filter_validate(&f));
    assert(!md_filter_ports(&f,htonl(0x0a000264),ports,4,&count) && count==2);
    assert(!ports[0].address && ports[0].port==port && !ports[1].address && ports[1].port==port);
    chains[0].hook=NF_INET_PRE_ROUTING;
    struct md_filter_packet packet={.source=source,.destination=htonl(0x0a000264),.destination_port=port,
        .protocol=IPPROTO_TCP,.state=8};
    assert(!md_filter_evaluate(&f,NF_INET_PRE_ROUTING,&packet));
    assert(packet.dnat && packet.destination==destination && packet.destination_port==translated);
    packet.source=htonl(0x7f000001); packet.dnat=0; packet.destination_port=port;
    assert(!md_filter_evaluate(&f,NF_INET_PRE_ROUTING,&packet) && !packet.dnat);
    chains[0].nat=0; assert(md_filter_validate(&f)==-EOPNOTSUPP);
    chains[0].nat=1; chains[0].hook=NF_INET_POST_ROUTING;
    assert(md_filter_validate(&f)==-EOPNOTSUPP);
    chains[0].hook=NF_INET_PRE_ROUTING;
    e[3].code=MD_FILTER_IMMEDIATE;
    assert(md_filter_ports(&f,0,ports,4,&count)==-EOPNOTSUPP);
    rules[1].expressions[0]=(struct md_filter_expression){.code=MD_FILTER_VERDICT,.operation=NFT_JUMP,.target=3};
    assert(md_filter_validate(&f)==-ELOOP);
    rules[1].count=0;
    chains[0].nat=0;
    rules[0].expressions[0].operation=NFT_GOTO;
    assert(!md_filter_validate(&f));
    chains[0].policy=NF_DROP;
    assert(md_filter_evaluate(&f,NF_INET_PRE_ROUTING,&packet)==-EACCES);
    chains[0].policy=NF_ACCEPT;
    assert(!md_filter_evaluate(&f,NF_INET_PRE_ROUTING,&packet));
    rules[0].expressions[0].operation=NFT_RETURN;
    assert(!md_filter_evaluate(&f,NF_INET_PRE_ROUTING,&packet));
    chains[0].policy=NF_DROP;
    assert(md_filter_evaluate(&f,NF_INET_PRE_ROUTING,&packet)==-EACCES);
    puts("PASS nft program: transitive hook validation, cycle rejection, source-dependent finite publication and real tuple evaluation");
}
static void verdict_maps(void) {
    struct md_network_filter_table table={.handle=1,.family=NFPROTO_IPV4};
    struct md_filter_chain chains[2]={
        {.table=1,.handle=2,.hook=NF_INET_LOCAL_IN,.policy=NF_ACCEPT},
        {.table=1,.handle=3,.hook=-1}};
    struct md_filter_element elements[2]={
        {.key="lo",.verdict={NFT_JUMP,3}},
        {.key="eth0",.verdict={NF_DROP,0}}};
    struct md_filter_set set={.table=1,.handle=4,.flags=NFT_SET_MAP,.key_size=16,.data_type=NFT_DATA_VERDICT,
        .elements=elements,.count=2};
    struct md_filter_rule rules[2]={
        {.chain=2,.count=2,.expressions={{.code=MD_FILTER_META,.key=NFT_META_IIFNAME,.size=16},
            {.code=MD_FILTER_VERDICT_MAP,.target=4,.size=16}}},
        {.chain=3,.count=2,.expressions={{.code=MD_FILTER_COUNTER},
            {.code=MD_FILTER_VERDICT,.operation=NFT_RETURN}}}};
    struct md_network_filter f={.tables=&table,.count=1,.chains=chains,.chain_count=2,
        .rules=rules,.rule_count=2,.sets=&set,.set_count=1};
    assert(!md_filter_validate(&f));
    struct md_filter_accounting accounting={0};
    struct md_filter_packet p={.input_name="lo",.state=8,.accounting=&accounting};
    assert(!md_filter_evaluate(&f,NF_INET_LOCAL_IN,&p) && accounting.count==1);
    assert(!rules[1].expressions[0].counter.packets);
    md_filter_account(&accounting,123);
    assert(rules[1].expressions[0].counter.packets==1 && rules[1].expressions[0].counter.bytes==123);
    strcpy(p.input_name,"eth0"); accounting.count=0;
    assert(md_filter_evaluate(&f,NF_INET_LOCAL_IN,&p)==-EACCES && !accounting.count);
    strcpy(p.input_name,"missing"); assert(!md_filter_evaluate(&f,NF_INET_LOCAL_IN,&p));
    rules[1].expressions[1]=(struct md_filter_expression){.code=MD_FILTER_VERDICT_MAP,.target=4,.size=16};
    assert(md_filter_validate(&f)==-ELOOP);
    rules[1].expressions[1]=(struct md_filter_expression){.code=MD_FILTER_MASQUERADE};
    assert(md_filter_validate(&f)==-EOPNOTSUPP);
    free(accounting.cells);
    puts("PASS verdict maps: return, denial, miss, cycle and transitive NAT rejection; explicit counter accounting");
}
static void policy_counters(void) {
    struct md_filter_chain chains[2]={
        {.table=1,.handle=2,.hook=NF_INET_LOCAL_OUT,.policy=NF_ACCEPT,.counters=1},
        {.table=1,.handle=3,.hook=-1}};
    struct md_filter_rule rule={.chain=2,.count=1,.expressions={
        {.code=MD_FILTER_VERDICT,.operation=NFT_GOTO,.target=3}}};
    struct md_network_filter f={.chains=chains,.chain_count=2,.rules=&rule,.rule_count=1};
    struct md_filter_accounting a={0};
    struct md_filter_packet p={.state=8,.accounting=&a};
    assert(!md_filter_evaluate(&f,NF_INET_LOCAL_OUT,&p) && a.count==1);
    md_filter_account(&a,123);
    assert(chains[0].counter.packets==1 && chains[0].counter.bytes==123);
    a.count=0; rule.expressions[0].operation=NF_ACCEPT;
    assert(!md_filter_evaluate(&f,NF_INET_LOCAL_OUT,&p) && !a.count);
    rule.expressions[0].operation=NFT_RETURN;
    chains[0].policy=NF_DROP;
    assert(md_filter_evaluate(&f,NF_INET_LOCAL_OUT,&p)==-EACCES && a.count==1);
    md_filter_account(&a,456);
    assert(chains[0].counter.packets==2 && chains[0].counter.bytes==579);
    a.count=0; rule.expressions[0].operation=NF_DROP;
    assert(md_filter_evaluate(&f,NF_INET_LOCAL_OUT,&p)==-EACCES && !a.count);
    chains[0].nat=1; p.state=2; a.count=0;
    assert(!md_filter_evaluate(&f,NF_INET_LOCAL_OUT,&p) && !a.count);
    free(a.cells);
    puts("PASS base-chain counters: policy fallthrough, goto/return, explicit verdict exclusion and NAT established bypass");
}
static int parse_transport(struct md_network_filter *f,struct md_filter_rule *r,int tcp,unsigned inversion,unsigned flags) {
    struct packet p;
    struct md_network_message o={.data=p.data,.capacity=sizeof(p.data)};
    add(&o,(NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_NEWRULE,0,NFPROTO_IPV4);
    size_t start=o.size;
    size_t entry,data;
    assert(!md_network_message_nest(&o,NFTA_LIST_ELEM,&entry));
    assert(!md_network_message_attribute(&o,NFTA_EXPR_NAME,"match",6));
    assert(!md_network_message_nest(&o,NFTA_EXPR_DATA,&data));
    assert(!md_network_message_attribute(&o,NFTA_MATCH_NAME,tcp ? "tcp" : "udp",4));
    uint32_t revision=0;
    assert(!md_network_message_attribute(&o,NFTA_MATCH_REV,&revision,4));
    unsigned char info[16]={0};
    if (tcp) {
        struct xt_tcp value={.spts={1000,2000},.dpts={4000,4001},.invflags=inversion,.flg_mask=flags};
        memcpy(info,&value,sizeof(value));
    } else {
        struct xt_udp value={.spts={1000,2000},.dpts={4000,4001},.invflags=inversion};
        memcpy(info,&value,sizeof(value));
    }
    assert(!md_network_message_attribute(&o,NFTA_MATCH_INFO,info,sizeof(info)));
    assert(!md_network_message_end_nest(&o,data));
    assert(!md_network_message_end_nest(&o,entry));
    return md_nft_expressions(f,1,r,o.data+start,o.size-start);
}
static void compat_transport(void) {
    struct md_network_filter_table table={.handle=1,.family=NFPROTO_IPV4};
    struct md_filter_chain chain={.table=1,.handle=2,.hook=NF_INET_PRE_ROUTING,.policy=NF_ACCEPT,.nat=1};
    struct md_filter_rule rule={.chain=2};
    struct md_network_filter f={.tables=&table,.count=1,.chains=&chain,.chain_count=1,.rules=&rule,.rule_count=1};
    for (unsigned tcp=0;tcp<2;++tcp) for (unsigned invert=0;invert<4;++invert) {
        assert(md_nft_compat_supported(NFPROTO_IPV4,tcp ? "tcp" : "udp",0,0));
        assert(!parse_transport(&f,&rule,tcp,invert,0) && rule.count==1);
        struct packet dump;
        struct md_network_message out={.data=dump.data,.capacity=sizeof(dump.data)};
        add(&out,(NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_NEWRULE,0,NFPROTO_IPV4);
        size_t start=out.size;
        assert(!md_nft_emit_expressions(&f,&rule,&out));
        assert(out.size==start+NLA_HDRLEN+rule.wire_size && !memcmp(dump.data+start+NLA_HDRLEN,rule.wire,rule.wire_size));
        free(rule.wire); rule.wire=NULL;
        rule.expressions[1]=(struct md_filter_expression){.code=MD_FILTER_NAT,.operation=NFT_NAT_DNAT,
            .constant=1,.aux=1,.value={0,0,0,0,0x13,0x88}};
        rule.count=2;
        for (unsigned src=0;src<2;++src) for (unsigned dst=0;dst<2;++dst) {
            struct md_filter_packet p={.protocol=tcp ? IPPROTO_TCP : IPPROTO_UDP,.state=8,
                .source_port=htons(src ? 1500 : 999),.destination_port=htons(dst ? 4000 : 4002)};
            unsigned match=(src!=!!(invert&1)) && (dst!=!!(invert&2));
            assert(!md_filter_evaluate(&f,NF_INET_PRE_ROUTING,&p) && p.dnat==match);
            if (match) assert(p.destination_port==htons(5000));
            p.protocol=tcp ? IPPROTO_UDP : IPPROTO_TCP; p.dnat=0;
            assert(!md_filter_evaluate(&f,NF_INET_PRE_ROUTING,&p) && !p.dnat);
        }
        struct md_filter_port ports[4]; size_t count=0;
        int error=md_filter_ports(&f,0,ports,4,&count);
        if (invert&2) assert(error==-EOPNOTSUPP);
        else {
            assert(!error && count==2);
            assert(ports[0].protocol==(tcp ? IPPROTO_TCP : IPPROTO_UDP));
            assert(ports[0].port==htons(4000) && ports[1].port==htons(4001));
        }
        memset(&rule,0,sizeof(rule)); rule.chain=2;
    }
    assert(parse_transport(&f,&rule,1,0,2)==-EOPNOTSUPP);
    assert(parse_transport(&f,&rule,0,4,0)==-EOPNOTSUPP);
    assert(!md_nft_compat_supported(NFPROTO_IPV6,"tcp",0,0));
    assert(!md_nft_compat_supported(NFPROTO_IPV4,"udp",1,0));
    assert(!md_nft_compat_supported(NFPROTO_IPV4,"udp",0,1));
    puts("PASS xt TCP/UDP: raw ABI, dump roundtrip, source/destination ranges and inversion, NAT publication and explicit feature rejection");
}
static void compat_nat(void) {
    struct md_network_filter_table table={.handle=1,.family=NFPROTO_IPV4};
    struct md_filter_chain chain={.table=1,.handle=2,.policy=NF_ACCEPT,.nat=1};
    struct md_network_filter f={.tables=&table,.count=1,.chains=&chain,.chain_count=1};
    for (unsigned snat=0;snat<2;++snat) for (unsigned rev=0;rev<3;++rev)
        for (unsigned variant=0;variant<8;++variant) {
            const char *name=snat ? "SNAT" : "DNAT";
            assert(md_nft_compat_supported(NFPROTO_IPV4,name,rev,1));
            chain.hook=snat ? NF_INET_POST_ROUTING : NF_INET_PRE_ROUTING;
            struct nf_nat_range2 r={.flags=NF_NAT_RANGE_MAP_IPS|NF_NAT_RANGE_PROTO_SPECIFIED,
                .min_addr.ip=htonl(0x0a580002),.max_addr.ip=htonl(0x0a580002),
                .min_proto.all=htons(8080),.max_proto.all=htons(8080)};
            if (variant==1) r.flags=NF_NAT_RANGE_MAP_IPS;
            if (variant==2) r.flags=NF_NAT_RANGE_PROTO_SPECIFIED;
            if (variant==3) r.max_addr.ip=htonl(0x0a580003);
            if (variant==4) r.max_proto.all=htons(8081);
            if (variant==5) r.flags|=NF_NAT_RANGE_PROTO_RANDOM;
            if (variant==6) { r.flags|=NF_NAT_RANGE_PROTO_OFFSET; r.base_proto.all=htons(1000); }
            struct nf_nat_ipv4_multi_range_compat r0={.rangesize=1,
                .range={{.flags=r.flags,.min_ip=r.min_addr.ip,.max_ip=r.max_addr.ip,
                    .min=r.min_proto,.max=r.max_proto}}};
            struct nf_nat_range r1={.flags=r.flags,.min_addr=r.min_addr,.max_addr=r.max_addr,
                .min_proto=r.min_proto,.max_proto=r.max_proto};
            unsigned char wire[(sizeof(r)+7)&~(size_t)7]={0};
            size_t size=rev==0 ? sizeof(r0) : rev==1 ? sizeof(r1) : sizeof(r);
            memcpy(wire,rev==0 ? (void *)&r0 : rev==1 ? (void *)&r1 : (void *)&r,size);
            struct packet p;
            struct md_network_message o={.data=p.data,.capacity=sizeof(p.data)};
            add(&o,(NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_NEWRULE,0,NFPROTO_IPV4);
            size_t start=o.size,entry,data;
            assert(!md_network_message_nest(&o,NFTA_LIST_ELEM,&entry));
            assert(!md_network_message_attribute(&o,NFTA_EXPR_NAME,"target",7));
            assert(!md_network_message_nest(&o,NFTA_EXPR_DATA,&data));
            assert(!md_network_message_attribute(&o,NFTA_TARGET_NAME,name,strlen(name)+1));
            uint32_t revision=htonl(rev);
            assert(!md_network_message_attribute(&o,NFTA_TARGET_REV,&revision,4));
            assert(!md_network_message_attribute(&o,NFTA_TARGET_INFO,wire,((size+7)&~(size_t)7)-(variant==7)));
            assert(!md_network_message_end_nest(&o,data));
            assert(!md_network_message_end_nest(&o,entry));
            struct md_filter_rule rule={.chain=2};
            int error=md_nft_expressions(&f,1,&rule,o.data+start,o.size-start);
            if (variant>=3) { assert(error==(variant==7 ? -EINVAL : -EOPNOTSUPP)); continue; }
            assert(!error && rule.count==1 && rule.expressions[0].code==MD_FILTER_NAT);
            f.rules=&rule; f.rule_count=1;
            for (unsigned udp=0;udp<2;++udp) {
                struct md_filter_packet flow={.protocol=udp ? IPPROTO_UDP : IPPROTO_TCP,.state=8,
                    .source=htonl(0xc0000201),.destination=htonl(0xc0000202),
                    .source_port=htons(40000),.destination_port=htons(443)};
                assert(!md_filter_evaluate(&f,chain.hook,&flow));
                assert(snat ? flow.snat : flow.dnat);
                assert((snat ? flow.source : flow.destination)==(variant==2 ? htonl(snat ? 0xc0000201 : 0xc0000202) : r.min_addr.ip));
                assert((snat ? flow.source_port : flow.destination_port)==(variant==1 ? htons(snat ? 40000 : 443) : r.min_proto.all));
            }
            o.size=NLMSG_HDRLEN; o.message=(void *)p.data;
            assert(!md_nft_emit_expressions(&f,&rule,&o));
            struct nlattr *list=(void *)(p.data+NLMSG_HDRLEN);
            struct md_filter_rule copy={.chain=2};
            assert(!md_nft_expressions(&f,1,&copy,list+1,list->nla_len-sizeof(*list)));
            assert(copy.wire_size==rule.wire_size && !memcmp(copy.wire,rule.wire,rule.wire_size));
            assert(copy.count==rule.count && !memcmp(copy.expressions,rule.expressions,rule.count*sizeof(*rule.expressions)));
            free(copy.wire); free(rule.wire); f.rules=NULL; f.rule_count=0;
        }
    puts("PASS xt NAT revisions 0/1/2: TCP/UDP translations, wire roundtrip, unsupported flags/ranges and malformed size");
}
static void compat_masquerade(void) {
    struct md_network_filter_table table={.handle=1,.family=NFPROTO_IPV4};
    struct md_filter_chain chain={.table=1,.handle=2,.hook=NF_INET_POST_ROUTING,.policy=NF_ACCEPT,.nat=1};
    struct md_network_filter f={.tables=&table,.count=1,.chains=&chain,.chain_count=1};
    assert(md_nft_compat_supported(NFPROTO_IPV4,"MASQUERADE",0,1));
    assert(!md_nft_compat_supported(NFPROTO_IPV4,"MASQUERADE",1,1));
    assert(!md_nft_compat_supported(NFPROTO_IPV6,"MASQUERADE",0,1));
    assert(!md_nft_compat_supported(NFPROTO_IPV4,"MASQUERADE",0,0));
    for (unsigned variant=0;variant<4;++variant) {
        struct packet p;
        struct md_network_message o={.data=p.data,.capacity=sizeof(p.data)};
        add(&o,(NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_NEWRULE,0,NFPROTO_IPV4);
        size_t start=o.size,entry,data;
        assert(!md_network_message_nest(&o,NFTA_LIST_ELEM,&entry));
        assert(!md_network_message_attribute(&o,NFTA_EXPR_NAME,"target",7));
        assert(!md_network_message_nest(&o,NFTA_EXPR_DATA,&data));
        assert(!md_network_message_attribute(&o,NFTA_TARGET_NAME,"MASQUERADE",11));
        uint32_t revision=0;
        assert(!md_network_message_attribute(&o,NFTA_TARGET_REV,&revision,4));
        struct nf_nat_ipv4_multi_range_compat info={.rangesize=variant==1 ? 2 : 1};
        if (variant==2) info.range[0].flags=NF_NAT_RANGE_PROTO_SPECIFIED;
        if (variant==3) info.range[0].min_ip=htonl(1);
        unsigned char wire[(sizeof(info)+7)&~(size_t)7];
        memset(wire,0,sizeof(wire)); memcpy(wire,&info,sizeof(info));
        assert(!md_network_message_attribute(&o,NFTA_TARGET_INFO,wire,sizeof(wire)));
        assert(!md_network_message_end_nest(&o,data));
        assert(!md_network_message_end_nest(&o,entry));
        struct md_filter_rule rule={.chain=2};
        int error=md_nft_expressions(&f,1,&rule,o.data+start,o.size-start);
        if (variant) { assert(error==-EOPNOTSUPP); continue; }
        assert(!error && rule.count==1 && rule.expressions[0].code==MD_FILTER_MASQUERADE);
        f.rules=&rule; f.rule_count=1;
        struct md_filter_packet flow={.protocol=IPPROTO_TCP,.state=8,
            .source=htonl(0x0a580002),.destination=htonl(0x08080808),
            .masquerade_address=htonl(0x0a580001)};
        assert(!md_filter_evaluate(&f,NF_INET_POST_ROUTING,&flow));
        assert(flow.masquerade && flow.snat && flow.source==flow.masquerade_address);
        free(rule.wire); f.rules=NULL; f.rule_count=0;
    }
    puts("PASS xt MASQUERADE: shared NAT expression and explicit unsupported range/flag rejection");
}
static void compat_comment(void) {
    struct md_network_filter_table table={.handle=1,.family=NFPROTO_IPV4};
    struct md_network_filter f={.tables=&table,.count=1};
    struct packet p;
    struct md_network_message o={.data=p.data,.capacity=sizeof(p.data)};
    add(&o,(NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_NEWRULE,0,NFPROTO_IPV4);
    size_t start=o.size,entry,data;
    assert(!md_network_message_nest(&o,NFTA_LIST_ELEM,&entry));
    assert(!md_network_message_attribute(&o,NFTA_EXPR_NAME,"match",6));
    assert(!md_network_message_nest(&o,NFTA_EXPR_DATA,&data));
    assert(!md_network_message_attribute(&o,NFTA_MATCH_NAME,"comment",8));
    uint32_t revision=0;
    assert(!md_network_message_attribute(&o,NFTA_MATCH_REV,&revision,4));
    struct xt_comment_info comment={.comment="container forwarding"};
    assert(!md_network_message_attribute(&o,NFTA_MATCH_INFO,&comment,sizeof(comment)));
    assert(!md_network_message_end_nest(&o,data));
    assert(!md_network_message_end_nest(&o,entry));
    struct md_filter_rule rule={0};
    assert(md_nft_compat_supported(NFPROTO_IPV4,"comment",0,0));
    assert(!md_nft_compat_supported(NFPROTO_IPV4,"comment",1,0));
    assert(!md_nft_expressions(&f,1,&rule,o.data+start,o.size-start));
    assert(rule.count==1 && rule.expressions[0].code==MD_FILTER_VERDICT
        && (int)rule.expressions[0].operation==NFT_CONTINUE);
    struct packet dump;
    struct md_network_message out={.data=dump.data,.capacity=sizeof(dump.data)};
    add(&out,(NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_NEWRULE,0,NFPROTO_IPV4);
    start=out.size;
    assert(!md_nft_emit_expressions(&f,&rule,&out));
    assert(out.size==start+NLA_HDRLEN+rule.wire_size
        && !memcmp(dump.data+start+NLA_HDRLEN,rule.wire,rule.wire_size));
    free(rule.wire);
    puts("PASS xt comment: unconditional predicate and exact dump preservation");
}
static void compat_conntrack(void) {
    struct md_network_filter_table table={.handle=1,.family=NFPROTO_IPV4};
    struct md_filter_chain chain={.table=1,.handle=2,.hook=NF_INET_FORWARD,.policy=NF_DROP};
    struct md_network_filter f={.tables=&table,.count=1,.chains=&chain,.chain_count=1};
    assert(md_nft_compat_supported(NFPROTO_IPV4,"conntrack",3,0));
    assert(!md_nft_compat_supported(NFPROTO_IPV4,"conntrack",2,0));
    for (unsigned variant=0;variant<4;++variant) {
        struct packet p;
        struct md_network_message o={.data=p.data,.capacity=sizeof(p.data)};
        add(&o,(NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_NEWRULE,0,NFPROTO_IPV4);
        size_t start=o.size,entry,data;
        assert(!md_network_message_nest(&o,NFTA_LIST_ELEM,&entry));
        assert(!md_network_message_attribute(&o,NFTA_EXPR_NAME,"match",6));
        assert(!md_network_message_nest(&o,NFTA_EXPR_DATA,&data));
        assert(!md_network_message_attribute(&o,NFTA_MATCH_NAME,"conntrack",10));
        uint32_t revision=htonl(3);
        assert(!md_network_message_attribute(&o,NFTA_MATCH_REV,&revision,4));
        struct xt_conntrack_mtinfo3 info={.match_flags=XT_CONNTRACK_STATE,.state_mask=6,
            .invert_flags=variant==1 ? XT_CONNTRACK_STATE : 0};
        if (variant==2) info.match_flags|=XT_CONNTRACK_PROTO;
        if (variant==3) info.state_mask|=XT_CONNTRACK_STATE_SNAT;
        unsigned char wire[(sizeof(info)+7)&~(size_t)7];
        memset(wire,0,sizeof(wire)); memcpy(wire,&info,sizeof(info));
        assert(!md_network_message_attribute(&o,NFTA_MATCH_INFO,wire,sizeof(wire)));
        assert(!md_network_message_end_nest(&o,data));
        assert(!md_network_message_end_nest(&o,entry));
        struct md_filter_rule rule={.chain=2};
        int error=md_nft_expressions(&f,1,&rule,o.data+start,o.size-start);
        if (variant>=2) { assert(error==-EOPNOTSUPP); continue; }
        assert(!error && rule.count==1);
        rule.expressions[rule.count++]=(struct md_filter_expression){.code=MD_FILTER_VERDICT,.operation=NF_ACCEPT};
        f.rules=&rule; f.rule_count=1;
        for (unsigned state=1;state<=8;state<<=1) {
            struct md_filter_packet flow={.state=state};
            int accepted=!!(state&6)!=!!variant;
            assert(md_filter_evaluate(&f,NF_INET_FORWARD,&flow)==(accepted ? 0 : -EACCES));
        }
        free(rule.wire); f.rules=NULL; f.rule_count=0;
    }
    puts("PASS xt conntrack: original state masks, inversion and unsupported selectors rejected");
}
static void compat_mark(void) {
    struct md_network_filter_table table={.handle=1,.family=NFPROTO_IPV4};
    struct md_filter_chain chain={.table=1,.handle=2,.hook=NF_INET_FORWARD,.policy=NF_DROP};
    struct md_network_filter f={.tables=&table,.count=1,.chains=&chain,.chain_count=1};
    assert(md_nft_compat_supported(NFPROTO_IPV4,"MARK",2,1));
    assert(md_nft_compat_supported(NFPROTO_IPV4,"mark",1,0));
    assert(!md_nft_compat_supported(NFPROTO_IPV4,"MARK",0,1));
    for (unsigned variant=0;variant<3;++variant) {
        struct packet p;
        struct md_network_message o={.data=p.data,.capacity=sizeof(p.data)};
        add(&o,(NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_NEWRULE,0,NFPROTO_IPV4);
        size_t start=o.size,entry,data;
        assert(!md_network_message_nest(&o,NFTA_LIST_ELEM,&entry));
        assert(!md_network_message_attribute(&o,NFTA_EXPR_NAME,variant ? "match" : "target",variant ? 6 : 7));
        assert(!md_network_message_nest(&o,NFTA_EXPR_DATA,&data));
        uint32_t revision=htonl(variant ? 1 : 2);
        if (variant) {
            struct xt_mark_mtinfo1 info={.mark=0x2000,.mask=0x2000,.invert=variant==2};
            unsigned char wire[(sizeof(info)+7)&~(size_t)7];
            memset(wire,0,sizeof(wire)); memcpy(wire,&info,sizeof(info));
            assert(!md_network_message_attribute(&o,NFTA_MATCH_NAME,"mark",5));
            assert(!md_network_message_attribute(&o,NFTA_MATCH_REV,&revision,4));
            assert(!md_network_message_attribute(&o,NFTA_MATCH_INFO,wire,sizeof(wire)));
        } else {
            struct xt_mark_tginfo2 info={.mark=0x2001,.mask=0x2000};
            assert(!md_network_message_attribute(&o,NFTA_TARGET_NAME,"MARK",5));
            assert(!md_network_message_attribute(&o,NFTA_TARGET_REV,&revision,4));
            assert(!md_network_message_attribute(&o,NFTA_TARGET_INFO,&info,sizeof(info)));
        }
        assert(!md_network_message_end_nest(&o,data));
        assert(!md_network_message_end_nest(&o,entry));
        struct md_filter_rule rule={.chain=2};
        assert(!md_nft_expressions(&f,1,&rule,o.data+start,o.size-start));
        rule.expressions[rule.count++]=(struct md_filter_expression){.code=MD_FILTER_VERDICT,.operation=NF_ACCEPT};
        f.rules=&rule; f.rule_count=1;
        for (unsigned bit=0;bit<2;++bit) {
            struct md_filter_packet flow={.mark=0x4001|(bit ? 0x2000 : 0)};
            int accepted=!variant || (bit!=(variant==2));
            assert(md_filter_evaluate(&f,NF_INET_FORWARD,&flow)==(accepted ? 0 : -EACCES));
            if (!variant) assert(flow.mark==0x6000);
        }
        free(rule.wire); f.rules=NULL; f.rule_count=0;
    }
    puts("PASS xt mark: masked update, preserved bits, XOR and inverted predicate");
}
static void compat_addrtype(void) {
    struct md_network_filter_table table={.handle=1,.family=NFPROTO_IPV4};
    struct md_filter_chain chain={.table=1,.handle=2,.hook=NF_INET_FORWARD,.policy=NF_DROP};
    struct md_network_filter f={.tables=&table,.count=1,.chains=&chain,.chain_count=1};
    assert(md_nft_compat_supported(NFPROTO_IPV4,"addrtype",1,0));
    assert(!md_nft_compat_supported(NFPROTO_IPV4,"addrtype",0,0));
    for (unsigned variant=0;variant<4;++variant) {
        struct packet p;
        struct md_network_message o={.data=p.data,.capacity=sizeof(p.data)};
        add(&o,(NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_NEWRULE,0,NFPROTO_IPV4);
        size_t start=o.size,entry,data;
        assert(!md_network_message_nest(&o,NFTA_LIST_ELEM,&entry));
        assert(!md_network_message_attribute(&o,NFTA_EXPR_NAME,"match",6));
        assert(!md_network_message_nest(&o,NFTA_EXPR_DATA,&data));
        assert(!md_network_message_attribute(&o,NFTA_MATCH_NAME,"addrtype",9));
        uint32_t revision=htonl(1);
        assert(!md_network_message_attribute(&o,NFTA_MATCH_REV,&revision,4));
        struct xt_addrtype_info_v1 info={.source=XT_ADDRTYPE_UNICAST,.dest=XT_ADDRTYPE_LOCAL,
            .flags=variant==1 ? XT_ADDRTYPE_INVERT_DEST : 0};
        if (variant==2) info.flags|=XT_ADDRTYPE_LIMIT_IFACE_IN;
        if (variant==3) info.dest|=XT_ADDRTYPE_BROADCAST;
        assert(!md_network_message_attribute(&o,NFTA_MATCH_INFO,&info,sizeof(info)));
        assert(!md_network_message_end_nest(&o,data));
        assert(!md_network_message_end_nest(&o,entry));
        struct md_filter_rule rule={.chain=2};
        int error=md_nft_expressions(&f,1,&rule,o.data+start,o.size-start);
        if (variant>=2) { assert(error==-EOPNOTSUPP); continue; }
        assert(!error);
        rule.expressions[rule.count++]=(struct md_filter_expression){.code=MD_FILTER_VERDICT,.operation=NF_ACCEPT};
        f.rules=&rule; f.rule_count=1;
        for (unsigned source=RTN_UNICAST;source<=RTN_LOCAL;++source)
            for (unsigned dest=RTN_UNICAST;dest<=RTN_LOCAL;++dest) {
                struct md_filter_packet flow={.source_fib_type=source,.fib_type=dest};
                int accepted=source==RTN_UNICAST && ((dest==RTN_LOCAL)!=!!variant);
                assert(md_filter_evaluate(&f,NF_INET_FORWARD,&flow)==(accepted ? 0 : -EACCES));
            }
        free(rule.wire); f.rules=NULL; f.rule_count=0;
    }
    puts("PASS xt addrtype: shared route classification and unsupported scopes rejected");
}
static void compat_revisions(void) {
    struct md_network_namespace *n=md_network_namespace_new(NULL,MD_NETWORK_ROUTED);
    struct md_identity root=md_identity_new(0,0);
    assert(n);
    const char *names[]={"DNAT","SNAT","MASQUERADE","MARK","tcp","udp","comment","mark","addrtype","conntrack"};
    unsigned revisions[]={0,0,0,2,0,0,0,1,1,3};
    for (unsigned i=0;i<sizeof(names)/sizeof(*names);++i) for (unsigned variant=0;variant<4;++variant) {
        struct packet p,reply;
        struct md_network_message o={.data=p.data,.capacity=sizeof(p.data)};
        unsigned family=variant==3 ? NFPROTO_IPV6 : NFPROTO_IPV4;
        const char *name=variant==2 ? "unknown" : names[i];
        uint32_t revision=htonl(variant==1 ? 32 : revisions[i]),target=htonl(i<4);
        add(&o,(NFNL_SUBSYS_NFT_COMPAT<<8)|NFNL_MSG_COMPAT_GET,NLM_F_ACK,family);
        assert(!md_network_message_attribute(&o,NFTA_COMPAT_NAME,name,strlen(name)+1));
        assert(!md_network_message_attribute(&o,NFTA_COMPAT_REV,&revision,4));
        assert(!md_network_message_attribute(&o,NFTA_COMPAT_TYPE,&target,4));
        if (variant) assert(result(n,&root,&o)==(variant==1 ? -EPROTONOSUPPORT : -ENOENT));
        else {
            long size=run(n,&root,&o,&reply,NULL);
            struct nlmsghdr *h=(void *)reply.data;
            assert(NLMSG_OK(h,size) && h->nlmsg_type==((NFNL_SUBSYS_NFT_COMPAT<<8)|NFNL_MSG_COMPAT_GET));
            h=NLMSG_NEXT(h,size);
            assert(NLMSG_OK(h,size) && h->nlmsg_type==NLMSG_ERROR && !((struct nlmsgerr *)NLMSG_DATA(h))->error);
        }
    }
    md_identity_release(&root); md_network_namespace_release(n);
    puts("PASS xt revision negotiation: absent extension differs from unsupported revision");
}
void test_network_nft(void) {
    compat_revisions();
    compat_transport();
    compat_nat();
    compat_masquerade();
    compat_comment();
    compat_conntrack();
    compat_mark();
    compat_addrtype();
    program();
    verdict_maps();
    policy_counters();
    reverse_policy();
    nat_hook_order();
    native_nat_update();
    struct md_network_namespace *n=md_network_namespace_new(NULL,MD_NETWORK_ROUTED);
    struct md_network_namespace *child=md_network_namespace_copy(n,NULL);
    struct md_identity root=md_identity_new(0,0),user=md_identity_new(1000,1000);
    struct packet p,reply;
    struct md_network_message o={.data=p.data,.capacity=sizeof(p.data)};
    assert(n && child && !n->filter && md_network_filter_generation(n->filter)==1);

    add(&o,(NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_GETGEN,0,AF_UNSPEC);
    assert(result(n,&user,&o)==-EPERM);
    long length=run(n,&root,&o,&reply,NULL);
    struct nlmsghdr *h=(void *)reply.data;
    assert(length>0 && h->nlmsg_type==((NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_NEWGEN));
    assert(ntohs(((struct nfgenmsg *)NLMSG_DATA(h))->res_id)==1);
    struct nlattr *a=(void *)((struct nfgenmsg *)NLMSG_DATA(h)+1);
    uint32_t generation; memcpy(&generation,a+1,sizeof(generation));
    assert(a->nla_type==NFTA_GEN_ID && ntohl(generation)==1);

    o.size=0; table(&o,NFT_MSG_GETTABLE,NLM_F_DUMP,AF_UNSPEC,NULL);
    length=run(n,&root,&o,&reply,NULL); h=(void *)reply.data;
    assert(length>0 && h->nlmsg_type==NLMSG_DONE);
    o.size=0; table(&o,NFT_MSG_NEWTABLE,NLM_F_CREATE,NFPROTO_INET,"test");
    assert(result(n,&root,&o)==-EINVAL && !n->filter);
    o.size=0; begin(&o,1);
    table(&o,NFT_MSG_NEWTABLE,NLM_F_CREATE|NLM_F_EXCL,NFPROTO_INET,"test");
    end(&o);
    assert(result(n,&user,&o)==-EPERM && !n->filter);
    struct md_network_publication refusal={.publish=fail_publish};
    assert(run(n,&root,&o,&reply,&refusal)==-EAGAIN && !n->filter);
    assert(md_network_nft(n,&root,o.data,o.size,43,0,reply.data,0,NULL)==-EMSGSIZE && !n->filter);
    assert(!result(n,&root,&o));
    assert(n->filter && n->filter->count==1 && n->filter->generation==2);
    assert(n->filter->tables[0].handle==1 && !child->filter);
    assert(result(n,&root,&o)==-ERESTART && n->filter->generation==2);

    o.size=0; begin(&o,2);
    table(&o,NFT_MSG_NEWTABLE,NLM_F_CREATE,NFPROTO_IPV4,"second");
    table(&o,NFT_MSG_NEWTABLE,NLM_F_CREATE|NLM_F_EXCL,NFPROTO_INET,"test");
    end(&o);
    assert(result(n,&root,&o)==-EEXIST && n->filter->count==1 && n->filter->next_handle==2);
    o.size=0; begin(&o,2);
    table(&o,NFT_MSG_NEWTABLE,NLM_F_CREATE,NFPROTO_IPV4,"second");
    assert(result(n,&root,&o)==-EINVAL && n->filter->count==1);
    end(&o);
    assert(!result(n,&root,&o) && n->filter->count==2 && n->filter->generation==3);

    o.size=0; table(&o,NFT_MSG_GETTABLE,NLM_F_DUMP,AF_UNSPEC,NULL);
    length=run(n,&root,&o,&reply,NULL); h=(void *)reply.data;
    assert(length>0 && h->nlmsg_type==((NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_NEWTABLE));
    assert(h->nlmsg_flags&NLM_F_MULTI);
    h=NLMSG_NEXT(h,length);
    assert(NLMSG_OK(h,length) && h->nlmsg_type==((NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_NEWTABLE));
    h=NLMSG_NEXT(h,length);
    assert(NLMSG_OK(h,length) && h->nlmsg_type==NLMSG_DONE);
    length=run(child,&root,&o,&reply,NULL); h=(void *)reply.data;
    assert(length>0 && h->nlmsg_type==NLMSG_DONE);

    o.size=0; begin(&o,3);
    table(&o,NFT_MSG_DELTABLE,0,NFPROTO_INET,"test");
    add(&o,(NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_NEWFLOWTABLE,NLM_F_CREATE|NLM_F_ACK,NFPROTO_INET);
    end(&o);
    assert(result(n,&root,&o)==-EOPNOTSUPP && n->filter->count==2 && n->filter->generation==3);
    o.size=0; begin(&o,3); table(&o,NFT_MSG_DELTABLE,0,AF_UNSPEC,NULL); end(&o);
    assert(!result(n,&root,&o) && !n->filter->count && n->filter->generation==4);

    o.size=0; begin(&o,4);
    table(&o,NFT_MSG_NEWTABLE,NLM_F_CREATE,NFPROTO_INET,"test");
    assert(!md_network_message_attribute(&o,NFTA_TABLE_NAME,"duplicate",10));
    end(&o);
    assert(result(n,&root,&o)==-EINVAL && !n->filter->count);
    o.size=0; begin(&o,4);
    table(&o,NFT_MSG_NEWTABLE,NLM_F_CREATE,NFPROTO_INET,"test");
    uint32_t flags=htonl(NFT_TABLE_F_DORMANT);
    assert(!md_network_message_attribute(&o,NFTA_TABLE_FLAGS,&flags,sizeof(flags)));
    end(&o);
    assert(result(n,&root,&o)==-EOPNOTSUPP && !n->filter->count);

    /* Large batches use the same transaction, not a 4 KiB per-message limit. */
    o.size=0; begin(&o,4);
    for (int i=0;i<150;++i) {
        char name[32]; snprintf(name,sizeof(name),"table-%d",i);
        table(&o,NFT_MSG_NEWTABLE,NLM_F_CREATE,NFPROTO_INET,name);
    }
    end(&o); assert(o.size>4096);
    assert(!result(n,&root,&o) && n->filter->count==150);

    /* Mutation echoes and subsequent queries expose the same wrapped generation. */
    n->filter->generation=UINT32_MAX;
    o.size=0; begin(&o,UINT32_MAX);
    table(&o,NFT_MSG_NEWTABLE,NLM_F_CREATE|NLM_F_EXCL|NLM_F_ECHO,NFPROTO_INET,"wrapped");
    end(&o);
    length=run(n,&root,&o,&reply,NULL); h=(void *)reply.data;
    assert(length>0 && h->nlmsg_type==((NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_NEWTABLE));
    assert(ntohs(((struct nfgenmsg *)NLMSG_DATA(h))->res_id)==1 && n->filter->generation==1);
    assert(result(n,&root,&o)==-ERESTART && n->filter->generation==1);
    o.size=0; add(&o,(NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_GETGEN,0,AF_UNSPEC);
    length=run(n,&root,&o,&reply,NULL); h=(void *)reply.data;
    assert(length>0 && ntohs(((struct nfgenmsg *)NLMSG_DATA(h))->res_id)==1);
    a=(void *)((struct nfgenmsg *)NLMSG_DATA(h)+1);
    memcpy(&generation,a+1,sizeof(generation));
    assert(a->nla_type==NFTA_GEN_ID && ntohl(generation)==1);

    /* Kernel queue framing and capabilities are identical to the other netlink
     * owners, including poll readiness and retained creation namespace. */
    struct md_fd_object *socket=NULL; int fd=-1;
    assert(!md_network_socket_open(child,&root,AF_NETLINK,SOCK_RAW,NETLINK_NETFILTER,&socket,&fd));
    o.size=0; add(&o,(NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_GETGEN,0,AF_UNSPEC);
    unsigned long args[6]={0};
    assert(md_network_socket_call(socket,&root,SYS_sendto,args,o.data,o.capacity,o.size,92,0,NULL,NULL)==(long)o.size);
    struct { struct md_network_packet envelope; struct packet payload; } received;
    /* EVENT_WAIT: the queued response must arrive within the fixture alarm. */
    assert(read(fd,&received,sizeof(received))>0 && !received.envelope.group);
    h=(void *)((char *)&received+sizeof(struct md_network_packet));
    assert(h->nlmsg_type==((NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_NEWGEN) && h->nlmsg_pid==92);
    close(fd); md_fd_object_release(socket);
    md_identity_release(&root); md_identity_release(&user);
    md_network_namespace_release(child); md_network_namespace_release(n);
    puts("PASS nftables: isolated catalogue, generation, atomic batches, rollback, permissions, explicit unsupported operations and netlink carrier");
}

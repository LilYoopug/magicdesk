#define _GNU_SOURCE
#include "network_nft.h"
#include "network_filter.h"
#include "network_flow.h"
#include "network_internal.h"
#include "guest_identity.h"
#include <assert.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
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
void test_network_nft(void) {
    program();
    reverse_policy();
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
    assert(!md_network_socket_open(child,AF_NETLINK,SOCK_RAW,NETLINK_NETFILTER,&socket,&fd));
    o.size=0; add(&o,(NFNL_SUBSYS_NFTABLES<<8)|NFT_MSG_GETGEN,0,AF_UNSPEC);
    unsigned long args[6]={0};
    assert(md_network_socket_call(socket,&root,SYS_sendto,args,o.data,o.capacity,o.size,92,NULL)==(long)o.size);
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

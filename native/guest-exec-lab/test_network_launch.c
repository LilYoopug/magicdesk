#define _GNU_SOURCE
#include "network_launch.h"
#include "guest_identity.h"
#include "network_internal.h"
#include "network_endpoint.h"
#include "network_flow.h"
#include "network_filter.h"
#include "network_forward.h"
#include "network_nft_objects.h"
#include "network_nft_expression.h"
#include <assert.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned reserve(int *fd) {
    *fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); assert(*fd>=0);
    struct sockaddr_in a={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    assert(!bind(*fd,(void *)&a,sizeof(a)));
    socklen_t size=sizeof(a); assert(!getsockname(*fd,(void *)&a,&size));
    return ntohs(a.sin_port);
}
static struct md_network_profile bridge(void) {
    struct md_network_profile p={0};
    assert(!md_network_profile_add(&p,"--network","bridge")); return p;
}
static void parsing(void) {
    struct md_network_profile p={0};
    assert(!md_network_profile_validate(&p) && !md_network_profile_arguments(&p,NULL));
    assert(!md_network_profile_add(&p,"-p","127.0.0.1:8080:80/tcp"));
    assert(md_network_profile_validate(&p)==-EINVAL);
    assert(!md_network_profile_add(&p,"--network","bridge"));
    assert(!md_network_profile_add(&p,"--publish","8080:53/udp"));
    assert(!md_network_profile_add(&p,"--dns","192.0.2.53"));
    assert(!md_network_profile_validate(&p));
    assert(md_network_profile_add(&p,"-p","8080:81/tcp")==-EADDRINUSE);
    assert(md_network_profile_add(&p,"--network","host")==-EEXIST);
    assert(md_network_profile_add(&p,"--dns","127.0.0.53")==-EADDRNOTAVAIL);
    assert(md_network_profile_add(&p,"--dns","192.0.2.53")==-EEXIST);
    const char *bad[]={"80","0:80","80:0","65536:80","1:999999999999999",":80","80:",
        "127.0.0.256:80:80","127.0.0:80:80","127.0.0.1.:80:80","1:2/sctp","[::1]:80:80","-1:80","1:2/udp/extra"};
    for (unsigned i=0;i<sizeof(bad)/sizeof(*bad);++i) assert(md_network_profile_add(&p,"-p",bad[i])<0);
    char *args[2*(1+MD_NETWORK_PUBLICATIONS_MAX+MD_NETWORK_DNS_MAX)];
    unsigned count=md_network_profile_arguments(&p,args);
    assert(count==md_network_profile_arguments(&p,NULL));
    struct md_network_profile copy={0};
    for (unsigned i=0;i<count;i+=2) assert(!md_network_profile_add(&copy,args[i],args[i+1]));
    assert(!md_network_profile_validate(&copy) && copy.count==p.count && copy.dns_count==p.dns_count);
    assert(copy.ports[0].host==htons(8080) && copy.ports[0].guest==htons(80));
    puts("PASS launch network grammar, conflicts, DNS and argument round trip");
}
static void routes(void) {
    struct md_network_launch a={0},b={0};
    struct md_network_profile p={0};
    assert(!md_network_launch_open(&p,NULL,&a) && !a.space && !a.gateway);
    assert(!md_network_profile_add(&p,"--network","none"));
    assert(!md_network_launch_open(&p,NULL,&a));
    assert(md_network_endpoint_enabled(a.space) && a.space->count==1 && !a.gateway);
    struct md_filter_packet packet={.destination=htonl(0xc0000201),.destination_port=htons(80),.protocol=6};
    struct md_network_flow_path path;
    assert(md_network_flow_route(a.space,&packet,0,&path)==-ENETUNREACH);
    packet.destination=htonl(INADDR_LOOPBACK);
    assert(!md_network_flow_route(a.space,&packet,0,&path) && path.destination==a.space->inode && !path.mediated);
    md_network_launch_close(&a);
    p=bridge();
    assert(!md_network_launch_open(&p,NULL,&a));
    assert(!md_network_launch_open(&p,NULL,&b));
    assert(a.space->fabric!=b.space->fabric && a.space->mode==MD_NETWORK_PRIVATE);
    assert(a.space->count==2 && a.gateway->count==4);
    packet=(struct md_filter_packet){.destination=htonl(0xc0000201),.destination_port=htons(80),.protocol=6};
    assert(!md_network_flow_route(a.space,&packet,0,&path));
    assert(!path.mediated && !path.destination && packet.source==htonl(0x0a580002));
    struct md_fd_object *sa=NULL,*sb=NULL; int fa=-1,fb=-1;
    struct md_identity identity=md_identity_new(0,0);
    struct sockaddr_in local={.sin_family=AF_INET,.sin_port=htons(80)};
    assert(!md_network_endpoint_open(a.space,0,AF_INET,SOCK_STREAM,0,&sa,&fa));
    assert(!md_network_endpoint_open(b.space,0,AF_INET,SOCK_STREAM,0,&sb,&fb));
    assert(!md_network_endpoint_bind(sa,fa,&identity,(void *)&local,sizeof(local)));
    assert(!md_network_endpoint_bind(sb,fb,&identity,(void *)&local,sizeof(local)));
    close(fa); close(fb); md_fd_object_release(sa); md_fd_object_release(sb);
    md_identity_release(&identity);
    md_network_launch_close(&a); md_network_launch_close(&b);
    puts("PASS host no-op, offline loopback, private bridge and unmediated outbound flow");
}
static void ports(void) {
    int held=-1; unsigned number=reserve(&held);
    char text[64]; snprintf(text,sizeof(text),"127.0.0.1:%u:80/tcp",number);
    struct md_network_profile p=bridge();
    assert(!md_network_profile_add(&p,"-p",text));
    struct md_network_launch a={0},b={0};
    assert(md_network_launch_open(&p,NULL,&a)==-EADDRINUSE && !a.space && !a.gateway);
    close(held);
    assert(!md_network_launch_open(&p,NULL,&a));
    assert(md_network_launch_open(&p,NULL,&b)==-EADDRINUSE && !b.space && !b.gateway);
    struct md_filter_packet packet={.source=htonl(INADDR_LOOPBACK),.source_port=htons(40000),
        .destination=htonl(INADDR_LOOPBACK),.destination_port=htons(number),.protocol=6,.state=8};
    struct md_network_flow_path path;
    assert(!md_network_flow_route(a.gateway,&packet,1,&path));
    assert(path.mediated && path.destination==a.space->inode && packet.destination==htonl(0x0a580002)
        && packet.destination_port==htons(80));
    packet=(struct md_filter_packet){.source=htonl(INADDR_LOOPBACK),.source_port=htons(40000),
        .destination=htonl(INADDR_LOOPBACK),.destination_port=htons(number),.protocol=6,.state=8};
    assert(!md_network_flow_route(a.gateway,&packet,0,&path));
    assert(path.steps[0].hook==NF_INET_LOCAL_OUT && path.destination==a.space->inode
        && packet.destination==htonl(0x0a580002) && packet.destination_port==htons(80));
    unsigned char bytes[4096]={0};
    struct md_network_message output={.data=bytes,.capacity=sizeof(bytes),.size=NLMSG_HDRLEN,.message=(void *)bytes};
    struct md_filter_rule *rule=&a.gateway->filter->rules[0];
    assert(!md_nft_emit_expressions(a.gateway->filter,rule,&output));
    const struct nlattr *list=(void *)(bytes+NLMSG_HDRLEN);
    struct md_filter_rule roundtrip={0};
    assert(!md_nft_expressions(a.gateway->filter,a.gateway->filter->tables[0].handle,&roundtrip,
        list+1,list->nla_len-sizeof(*list)));
    assert(roundtrip.count==rule->count && !memcmp(roundtrip.expressions,rule->expressions,
        rule->count*sizeof(*rule->expressions)));
    free(roundtrip.wire);
    md_network_launch_close(&a);
    assert(!md_network_launch_open(&p,NULL,&b));
    md_network_launch_close(&b);
    p=bridge();
    snprintf(text,sizeof(text),"0.0.0.0:%u:80/tcp",number);
    assert(!md_network_profile_add(&p,"-p",text));
    assert(!md_network_launch_open(&p,NULL,&a));
    struct md_network_interface *inside=md_network_interface_find(a.space,0,"eth0");
    struct md_network_interface *port=md_network_interface_find(a.gateway,inside->peer,NULL);
    struct md_filter_packet reflect={.source=htonl(0x0a580002),.source_port=htons(40000),
        .destination=htonl(0x0a580001),.destination_port=htons(number),.protocol=6,.state=8};
    packet=reflect;
    assert(md_network_flow_route(a.space,&packet,0,&path)==-EACCES);
    port->hairpin=1; packet=reflect;
    assert(!md_network_flow_route(a.space,&packet,0,&path));
    assert(path.mediated && path.destination==a.space->inode);
    assert(!md_network_flow_check(a.space->fabric,&path,0));
    assert(!md_network_flow_check(a.space->fabric,&path,1));
    port->hairpin=0;
    assert(md_network_flow_check(a.space->fabric,&path,0)==-EACCES);
    assert(md_network_flow_check(a.space->fabric,&path,1)==-EACCES);
    md_network_launch_close(&a);
    puts("PASS launch NAT, typed nft round trip, occupied-port rollback and release");
}
static void partial_rollback(void) {
    int first=-1,last=-1;
    unsigned available=reserve(&first),occupied=reserve(&last);
    char ports[2][64];
    snprintf(ports[0],sizeof(ports[0]),"127.0.0.1:%u:80",available);
    snprintf(ports[1],sizeof(ports[1]),"127.0.0.1:%u:81",occupied);
    struct md_network_profile p=bridge();
    for (unsigned i=0;i<2;++i) assert(!md_network_profile_add(&p,"-p",ports[i]));
    close(first);
    struct md_network_launch launch={0};
    assert(md_network_launch_open(&p,NULL,&launch)==-EADDRINUSE && !launch.space && !launch.gateway);
    first=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); assert(first>=0);
    struct sockaddr_in a={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK),.sin_port=htons(available)};
    assert(!bind(first,(void *)&a,sizeof(a)));
    close(first); close(last);
    assert(!md_network_launch_open(&p,NULL,&launch));
    md_network_launch_close(&launch);
    puts("PASS partial multi-port reservation rollback and retry");
}
static void port_state(const struct sockaddr_in *address,int listening) {
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); assert(fd>=0);
    struct timeval timeout={.tv_sec=2};
    assert(!setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout)));
    /* EVENT_WAIT: native TCP handshake; a timeout is a failed assertion. */
    int r=connect(fd,(const void *)address,sizeof(*address));
    assert(listening ? !r : r==-1 && errno==ECONNREFUSED);
    close(fd);
    fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); assert(fd>=0);
    assert(bind(fd,(const void *)address,sizeof(*address))==-1 && errno==EADDRINUSE);
    close(fd);
}
static void reserved_publication(void) {
    struct md_network_namespace *n=md_network_namespace_new(NULL,MD_NETWORK_ROUTED);
    assert(n);
    int held=-1,token=0;
    unsigned number=reserve(&held); close(held);
    struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK),.sin_port=htons(number)};
    struct md_network_filter_table table={.handle=1,.family=NFPROTO_IPV4};
    struct md_filter_chain chain={.table=1,.handle=2,.hook=NF_INET_PRE_ROUTING,.nat=1,.policy=NF_ACCEPT};
    struct md_filter_rule rule={.chain=2,.count=8};
    struct md_filter_expression *e=rule.expressions;
    e[0]=(struct md_filter_expression){.code=MD_FILTER_PAYLOAD,.key=NFT_PAYLOAD_NETWORK_HEADER,.aux=16,.size=4};
    e[1]=(struct md_filter_expression){.code=MD_FILTER_COMPARE,.operation=NFT_CMP_EQ,.size=4};
    memcpy(e[1].value,&address.sin_addr.s_addr,4);
    e[2]=(struct md_filter_expression){.code=MD_FILTER_META,.key=NFT_META_L4PROTO,.size=1};
    e[3]=(struct md_filter_expression){.code=MD_FILTER_COMPARE,.operation=NFT_CMP_EQ,.size=1,.value={IPPROTO_TCP}};
    e[4]=(struct md_filter_expression){.code=MD_FILTER_PAYLOAD,.key=NFT_PAYLOAD_TRANSPORT_HEADER,.aux=2,.size=2};
    e[5]=(struct md_filter_expression){.code=MD_FILTER_COMPARE,.operation=NFT_CMP_EQ,.size=2};
    memcpy(e[5].value,&address.sin_port,2);
    e[6]=(struct md_filter_expression){.code=MD_FILTER_IMMEDIATE,.dst=4,.size=4};
    memcpy(e[6].value,&address.sin_addr.s_addr,4);
    e[7]=(struct md_filter_expression){.code=MD_FILTER_NAT,.operation=NFT_NAT_DNAT,.key=1,.dst=4};
    struct md_network_filter f={.tables=&table,.count=1,.chains=&chain,.chain_count=1,.rules=&rule,.rule_count=1};
    struct md_network_port_reservation *reservation=NULL;
    struct md_network_forward_update *update=NULL;
    pthread_mutex_lock(&n->fabric->lock);
    assert(!md_network_forward_bind(n,&token,SOCK_STREAM,&address,&reservation));
    md_network_forward_bound(reservation,1);
    port_state(&address,0);
    assert(!md_network_forward_prepare(n,&f,&update));
    md_network_forward_abort(update);
    port_state(&address,0);
    int occupied=-1;
    unsigned busy=reserve(&occupied);
    struct md_filter_rule rules[2]={rule,rule};
    uint16_t port=htons(busy);
    memcpy(rules[1].expressions[5].value,&port,2);
    f.rules=rules; f.rule_count=2;
    assert(md_network_forward_prepare(n,&f,&update)==-EADDRINUSE && !update);
    port_state(&address,0);
    close(occupied); f.rules=&rule; f.rule_count=1;
    for (unsigned i=0;i<3;++i) {
        assert(!md_network_forward_prepare(n,&f,&update));
        md_network_forward_commit(update);
        port_state(&address,1);
        assert(!md_network_forward_prepare(n,NULL,&update));
        md_network_forward_commit(update);
        port_state(&address,0);
    }
    assert(!md_network_forward_prepare(n,&f,&update));
    md_network_forward_commit(update);
    assert(!md_network_forward_listen(n,&token,4));
    assert(!md_network_forward_prepare(n,NULL,&update));
    md_network_forward_commit(update);
    port_state(&address,1);
    md_network_forward_endpoint_closed(n,&token);
    /* A guest may reserve a port after NAT publication, then outlive it. */
    assert(!md_network_forward_prepare(n,&f,&update));
    md_network_forward_commit(update);
    assert(!md_network_forward_bind(n,&token,SOCK_STREAM,&address,&reservation));
    md_network_forward_bound(reservation,1);
    assert(!md_network_forward_prepare(n,NULL,&update));
    md_network_forward_commit(update);
    port_state(&address,0);
    md_network_forward_endpoint_closed(n,&token);
    pthread_mutex_unlock(&n->fabric->lock);
    md_network_namespace_release(n);
    held=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); assert(held>=0);
    assert(!bind(held,(const void *)&address,sizeof(address))); close(held);
    puts("PASS bound-only TCP: NAT admission, abort, removal, guest listen, late bind and port release");
}
static void loopback_origin(void) {
    for (unsigned udp=0;udp<2;++udp) {
        int type=udp ? SOCK_DGRAM : SOCK_STREAM;
        struct md_network_namespace *n=md_network_namespace_new(NULL,MD_NETWORK_ROUTED);
        assert(n);
        struct md_identity root=md_identity_new(0,0);
        struct md_fd_object *endpoint=NULL;
        int server=-1,held=-1;
        struct sockaddr_in local={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
        local.sin_port=htons(reserve(&held)); close(held);
        assert(!md_network_endpoint_open(n,0,AF_INET,type,0,&endpoint,&server));
        assert(!md_network_endpoint_bind(endpoint,server,&root,(void *)&local,sizeof(local)));
        if (!udp) assert(!md_network_endpoint_listen(endpoint,server,4));
        struct md_network_filter_table table={.handle=1,.family=NFPROTO_IPV4};
        struct md_filter_chain chains[]={
            {.table=1,.handle=2,.hook=NF_INET_PRE_ROUTING,.policy=NF_DROP},
            {.table=1,.handle=3,.hook=NF_INET_LOCAL_OUT,.policy=NF_ACCEPT},
            {.table=1,.handle=4,.hook=NF_INET_LOCAL_IN,.policy=NF_ACCEPT}};
        struct md_network_filter filter={.tables=&table,.count=1,.chains=chains,.chain_count=3};
        pthread_mutex_lock(&n->fabric->lock);
        n->filter=&filter; md_network_forward_changed(n->fabric);
        pthread_mutex_unlock(&n->fabric->lock);
        for (unsigned denied=0;denied<3;++denied) {
            pthread_mutex_lock(&n->fabric->lock);
            chains[1].policy=denied==1 ? NF_DROP : NF_ACCEPT;
            chains[2].policy=denied==2 ? NF_DROP : NF_ACCEPT;
            md_network_forward_changed(n->fabric);
            pthread_mutex_unlock(&n->fabric->lock);
            int client=socket(AF_INET,type|SOCK_CLOEXEC,0); assert(client>=0);
            struct timeval timeout={.tv_sec=2};
            assert(!setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)));
            assert(!connect(client,(void *)&local,sizeof(local)));
            long sent=send(client,"ping",4,MSG_NOSIGNAL);
            char data[8];
            if (denied) {
                assert(sent==4 || (!udp && sent<0));
                /* EVENT_WAIT: denied TCP closes, UDP has no reply; timeout
                 * bounds the negative observation, not server readiness. */
                assert(recv(client,data,sizeof(data),0)<=0);
            } else {
                assert(sent==4);
                struct pollfd ready={.fd=server,.events=POLLIN};
                /* EVENT_WAIT: admitted payload/accept; timeout fails delivery. */
                assert(poll(&ready,1,2000)==1 && (ready.revents&POLLIN));
                int peer=udp ? server : accept4(server,NULL,NULL,SOCK_CLOEXEC);
                assert(peer>=0);
                assert(!setsockopt(peer,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)));
                struct sockaddr_in source; socklen_t size=sizeof(source);
                assert(recvfrom(peer,data,sizeof(data),0,(void *)&source,&size)==4 && !memcmp(data,"ping",4));
                assert((udp ? sendto(peer,"pong",4,0,(void *)&source,size) : send(peer,"pong",4,MSG_NOSIGNAL))==4);
                assert(recv(client,data,sizeof(data),0)==4 && !memcmp(data,"pong",4));
                if (!udp) close(peer);
            }
            close(client);
        }
        pthread_mutex_lock(&n->fabric->lock);
        n->filter=NULL; md_network_forward_changed(n->fabric);
        pthread_mutex_unlock(&n->fabric->lock);
        close(server); md_fd_object_release(endpoint);
        md_identity_release(&root); md_network_namespace_release(n);
    }
    puts("PASS native loopback TCP/UDP: OUTPUT and INPUT policy, never PREROUTING");
}
void test_network_launch(void) { parsing(); routes(); ports(); partial_rollback(); reserved_publication(); loopback_origin(); }

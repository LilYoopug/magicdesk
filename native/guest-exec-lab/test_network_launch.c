#define _GNU_SOURCE
#include "network_launch.h"
#include "guest_identity.h"
#include "network_internal.h"
#include "network_endpoint.h"
#include "network_flow.h"
#include "network_filter.h"
#include "network_nft_objects.h"
#include "network_nft_expression.h"
#include <assert.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <net/if.h>
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
void test_network_launch(void) { parsing(); routes(); ports(); partial_rollback(); }

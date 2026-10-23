#define _GNU_SOURCE
#include "network_endpoint.h"
#include "network_internal.h"
#include "network_forward.h"
#include "network_proc.h"
#include "test_network_fixture.h"
#include "guest_identity.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void device_binding(void) {
    struct md_network_namespace *n=md_network_namespace_new(NULL,MD_NETWORK_ROUTED);
    struct md_identity root=md_identity_new(0,0),user=md_identity_new(1000,1000);
    unsigned first,second;
    assert(!md_network_interface_add(n,MD_LINK_BRIDGE,"device-a",&first));
    assert(!md_network_interface_add(n,MD_LINK_BRIDGE,"device-b",&second));
    struct md_network_interface *a=md_network_interface_find(n,first,NULL);
    struct md_network_interface *b=md_network_interface_find(n,second,NULL);
    a->info.flags|=IFF_UP; test_network_v4(a,htonl(0x0a010001),24);
    b->info.flags|=IFF_UP; test_network_v4(b,htonl(0x0a020001),24);
    struct md_fd_object *late; int late_fd;
    assert(!md_network_endpoint_open(n,0,AF_INET,SOCK_DGRAM,0,&late,&late_fd));
    struct sockaddr_in wildcard={.sin_family=AF_INET};
    assert(!md_network_endpoint_bind(late,late_fd,&root,(void *)&wildcard,sizeof(wildcard)));
    struct sockaddr_storage public_address; socklen_t size;
    assert(!md_network_endpoint_name(late,late_fd,0,&public_address,&size));
    assert(!md_network_endpoint_device_set(late,&root,"device-a"));
    int native_fd=socket(AF_INET,SOCK_DGRAM,0);
    assert(native_fd>=0 && !bind(native_fd,(void *)&public_address,size));
    assert(md_network_endpoint_device_set(late,&root,"")==-EADDRINUSE);
    char retained[IFNAMSIZ]; size=sizeof(retained);
    assert(!md_network_endpoint_device_get(late,retained,&size) && !strcmp(retained,"device-a"));
    close(native_fd);
    assert(!md_network_endpoint_device_set(late,&root,""));
    close(late_fd); md_fd_object_release(late);
    struct md_fd_object *one,*two; int f,s;
    assert(!md_network_endpoint_open(n,0,AF_INET,SOCK_DGRAM,0,&one,&f));
    assert(!md_network_endpoint_open(n,0,AF_INET,SOCK_DGRAM,0,&two,&s));
    char name[IFNAMSIZ]; socklen_t length=0;
    assert(!md_network_endpoint_device_get(one,name,&length) && !length);
    assert(md_network_endpoint_device_set(one,&root,"missing")==-ENODEV);
    assert(!md_network_endpoint_device_set(one,&user,"device-a"));
    assert(md_network_endpoint_device_set(one,&user,"")==-EPERM);
    assert(md_network_endpoint_device_get(one,name,&length)==-EINVAL);
    length=sizeof(name);
    assert(!md_network_endpoint_device_get(one,name,&length) && length==9 && !strcmp(name,"device-a"));
    assert(!md_network_endpoint_device_set(one,&root,""));
    assert(!md_network_endpoint_device_set(one,&root,"device-a"));
    assert(!md_network_endpoint_device_set(two,&root,"device-b"));
    struct sockaddr_in any={.sin_family=AF_INET,.sin_port=htons(18670)};
    assert(!md_network_endpoint_bind(one,f,&root,(void *)&any,sizeof(any)));
    assert(!md_network_endpoint_bind(two,s,&root,(void *)&any,sizeof(any)));
    struct md_network_flow_path path={.destination=n->inode,
        .translated={.destination=md_ip_v4(htonl(0x0a010001)),.destination_port=any.sin_port,.input=first}};
    struct md_inet_address native; const void *selected=NULL;
    assert(!md_network_endpoint_resolve(n->fabric,&path,SOCK_DGRAM,&native,&selected));
    assert(selected==one && path.mediated);
    path.translated.input=second;
    assert(!md_network_endpoint_resolve(n->fabric,&path,SOCK_DGRAM,&native,&selected) && selected==two);
    path.translated.input=1;
    assert(md_network_endpoint_resolve(n->fabric,&path,SOCK_DGRAM,&native,&selected)==-ECONNREFUSED);
    struct sockaddr_storage destination;
    any.sin_addr.s_addr=htonl(0x0a020001);
    assert(md_network_endpoint_destination(one,(void *)&any,sizeof(any),&destination,&length)==-ENETUNREACH);
    assert(!md_network_interface_move(n,first,n,"renamed"));
    length=sizeof(name);
    assert(!md_network_endpoint_device_get(one,name,&length) && !strcmp(name,"renamed"));
    assert(!md_network_interface_remove(n,first));
    assert(!md_network_interface_add(n,MD_LINK_BRIDGE,"renamed",&first));
    length=sizeof(name);
    assert(md_network_endpoint_device_get(one,name,&length)==-ENODEV);
    assert(md_network_endpoint_destination(one,(void *)&any,sizeof(any),&destination,&length)==-ENODEV);
    close(f); close(s); md_fd_object_release(one); md_fd_object_release(two);
    md_identity_release(&root); md_identity_release(&user); md_network_namespace_release(n);
    puts("PASS socket device binding: shared endpoint identity, permissions, routing, ingress, rename and removal");
}

static void tcp_defaults(void) {
    struct md_network_namespace *n=md_network_namespace_new(NULL,MD_NETWORK_ROUTED);
    assert(n);
    const int options[]={TCP_KEEPIDLE,TCP_KEEPINTVL,TCP_KEEPCNT};
    const uint32_t defaults[]={7200,75,9},selected[]={1800,30,4};
    uint32_t values[2]={0};
    for (unsigned i=0;i<3;++i) {
        enum md_network_parameter kind=MD_NET_TCP_KEEPIDLE+i;
        assert(!md_network_parameter_read(n,kind,0,values) && values[0]==defaults[i]);
        values[0]=0;
        assert(md_network_parameter_write(n,kind,0,values)==-EOPNOTSUPP);
        values[0]=i==2 ? 256 : UINT32_MAX;
        assert(md_network_parameter_write(n,kind,0,values)==-EINVAL);
        values[0]=i==2 ? 128 : 32768;
        assert(md_network_parameter_write(n,kind,0,values)==-EOPNOTSUPP);
        values[0]=selected[i];
        assert(!md_network_parameter_write(n,kind,0,values));
    }
    struct md_network_namespace *child=md_network_namespace_copy(n,NULL);
    assert(child);
    assert(!md_network_parameter_read(child,MD_NET_TCP_KEEPIDLE,0,values) && values[0]==7200);
    struct md_fd_object *tcp,*udp; int fd,datagram;
    assert(!md_network_endpoint_open(n,0,AF_INET,SOCK_DGRAM,0,&udp,&datagram));
    values[0]=1801;
    assert(!md_network_parameter_write(n,MD_NET_TCP_KEEPIDLE,0,values));
    values[0]=1800;
    assert(!md_network_parameter_write(n,MD_NET_TCP_KEEPIDLE,0,values));
    assert(!md_network_endpoint_open(n,0,AF_INET,SOCK_STREAM,0,&tcp,&fd));
    for (unsigned i=0;i<3;++i) {
        int value=-1; socklen_t length=sizeof(value);
        assert(!getsockopt(fd,IPPROTO_TCP,options[i],&value,&length) && value==(int)selected[i]);
        values[0]=selected[i];
        assert(!md_network_parameter_write(n,MD_NET_TCP_KEEPIDLE+i,0,values));
        ++values[0];
        assert(md_network_parameter_write(n,MD_NET_TCP_KEEPIDLE+i,0,values)==-EBUSY);
        assert(!md_network_parameter_read(n,MD_NET_TCP_KEEPIDLE+i,0,values) && values[0]==selected[i]);
    }
    values[0]=3600;
    assert(!md_network_parameter_write(child,MD_NET_TCP_KEEPIDLE,0,values));
    close(fd); md_fd_object_release(tcp);
    assert(!md_network_parameter_write(n,MD_NET_TCP_KEEPIDLE,0,values));
    close(datagram); md_fd_object_release(udp);
    md_network_namespace_release(child); md_network_namespace_release(n);
    puts("PASS TCP namespace defaults: native options, independent namespaces, atomic admission and close");
}

void test_network_endpoint(void) {
    tcp_defaults();
    device_binding();
    struct md_network_namespace *root=md_network_namespace_new(NULL,MD_NETWORK_ROUTED);
    struct md_network_namespace *a=md_network_namespace_copy(root,NULL), *b=md_network_namespace_copy(root,NULL);
    struct md_network_namespace *offline=md_network_namespace_new(NULL,MD_NETWORK_PRIVATE);
    assert(root && a && b && offline);
    struct md_identity identity=md_identity_new(0,0),user=md_identity_new(1000,1000);
    struct md_fd_object *first=NULL,*second=NULL,*conflict=NULL;
    int f=-1,s=-1,c=-1;
    assert(md_network_endpoint_open(offline,0,AF_INET,SOCK_STREAM,0,&first,&f)==-EOPNOTSUPP);
    assert(!md_network_endpoint_open(a,0,AF_INET6,SOCK_STREAM,0,&first,&f));
    close(f); md_fd_object_release(first);
    assert(!md_network_endpoint_open(a,1000,AF_INET,SOCK_STREAM,0,&first,&f));
    assert(!md_network_endpoint_open(b,0,AF_INET,SOCK_STREAM,0,&second,&s));
    assert(!md_network_endpoint_open(a,0,AF_INET,SOCK_STREAM,0,&conflict,&c));
    struct sockaddr_in local={.sin_family=AF_INET,.sin_port=htons(80)};
    assert(md_network_endpoint_bind(first,f,&user,(void *)&local,sizeof(local))==-EACCES);
    assert(!md_network_endpoint_bind(first,f,&identity,(void *)&local,sizeof(local)));
    assert(!md_network_endpoint_bind(second,s,&identity,(void *)&local,sizeof(local)));
    assert(md_network_endpoint_bind(conflict,c,&identity,(void *)&local,sizeof(local))==-EADDRINUSE);
    struct sockaddr_in real_a,real_b; socklen_t length=sizeof(real_a);
    assert(!getsockname(f,(void *)&real_a,&length)); length=sizeof(real_b);
    assert(!getsockname(s,(void *)&real_b,&length) && real_a.sin_port!=real_b.sin_port);
    assert(!md_network_endpoint_listen(first,f,1));
    assert(!md_network_endpoint_listen(second,s,1));
    struct md_network_endpoint_info *entries=NULL;
    size_t count=0;
    assert(!md_network_endpoint_snapshot(a,IPPROTO_TCP,&entries,&count));
    struct stat st,other;
    assert(!fstat(f,&st) && !fstat(s,&other));
    assert(count==1 && entries[0].inode==st.st_ino && entries[0].uid==1000
        && entries[0].local.port==htons(80));
    free(entries);
    struct md_control_file table=md_network_proc_new(a,MD_NET_TABLE_TCP);
    assert(table.ops);
    struct md_control_actor actor={.identity=&identity};
    char text[4096]={0},needle[64];
    long bytes=table.ops->read(table.context,&actor,text,sizeof(text)-1,0);
    assert(bytes>0 && strstr(text,"00000000:0050"));
    snprintf(needle,sizeof(needle)," %llu ",(unsigned long long)st.st_ino);
    assert(strstr(text,needle));
    snprintf(needle,sizeof(needle)," %llu ",(unsigned long long)other.st_ino);
    assert(!strstr(text,needle));
    assert(table.ops->read(table.context,&actor,text,sizeof(text),bytes)==0);
    assert(table.ops->access(table.context,&identity,W_OK)==-EACCES);
    void *reopened=table.ops->open(table.context,O_RDONLY);
    assert(reopened && reopened!=table.context);
    table.ops->release(reopened); md_control_file_release(table);
    table=md_network_proc_new(offline,MD_NET_TABLE_TCP6);
    assert(table.ops);
    bytes=table.ops->read(table.context,&actor,text,sizeof(text)-1,0);
    assert(bytes>0); text[bytes]=0;
    assert(strchr(text,'\n')==text+bytes-1);
    md_control_file_release(table);
    struct sockaddr_storage logical;
    assert(!md_network_endpoint_name(first,f,0,&logical,&length));
    assert(((struct sockaddr_in *)&logical)->sin_port==htons(80));
    struct sockaddr_in internet=real_b;
    internet.sin_addr.s_addr=htonl(0xcb007109);
    memcpy(&logical,&internet,sizeof(internet)); length=sizeof(internet);
    assert(!md_network_endpoint_source(first,&logical,&length));
    assert(!memcmp(&logical,&internet,sizeof(internet)));
    struct sockaddr_in remote={.sin_family=AF_INET,.sin_port=htons(443),.sin_addr.s_addr=htonl(0x01010101)};
    assert(md_network_endpoint_destination(first,(void *)&remote,sizeof(remote),&logical,&length)==-ENETUNREACH);
    unsigned bridge,inside,outside;
    assert(!md_network_interface_add(root,MD_LINK_BRIDGE,"forward-bridge",&bridge));
    assert(!md_network_interface_add(root,MD_LINK_VETH,"forward-out",&outside));
    assert(!md_network_interface_add(a,MD_LINK_VETH,"forward-in",&inside));
    struct md_network_interface *in=md_network_interface_find(a,inside,NULL);
    struct md_network_interface *out=md_network_interface_find(root,outside,NULL);
    in->info.flags|=IFF_UP; out->info.flags|=IFF_UP;
    test_network_v4(in,htonl(0x0a580002),16);
    in->peer=outside; out->peer=inside; out->master=bridge;
    md_network_interface_find(root,bridge,NULL)->info.flags|=IFF_UP;
    a->routes[a->route_count++]=(struct md_network_route_entry){.destination=md_ip_any(AF_INET),
        .gateway=md_ip_any(AF_INET),.interface=inside};
    assert(!md_network_endpoint_destination(first,(void *)&remote,sizeof(remote),&logical,&length));
    uint32_t filter[2]={1};
    uint64_t scope;
    assert(!md_network_parameter_scope(root,MD_NET_RP_FILTER,"forward-bridge",&scope));
    assert(!md_network_parameter_write(root,MD_NET_RP_FILTER,scope,filter));
    assert(md_network_endpoint_destination(first,(void *)&remote,sizeof(remote),&logical,&length)==-ENETUNREACH);
    filter[0]=2;
    assert(!md_network_parameter_write(root,MD_NET_RP_FILTER,scope,filter));
    assert(!md_network_endpoint_destination(first,(void *)&remote,sizeof(remote),&logical,&length));
    struct md_network_interface *gateway=md_network_interface_find(root,bridge,NULL);
    test_network_v4(gateway,htonl(0x0a580001),16);
    filter[0]=1;
    assert(!md_network_parameter_write(root,MD_NET_RP_FILTER,scope,filter));
    assert(!md_network_endpoint_destination(first,(void *)&remote,sizeof(remote),&logical,&length));
    assert(md_network_ingress(root,gateway,md_ip_v4(htonl(INADDR_LOOPBACK)),md_ip_v4(remote.sin_addr.s_addr))==-ENETUNREACH);
    filter[0]=2;
    assert(!md_network_parameter_write(root,MD_NET_RP_FILTER,scope,filter));
    uint32_t localnet[2]={1};
    assert(!md_network_parameter_write(root,MD_NET_ROUTE_LOCALNET,scope,localnet));
    assert(!md_network_ingress(root,gateway,md_ip_v4(htonl(INADDR_LOOPBACK)),md_ip_v4(remote.sin_addr.s_addr)));
    uint32_t forward[2]={0};
    assert(!md_network_parameter_write(root,MD_NET_IPV4_FORWARD,0,forward));
    assert(md_network_endpoint_destination(first,(void *)&remote,sizeof(remote),&logical,&length)==-ENETUNREACH);
    struct md_fd_object *host=NULL; int hostfd=-1;
    assert(!md_network_endpoint_open(root,0,AF_INET,SOCK_STREAM,0,&host,&hostfd));
    assert(!md_network_endpoint_destination(host,(void *)&remote,sizeof(remote),&logical,&length));
    close(hostfd); md_fd_object_release(host);
    forward[0]=1;
    assert(!md_network_parameter_write(root,MD_NET_IPV4_FORWARD,0,forward));
    assert(!md_network_endpoint_destination(first,(void *)&remote,sizeof(remote),&logical,&length));
    /* Retaining provenance does not retain the application's OFD. */
    close(f); close(s); close(c);
    assert(fcntl(f,F_GETFD)==-1 && errno==EBADF);
    md_fd_object_release(first); md_fd_object_release(second); md_fd_object_release(conflict);
    assert(!root->fabric->endpoints);
    uint32_t ports[2]={49100,49101};
    assert(!md_network_parameter_write(a,MD_NET_LOCAL_PORTS,0,ports));
    assert(!md_network_endpoint_open(a,0,AF_INET,SOCK_STREAM,0,&first,&f));
    assert(!md_network_endpoint_open(a,0,AF_INET,SOCK_STREAM,0,&second,&s));
    assert(!md_network_endpoint_open(a,0,AF_INET,SOCK_STREAM,0,&conflict,&c));
    local.sin_port=0;
    assert(!md_network_endpoint_bind(first,f,&identity,(void *)&local,sizeof(local)));
    assert(!md_network_endpoint_bind(second,s,&identity,(void *)&local,sizeof(local)));
    assert(md_network_endpoint_bind(conflict,c,&identity,(void *)&local,sizeof(local))==-EADDRINUSE);
    assert(!md_network_endpoint_name(first,f,0,&logical,&length));
    assert(ntohs(((struct sockaddr_in *)&logical)->sin_port)==49100);
    assert(!md_network_endpoint_name(second,s,0,&logical,&length));
    assert(ntohs(((struct sockaddr_in *)&logical)->sin_port)==49101);
    close(f); md_fd_object_release(first);
    assert(!md_network_endpoint_bind(conflict,c,&identity,(void *)&local,sizeof(local)));
    close(s); close(c); md_fd_object_release(second); md_fd_object_release(conflict);
    md_network_namespace_release(a); md_network_namespace_release(b);
    md_network_namespace_release(root); md_network_namespace_release(offline);
    md_identity_release(&identity); md_identity_release(&user);
    puts("PASS network endpoints: namespace port reuse, conflicts, credentials, offline routing and OFD custody");
}

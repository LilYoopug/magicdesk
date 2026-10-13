#define _GNU_SOURCE
#include "network_route.h"
#include "network_internal.h"
#include "guest_identity.h"
#include <assert.h>
#include <errno.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>

struct packet { union { struct nlmsghdr align; unsigned char bytes[2048]; }; };
static struct nlmsghdr *request(struct packet *p,unsigned type,unsigned flags) {
    memset(p,0,sizeof(*p));
    struct nlmsghdr *h=(void *)p->bytes;
    *h=(struct nlmsghdr){.nlmsg_len=NLMSG_LENGTH(sizeof(struct ifinfomsg)),.nlmsg_type=type,
        .nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK|flags,.nlmsg_seq=71};
    return h;
}
static struct rtattr *attr(struct nlmsghdr *h,unsigned type,const void *data,size_t size) {
    assert(h->nlmsg_len+RTA_SPACE(size)<sizeof(struct packet));
    struct rtattr *a=(void *)((char *)h+h->nlmsg_len);
    a->rta_type=type; a->rta_len=RTA_LENGTH(size);
    if (size) memcpy(RTA_DATA(a),data,size);
    h->nlmsg_len+=RTA_SPACE(size); return a;
}
static int ack(struct md_network_namespace *n,const struct md_identity *id,struct nlmsghdr *h,
        const struct md_network_target *resolver) {
    struct packet reply;
    long length=md_network_route(n,id,h,h->nlmsg_len,91,0,resolver,reply.bytes,sizeof(reply),NULL);
    assert(length>=(long)NLMSG_LENGTH(sizeof(struct nlmsgerr)));
    struct nlmsghdr *out=(void *)reply.bytes;
    assert(out->nlmsg_type==NLMSG_ERROR && out->nlmsg_seq==71 && out->nlmsg_pid==91);
    int error=((struct nlmsgerr *)NLMSG_DATA(out))->error;
    if (error) {
        assert(length==(long)(NLMSG_LENGTH(sizeof(struct nlmsgerr))+h->nlmsg_len-sizeof(*h)));
        assert(!memcmp((char *)NLMSG_DATA(out)+sizeof(struct nlmsgerr),NLMSG_DATA(h),h->nlmsg_len-sizeof(*h)));
    } else assert(out->nlmsg_flags&NLM_F_CAPPED);
    return error;
}
static int resolve(void *context,int fd,struct md_network_namespace **out) {
    if (fd!=7) return -EBADF;
    *out=md_network_namespace_retain(context); return 0;
}
static int reject_response(void *context,const void *data,size_t size) {
    (void)context; (void)data; assert(size); return -EAGAIN;
}
void test_network_route(void) {
    struct md_network_namespace *n=md_network_namespace_new(NULL,MD_NETWORK_ROUTED);
    struct md_network_namespace *child=md_network_namespace_copy(n,NULL);
    struct md_identity root=md_identity_new(0,0),user=md_identity_new(1000,1000);
    struct packet p;
    struct nlmsghdr *h=request(&p,RTM_SETLINK,NLM_F_CREATE|NLM_F_EXCL);
    struct ifinfomsg *loopback=NLMSG_DATA(h);
    loopback->ifi_index=1; loopback->ifi_flags=loopback->ifi_change=IFF_UP;
    assert(!ack(n,&root,h,NULL) && n->count==2);
    loopback->ifi_index=999;
    assert(ack(n,&root,h,NULL)==-ENODEV && n->count==2);
    h=request(&p,RTM_NEWLINK,NLM_F_CREATE|NLM_F_EXCL);
    attr(h,IFLA_IFNAME,"br-test",8);
    struct rtattr *info=attr(h,IFLA_LINKINFO|NLA_F_NESTED,NULL,0);
    attr(h,IFLA_INFO_KIND,"bridge",6);
    info->rta_len=(char *)h+h->nlmsg_len-(char *)info;
    assert(ack(n,&user,h,NULL)==-EPERM && n->count==2);
    struct packet rejected;
    struct md_network_publication refusal={.publish=reject_response};
    unsigned original_index=n->fabric->next_index;
    assert(md_network_route(n,&root,h,h->nlmsg_len,91,0,NULL,rejected.bytes,sizeof(rejected),&refusal)==-EAGAIN);
    assert(n->count==2 && n->fabric->next_index==original_index);
    assert(!md_network_interface_find(n,0,"br-test"));
    assert(md_network_route(n,&root,h,h->nlmsg_len,91,0,NULL,rejected.bytes,0,NULL)==-EMSGSIZE);
    assert(n->count==2 && n->fabric->next_index==original_index);
    assert(!ack(n,&root,h,NULL) && n->count==3);
    assert(ack(n,&root,h,NULL)==-EEXIST && n->count==3);
    unsigned bridge=md_network_interface_find(n,0,"br-test")->info.index;
    h=request(&p,RTM_NEWLINK,NLM_F_CREATE|NLM_F_EXCL);
    attr(h,IFLA_IFNAME,"veth-host",10);
    info=attr(h,IFLA_LINKINFO|NLA_F_NESTED,NULL,0);
    attr(h,IFLA_INFO_KIND,"veth",5);
    struct rtattr *data=attr(h,IFLA_INFO_DATA|NLA_F_NESTED,NULL,0);
    struct ifinfomsg zero={0};
    struct rtattr *peer=attr(h,VETH_INFO_PEER|NLA_F_NESTED,&zero,sizeof(zero));
    attr(h,IFLA_IFNAME,"veth-guest",11);
    unsigned queue_length=77;
    attr(h,IFLA_TXQLEN,&queue_length,sizeof(queue_length));
    peer->rta_len=(char *)h+h->nlmsg_len-(char *)peer;
    data->rta_len=(char *)h+h->nlmsg_len-(char *)data;
    info->rta_len=(char *)h+h->nlmsg_len-(char *)info;
    assert(!ack(n,&root,h,NULL) && n->count==5);
    unsigned endpoint=md_network_interface_find(n,0,"veth-guest")->info.index;
    assert(md_network_interface_find(n,endpoint,NULL)->info.tx_queue_length==77);
    h=request(&p,RTM_NEWLINK,0);
    ((struct ifinfomsg *)NLMSG_DATA(h))->ifi_index=endpoint;
    attr(h,IFLA_IFNAME,"eth0",4); unsigned fd=7;
    attr(h,IFLA_NET_NS_FD,&fd,sizeof(fd));
    struct md_network_target target={.context=child,.resolve=resolve};
    assert(md_network_route(n,&root,h,h->nlmsg_len,91,0,&target,rejected.bytes,sizeof(rejected),&refusal)==-EAGAIN);
    assert(md_network_interface_find(n,endpoint,NULL) && !md_network_interface_find(child,endpoint,NULL));
    assert(!ack(n,&root,h,&target));
    assert(!md_network_interface_find(n,endpoint,NULL));
    assert(md_network_interface_find(child,endpoint,NULL));
    h=request(&p,RTM_NEWLINK,0);
    struct ifinfomsg *link=NLMSG_DATA(h);
    link->ifi_index=endpoint; link->ifi_change=IFF_UP; link->ifi_flags=IFF_UP;
    unsigned invalid=999;
    attr(h,IFLA_MASTER,&invalid,sizeof(invalid));
    assert(ack(child,&root,h,NULL)==-EINVAL);
    assert(!(md_network_interface_find(child,endpoint,NULL)->info.flags&IFF_UP));
    h=request(&p,RTM_GETLINK,NLM_F_DUMP);
    struct packet reply;
    long length=md_network_route(n,&user,h,h->nlmsg_len,91,0,NULL,reply.bytes,sizeof(reply),NULL);
    assert(length>0);
    unsigned links=0,done=0,bridges=0;
    for (struct nlmsghdr *item=(void *)reply.bytes;NLMSG_OK(item,length);item=NLMSG_NEXT(item,length)) {
        assert(item->nlmsg_seq==71);
        if (item->nlmsg_type==RTM_NEWLINK) {
            ++links;
            const struct ifinfomsg *m=NLMSG_DATA(item);
            int left=IFLA_PAYLOAD(item);
            for (const struct rtattr *a=IFLA_RTA(m);RTA_OK(a,left);a=RTA_NEXT(a,left)) {
                assert(a->rta_type!=(IFLA_LINKINFO|NLA_F_NESTED));
                if (a->rta_type==IFLA_LINKINFO && (unsigned)m->ifi_index==bridge) {
                    const struct rtattr *kind=RTA_DATA(a);
                    assert(kind->rta_type==IFLA_INFO_KIND && !strcmp(RTA_DATA(kind),"bridge"));
                    ++bridges;
                }
            }
        }
        else { assert(item->nlmsg_type==NLMSG_DONE); ++done; }
    }
    assert(!length && links==4 && done==1 && bridges==1);
    for (unsigned bad=0;bad<4;++bad) {
        h=request(&p,RTM_GETLINK,NLM_F_DUMP);
        struct ifinfomsg *body=NLMSG_DATA(h);
        if (bad==0) h->nlmsg_len=NLMSG_LENGTH(sizeof(struct rtgenmsg));
        if (bad==1) body->ifi_index=1;
        if (bad==2) body->__ifi_pad=1;
        if (bad==3) attr(h,IFLA_IFNAME,"lo",3);
        length=md_network_route(n,&user,h,h->nlmsg_len,91,MD_NETWORK_ROUTE_STRICT,NULL,reply.bytes,sizeof(reply),NULL);
        assert(length>=(long)NLMSG_LENGTH(sizeof(struct nlmsgerr)));
        assert(reply.align.nlmsg_type==NLMSG_ERROR);
        assert(((struct nlmsgerr *)NLMSG_DATA(&reply.align))->error==(bad==3 ? -EOPNOTSUPP : -EINVAL));
    }
    h=request(&p,RTM_GETLINK,NLM_F_DUMP);
    length=md_network_route(n,&user,h,h->nlmsg_len,91,MD_NETWORK_ROUTE_STRICT,NULL,reply.bytes,sizeof(reply),NULL);
    assert(length>0); links=done=0;
    for (struct nlmsghdr *item=&reply.align;NLMSG_OK(item,length);item=NLMSG_NEXT(item,length)) {
        assert(item->nlmsg_type==RTM_NEWLINK || item->nlmsg_type==NLMSG_DONE);
        if (item->nlmsg_type==RTM_NEWLINK) ++links; else ++done;
    }
    assert(!length && links==4 && done==1);
    const unsigned queries[]={RTM_GETLINK,RTM_GETADDR,RTM_GETROUTE};
    for (unsigned q=0;q<3;++q) for (unsigned padding=1;padding<=4;padding*=4) {
        h=request(&p,queries[q],NLM_F_DUMP);
        h->nlmsg_len=NLMSG_LENGTH(padding);
        length=md_network_route(n,&user,h,h->nlmsg_len,91,0,NULL,reply.bytes,sizeof(reply),NULL);
        assert(length>0);
        done=0;
        for (struct nlmsghdr *item=(void *)reply.bytes;NLMSG_OK(item,length);item=NLMSG_NEXT(item,length)) {
            assert(item->nlmsg_type!=NLMSG_ERROR && item->nlmsg_seq==71);
            if (item->nlmsg_type==NLMSG_DONE) ++done;
        }
        assert(!length && done==1);
    }
    h=request(&p,RTM_DELLINK,0);
    ((struct ifinfomsg *)NLMSG_DATA(h))->ifi_index=bridge;
    assert(!ack(n,&root,h,NULL));
    md_network_namespace_release(child); md_network_namespace_release(n);
    md_identity_release(&root); md_identity_release(&user);
    puts("PASS route netlink: permissions, bridge/veth, namespace handles, atomic rejection and multipart dumps");
}

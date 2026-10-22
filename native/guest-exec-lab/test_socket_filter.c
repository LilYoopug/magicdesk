#define _GNU_SOURCE
#include "socket_filter.h"
#include "network_packet.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void compare(const struct sock_filter *code,unsigned count) {
    int native[2],wrapped[2];
    assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,native));
    assert(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0,wrapped));
    struct sock_fprog original={.len=(unsigned short)count,.filter=(void *)code};
    assert(!setsockopt(native[1],SOL_SOCKET,SO_ATTACH_FILTER,&original,sizeof(original)));
    struct md_socket_filter filter={0};
    assert(!md_socket_filter_attach(&filter,wrapped[1],code,count*sizeof(*code),sizeof(struct md_network_packet)));
    assert(filter.count==count && !memcmp(filter.code,code,count*sizeof(*code)));
    unsigned char payload[512],a[512],b[512+sizeof(struct md_network_packet)];
    for (unsigned i=0;i<sizeof(payload);++i) payload[i]=(unsigned char)(i*17);
    struct md_network_packet header={.group=17,.port=113,.pid=7,.uid=1024};
    for (unsigned size=1;size<=sizeof(payload);++size) {
        assert(send(native[0],payload,size,0)==size);
        struct iovec v[]={{&header,sizeof(header)},{payload,size}};
        struct msghdr msg={.msg_iov=v,.msg_iovlen=2};
        assert(sendmsg(wrapped[0],&msg,0)==sizeof(header)+size);
        ssize_t n=recv(native[1],a,sizeof(a),MSG_DONTWAIT);
        if (n<0) assert(errno==EAGAIN);
        ssize_t m=recv(wrapped[1],b,sizeof(b),MSG_DONTWAIT);
        if (n<0) assert(m<0 && errno==EAGAIN);
        else assert(m==n+(ssize_t)sizeof(header) && !memcmp(b,&header,sizeof(header)) && !memcmp(b+sizeof(header),a,(size_t)n));
    }
    struct sock_filter invalid[]={BPF_STMT(BPF_LD|BPF_MEM,0),BPF_STMT(BPF_RET|BPF_A,0)};
    assert(md_socket_filter_attach(&filter,wrapped[1],invalid,sizeof(invalid),sizeof(header))==-EINVAL);
    assert(filter.count==count && !memcmp(filter.code,code,count*sizeof(*code)));
    assert(!md_socket_filter_detach(&filter,wrapped[1]) && !filter.count && !filter.code);
    assert(md_socket_filter_detach(&filter,wrapped[1])==-ENOENT);
    assert(!md_socket_filter_attach(&filter,wrapped[1],code,count*sizeof(*code),sizeof(header)));
    int yes=1;
    assert(!setsockopt(wrapped[1],SOL_SOCKET,SO_LOCK_FILTER,&yes,sizeof(yes)));
    assert(md_socket_filter_detach(&filter,wrapped[1])==-EPERM);
    assert(md_socket_filter_attach(&filter,wrapped[1],code,count*sizeof(*code),sizeof(header))==-EPERM);
    md_socket_filter_clear(&filter);
    for (unsigned i=0;i<2;++i) { close(native[i]); close(wrapped[i]); }
}
void test_socket_filter(void) {
    const struct sock_filter absolute[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_LEN,0), BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K,16,0,4),
        BPF_STMT(BPF_LD|BPF_H|BPF_ABS,4), BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0x4455,0,2),
        BPF_STMT(BPF_LD|BPF_B|BPF_ABS,7), BPF_STMT(BPF_RET|BPF_A,0), BPF_STMT(BPF_RET|BPF_K,0)};
    compare(absolute,sizeof(absolute)/sizeof(*absolute));
    const struct sock_filter length[]={BPF_STMT(BPF_LD|BPF_W|BPF_LEN,0),BPF_STMT(BPF_RET|BPF_A,0)};
    compare(length,2);
    const struct sock_filter xlength[]={BPF_STMT(BPF_LD|BPF_IMM,4),BPF_STMT(BPF_LDX|BPF_W|BPF_LEN,0),
        BPF_STMT(BPF_ALU|BPF_ADD|BPF_X,0),BPF_STMT(BPF_RET|BPF_A,0)};
    compare(xlength,4);
    const struct sock_filter indexed[]={BPF_STMT(BPF_LDX|BPF_B|BPF_MSH,3),
        BPF_STMT(BPF_LD|BPF_H|BPF_IND,2),BPF_STMT(BPF_RET|BPF_A,0)};
    compare(indexed,3);
    const struct sock_filter overflow[]={BPF_STMT(BPF_LDX|BPF_IMM,0xffffffffU-16),
        BPF_STMT(BPF_LD|BPF_B|BPF_IND,0),BPF_STMT(BPF_RET|BPF_A,0)};
    compare(overflow,3);
    const struct sock_filter saturation[]={BPF_STMT(BPF_LD|BPF_IMM,0xfffffffeU),BPF_STMT(BPF_RET|BPF_A,0)};
    compare(saturation,2);
    const struct sock_filter cut[]={BPF_STMT(BPF_RET|BPF_K,3)};
    compare(cut,1);
    struct sock_filter distant[254];
    distant[0]=(struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_LEN,0);
    distant[1]=(struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K,200,250,251);
    for (unsigned i=2;i<252;++i) distant[i]=(struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_LEN,0);
    distant[252]=(struct sock_filter)BPF_STMT(BPF_RET|BPF_K,8);
    distant[253]=(struct sock_filter)BPF_STMT(BPF_RET|BPF_K,0);
    compare(distant,254);
    puts("PASS socket filter: kernel parity for loads, lengths, indexed overflow, long branches, truncation and locked replacement");
}

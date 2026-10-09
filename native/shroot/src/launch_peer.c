#define _GNU_SOURCE
#include "launch_peer.h"
#include "launch_peer_wire.h"
#include "fs_wire.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int alive(int process) {
    struct pollfd p={.fd=process,.events=POLLIN};
    /* One pidfd readiness probe, not a wait or timed process scan. */
    int n=poll(&p,1,0);
    return n<0 ? -errno : n ? -ESRCH : 0;
}
static int owner(const struct md_launch_registration *local) {
    if (!local || local->record<0) return -EINVAL;
    struct md_launch_info info;
    int process=md_launch_acquire(local,local->id,&info);
    if (process<0) return process;
    int r=info.pid==getpid() && info.descriptor==local->record ? alive(process) : -EACCES;
    close(process); return r;
}
static int address(const char *id, struct sockaddr_un *out) {
    if (!id || strlen(id)!=32 || strspn(id,"0123456789abcdef")!=32) return -EINVAL;
    char name[80];
    snprintf(name,sizeof(name),"magicdesk.shroot.peer.%u.%s",(unsigned)getuid(),id);
    return (int)md_fs_address(name,out);
}
static int check_process(int socket, int process, const struct md_launch_info *info) {
    long peer=md_fs_private_peer(socket);
    return peer<0 ? (int)peer : peer!=info->pid ? -EACCES : alive(process);
}
int md_launch_peer_listen(const struct md_launch_registration *local) {
    int r=owner(local);
    if (r) return r;
    struct sockaddr_un addr; int size=address(local->id,&addr);
    if (size<0) return size;
    int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    if (fd<0) return -errno;
    if (bind(fd,(struct sockaddr *)&addr,(socklen_t)size) || listen(fd,16)) {
        r=-errno; close(fd); return r;
    }
    return fd;
}
int md_launch_peer_verify(const struct md_launch_registration *local, int socket, const char *id) {
    int r=owner(local);
    if (r) return r;
    struct md_launch_info info;
    int process=md_launch_acquire(local,id,&info);
    if (process<0) return process;
    r=check_process(socket,process,&info);
    close(process); return r;
}
int md_launch_peer_connect(const struct md_launch_registration *local, const char *id) {
    int r=owner(local);
    if (r) return r;
    struct sockaddr_un addr; int size=address(id,&addr);
    if (size<0) return size;
    /* Resolve before connecting, so a foreign store or stale ID cannot cause
     * any connection to an otherwise guessable abstract address. */
    struct md_launch_info info;
    int process=md_launch_acquire(local,id,&info);
    if (process<0) return process;
    int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    r=fd<0 ? -errno : 0;
    if (!r && connect(fd,(struct sockaddr *)&addr,(socklen_t)size)) r=-errno;
    if (!r) r=check_process(fd,process,&info);
    close(process);
    if (!r) {
        struct md_launch_peer_packet packet={.magic=MD_LAUNCH_PEER_MAGIC,.version=MD_LAUNCH_PEER_VERSION};
        memcpy(packet.id,local->id,sizeof(packet.id));
        long n=md_fs_send(fd,&packet,sizeof(packet),&(struct md_fs_rights){0});
        if (n!=sizeof(packet)) r=n<0 ? (int)n : -EPROTO;
    }
    if (r) { if (fd>=0) close(fd); return r; }
    return fd;
}
int md_launch_peer_receive(int socket, char id[33]) {
    if (!id) return -EINVAL;
    long peer=md_fs_private_peer(socket);
    if (peer<0) return (int)peer;
    struct md_launch_peer_packet packet;
    struct md_fs_rights rights={0};
    long n=md_fs_receive(socket,&packet,sizeof(packet),&rights);
    if (rights.count) { md_fs_close_rights(&rights); return -EPROTO; }
    if (n<0) return (int)n;
    if (!n) return -ECONNRESET;
    if (n!=sizeof(packet) || packet.magic!=MD_LAUNCH_PEER_MAGIC) return -EPROTO;
    if (packet.version!=MD_LAUNCH_PEER_VERSION) return -EPROTONOSUPPORT;
    char value[33]; memcpy(value,packet.id,32); value[32]=0;
    if (strspn(value,"0123456789abcdef")!=32) return -EPROTO;
    memcpy(id,value,sizeof(value)); return 0;
}

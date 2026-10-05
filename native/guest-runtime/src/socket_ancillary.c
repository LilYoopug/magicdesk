#define _GNU_SOURCE
#include "socket_ancillary.h"
#include "socket_namespace.h"
#include "ipc_credentials.h"
#include "fs_rpc.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>

static struct cmsghdr *next_header(const struct msghdr *m, const struct cmsghdr *h) {
    size_t offset = (const char *)h - (const char *)m->msg_control;
    if (offset > m->msg_controllen || h->cmsg_len < CMSG_LEN(0) || h->cmsg_len > m->msg_controllen-offset) return NULL;
    size_t step = CMSG_ALIGN(h->cmsg_len);
    if (step > m->msg_controllen-offset || m->msg_controllen-offset-step < sizeof(*h)) return NULL;
    return (void *)((char *)m->msg_control+offset+step);
}

/* The kernel still transports data and SCM_RIGHTS. An explicit guest credential
 * message adds one sealed, connection-scoped identity capability; the receiving
 * adapter removes it before publishing ancillary data. No stream framing. */
static long message_rpc(const struct md_fs *fs, int socket, int token,
        const struct ucred *claimed, struct ucred *out) {
    if (!fs->endpoint[0]) return -ENODATA;
    struct md_fs_request q = {.operation=MD_FS_IPC,
        .flags=claimed ? MD_IPC_MESSAGE_CREATE : MD_IPC_MESSAGE_READ,
        .directory={socket,token}};
    if (claimed) { q.offset=claimed->pid; q.attributes.uid=claimed->uid; q.attributes.gid=claimed->gid; }
    struct md_fs_response reply;
    long r = md_fs_call(fs->endpoint, 5000, &q, &reply);
    if (!r) r = reply.result.error;
    if (r == -ENOTSUP || r == -EAFNOSUPPORT || r == -EPROTOTYPE) r = -ENODATA;
    if (r) return r;
    if (claimed) return reply.result.fd;
    *out = (struct ucred){(pid_t)reply.result.position,reply.result.info.uid,reply.result.info.gid};
    return 0;
}
static void *buffer(size_t size, void *local, size_t capacity) {
    if (size <= capacity) return local;
    if (size > 16*1024*1024) return NULL;
    long p = RAW6(mmap, 0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p < 0 ? NULL : (void *)p;
}
static void release(void *p, void *local, size_t size) { if (p && p != local) RAW2(munmap,p,size); }
long md_socket_ancillary_send(const struct md_fs *fs, const char *exe, const unsigned long *a) {
    struct msghdr m;
    long r = md_read_memory(&m, (void *)a[1], sizeof(m));
    if (r < 0 || !fs->endpoint[0] || !m.msg_control || !m.msg_controllen)
        return md_socket_address_call(fs, exe, SYS_sendmsg, a);
    size_t credential_offset = 0; int found = 0;
    struct ucred claimed;
    for (size_t pos = 0; pos <= m.msg_controllen && m.msg_controllen-pos >= sizeof(struct cmsghdr);) {
        struct cmsghdr h;
        if (md_read_memory(&h, (char *)m.msg_control+pos, sizeof(h)) < 0) return -EFAULT;
        if (h.cmsg_len < CMSG_LEN(0) || h.cmsg_len > m.msg_controllen-pos) return -EINVAL;
        if (h.cmsg_level == SOL_SOCKET && h.cmsg_type == SCM_CREDENTIALS) {
            if (found || h.cmsg_len != CMSG_LEN(sizeof(claimed))) return -EINVAL;
            found = 1; credential_offset = pos + CMSG_LEN(0);
            if (md_read_memory(&claimed, (char *)m.msg_control+credential_offset, sizeof(claimed)) < 0) return -EFAULT;
        }
        if (CMSG_ALIGN(h.cmsg_len) > m.msg_controllen-pos) break;
        pos += CMSG_ALIGN(h.cmsg_len);
    }
    if (!found) return md_socket_address_call(fs, exe, SYS_sendmsg, a);
    long token = message_rpc(fs, (int)a[0], -1, &claimed, NULL);
    if (token == -ENODATA) return md_socket_address_call(fs, exe, SYS_sendmsg, a);
    if (token < 0) return token;
    size_t offset = CMSG_ALIGN(m.msg_controllen), size = offset+CMSG_SPACE(sizeof(int));
    _Alignas(struct cmsghdr) char local[1024];
    void *storage = size < m.msg_controllen ? NULL : buffer(size,local,sizeof(local));
    if (!storage) { RAW1(close,token); return -ENOMEM; }
    memset(storage,0,size);
    r = md_read_memory(storage,m.msg_control,m.msg_controllen);
    if (!r) {
        struct ucred native = {(pid_t)RAW0(getpid),(uid_t)RAW0(getuid),(gid_t)RAW0(getgid)};
        memcpy((char *)storage+credential_offset,&native,sizeof(native));
        struct cmsghdr *h = (void *)((char *)storage+offset);
        *h = (struct cmsghdr){.cmsg_len=CMSG_LEN(sizeof(int)),.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS};
        int fd = (int)token; memcpy(CMSG_DATA(h),&fd,sizeof(fd));
        m.msg_control=storage; m.msg_controllen=size;
        unsigned long args[6]; memcpy(args,a,sizeof(args)); args[1]=(unsigned long)&m;
        r = md_socket_address_call(fs,exe,SYS_sendmsg,args);
    }
    release(storage,local,size); RAW1(close,token); return r;
}
static int candidate(int fd) {
    struct stat st;
    if (RAW2(fstat,fd,&st) < 0 || !S_ISREG(st.st_mode) || st.st_size != 24) return 0;
    long seals = RAW3(fcntl,fd,F_GET_SEALS,0);
    return seals >= 0 && (seals & (F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL))
        == (F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL);
}
static size_t append(void *out, size_t used, size_t capacity, int type, int level,
        const void *data, size_t size, int *flags) {
    size_t room = used < capacity ? capacity-used : 0;
    if (room < CMSG_LEN(size)) *flags |= MSG_CTRUNC;
    if (room < sizeof(struct cmsghdr)) return used;
    size_t copied = room-CMSG_LEN(0) < size ? room-CMSG_LEN(0) : size;
    struct cmsghdr h = {.cmsg_len=CMSG_LEN(copied),.cmsg_level=level,.cmsg_type=type};
    /* Ancillary copy faults leave the payload delivered, with no advance of
     * the control cursor. SCM_RIGHTS has its own per-descriptor commit below. */
    if (md_write_memory((char *)out+used,&h,sizeof(h)) < 0
            || md_write_memory((char *)out+used+CMSG_LEN(0),data,copied) < 0) return used;
    size_t step = CMSG_SPACE(copied);
    return used + (step < room ? step : room);
}
static size_t publish_rights(void *out, size_t used, size_t capacity,
        int *fds, size_t count, int *flags) {
    size_t room=used<capacity?capacity-used:0;
    size_t fit=room>CMSG_LEN(0)?(room-CMSG_LEN(0))/sizeof(int):0;
    size_t delivered=0;
    for (; delivered<count && delivered<fit; ++delivered) {
        if (md_write_memory((char *)out+used+CMSG_LEN(0)+delivered*sizeof(int),
                &fds[delivered],sizeof(int)) < 0) break;
        /* Published FD numbers are caller-owned even if a later control/header
         * write faults. Never roll them back or keep an extra data-OFD pin. */
        fds[delivered]=-1;
    }
    if (delivered<count) *flags |= MSG_CTRUNC;
    for (size_t i=delivered;i<count;++i) { RAW1(close,fds[i]); fds[i]=-1; }
    if (!delivered) return used;
    struct cmsghdr *target=(void *)((char *)out+used);
    int level=SOL_SOCKET, type=SCM_RIGHTS; size_t length=CMSG_LEN(delivered*sizeof(int));
    if (md_write_memory(&target->cmsg_level,&level,sizeof(level)) < 0
            || md_write_memory(&target->cmsg_type,&type,sizeof(type)) < 0
            || md_write_memory(&target->cmsg_len,&length,sizeof(length)) < 0) return used;
    size_t step=CMSG_SPACE(delivered*sizeof(int));
    return used+(step<room?step:room);
}
static void close_rights(struct msghdr *m) {
    for (struct cmsghdr *h=CMSG_FIRSTHDR(m); h; h=next_header(m,h))
        if (h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_RIGHTS) {
            int *fds=(void *)CMSG_DATA(h);
            for (size_t i=0;i<(h->cmsg_len-CMSG_LEN(0))/sizeof(int);i++) if (fds[i]>=0) RAW1(close,fds[i]);
        }
}
static long publish(const struct md_fs *fs, int socket, const struct msghdr *original,
        struct msghdr m, void *destination) {
    size_t capacity=original->msg_control?original->msg_controllen:0;
    struct ucred claimed={0}; int have_claim=0;
    /* Identify capabilities before rebuilding headers: the kernel can coalesce
     * ordinary descriptors and the identity descriptor into one SCM_RIGHTS. */
    for (struct cmsghdr *h=CMSG_FIRSTHDR(&m); h; h=next_header(&m,h)) {
        if (h->cmsg_level!=SOL_SOCKET || h->cmsg_type!=SCM_RIGHTS) continue;
        size_t count=(h->cmsg_len-CMSG_LEN(0))/sizeof(int);
        int *fds=(void *)CMSG_DATA(h);
        for (size_t i=0;i<count;i++) if (candidate(fds[i])) {
            struct ucred value;
            long status=message_rpc(fs,socket,fds[i],NULL,&value);
            if (!status) { claimed=value; have_claim=1; RAW1(close,fds[i]); fds[i]=-1; }
            else if (status != -ENODATA) { close_rights(&m); return status; }
        }
    }
    void *out=original->msg_control; size_t used=0;
    for (struct cmsghdr *h=CMSG_FIRSTHDR(&m); h; h=next_header(&m,h)) {
        const void *data=CMSG_DATA(h); size_t n=h->cmsg_len-CMSG_LEN(0);
        if (h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_CREDENTIALS && n==sizeof(claimed) && have_claim) data=&claimed;
        if (h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_RIGHTS) {
            int *fds=(void *)CMSG_DATA(h); size_t count=0;
            for (size_t i=0;i<n/sizeof(int);i++) if (fds[i]>=0) fds[count++]=fds[i];
            if (!count) continue;
            used=publish_rights(out,used,capacity,fds,count,&m.msg_flags);
            continue;
        }
        used=append(out,used,capacity,h->cmsg_type,h->cmsg_level,data,n,&m.msg_flags);
    }
    struct msghdr *target=destination;
    long copied=0;
    if (original->msg_name) {
        unsigned length=m.msg_namelen;
        copied=length>sizeof(struct sockaddr_storage)?-EPROTO:
            md_namespace_socket_restore(fs,socket,m.msg_name,&length);
        if (!copied) copied=md_write_memory(original->msg_name,m.msg_name,
            original->msg_namelen<length?original->msg_namelen:length);
        if (!copied) copied=md_write_memory(&target->msg_namelen,&length,sizeof(length));
    }
    if (!copied) copied=md_write_memory(&target->msg_flags,&m.msg_flags,sizeof(m.msg_flags));
    if (!copied) copied=md_write_memory(&target->msg_controllen,&used,sizeof(used));
    return copied;
}
static size_t native_capacity(size_t capacity) {
    size_t extra=CMSG_SPACE(sizeof(int))+CMSG_SPACE(sizeof(struct ucred));
    return capacity > 16*1024*1024-extra ? 0 : CMSG_ALIGN(capacity+extra);
}
long md_socket_ancillary_receive(const struct md_fs *fs, const char *exe, const unsigned long *a) {
    struct msghdr original;
    long r=md_read_memory(&original,(void *)a[1],sizeof(original));
    if (r < 0 || !fs->endpoint[0])
        return md_socket_address_call(fs,exe,SYS_recvmsg,a);
    if ((int)original.msg_namelen<0) return -EINVAL;
    size_t capacity=original.msg_control?original.msg_controllen:0;
    size_t size=native_capacity(capacity);
    if (!size) return -ENOBUFS;
    _Alignas(struct cmsghdr) char local[2048]; void *storage=buffer(size,local,sizeof(local));
    if (!storage) return -ENOMEM;
    memset(storage,0,size);
    struct msghdr m=original; m.msg_control=storage; m.msg_controllen=size;
    struct sockaddr_storage address={0};
    if (original.msg_name) { m.msg_name=&address; m.msg_namelen=sizeof(address); }
    r=RAW3(recvmsg,a[0],&m,a[2]);
    if (r >= 0) {
        long error=publish(fs,(int)a[0],&original,m,(void *)a[1]);
        if (error < 0) r=error;
    }
    release(storage,local,size); return r;
}
long md_socket_ancillary_batch(const struct md_fs *fs, const unsigned long *a) {
    unsigned count=(unsigned)a[2];
    if (!count || !fs->endpoint[0]) return md_raw(SYS_recvmmsg,a[0],a[1],a[2],a[3],a[4],0);
    if (count > 1024) count=1024;
    struct item {
        struct msghdr original; void *buffer; size_t size;
        struct sockaddr_storage address;
        _Alignas(struct cmsghdr) char local[256];
    };
    size_t size=count*(sizeof(struct item)+sizeof(struct mmsghdr));
    _Alignas(struct mmsghdr) char local[4096]; void *memory=buffer(size,local,sizeof(local));
    if (!memory) return -ENOMEM;
    memset(memory,0,size);
    struct mmsghdr *messages=memory;
    struct item *items=(void *)(messages+count);
    long error=0; unsigned prepared=0;
    for (; prepared<count; prepared++) {
        struct item *item=&items[prepared];
        error=md_read_memory(&messages[prepared].msg_hdr,(void *)(a[1]+prepared*sizeof(*messages)),sizeof(struct msghdr));
        if (error < 0) break;
        messages[prepared].msg_len=UINT_MAX;
        item->original=messages[prepared].msg_hdr;
        if ((int)item->original.msg_namelen<0) { error=-EINVAL; break; }
        size_t capacity=item->original.msg_control?item->original.msg_controllen:0;
        item->size=native_capacity(capacity);
        if (!item->size) { error=-ENOBUFS; break; }
        item->buffer=buffer(item->size,item->local,sizeof(item->local));
        if (!item->buffer) { error=-ENOMEM; break; }
        messages[prepared].msg_hdr.msg_control=item->buffer;
        messages[prepared].msg_hdr.msg_controllen=item->size;
        if (item->original.msg_name) {
            messages[prepared].msg_hdr.msg_name=&item->address;
            messages[prepared].msg_hdr.msg_namelen=sizeof(item->address);
        }
    }
    /* Keep native timeout/MSG_WAITFORONE handling. A late timeout-copy EFAULT
     * does not undo receives; msg_len commits each private, writable entry.
     * User-header faults within a batch still need kernel/publication interlock
     * (rights-batch-fault), not preflight memory writes or message replay. */
    long result=prepared?md_raw(SYS_recvmmsg,a[0],(unsigned long)messages,prepared,a[3],a[4],0):error;
    unsigned completed=0;
    while (completed<prepared && messages[completed].msg_len!=UINT_MAX) ++completed;
    for (unsigned i=0;i<completed;i++) {
        void *destination=(void *)(a[1]+(unsigned long)i*sizeof(*messages));
        struct item *item=&items[i];
        error=publish(fs,(int)a[0],&item->original,messages[i].msg_hdr,destination);
        if (!error) error=md_write_memory((char *)destination+offsetof(struct mmsghdr,msg_len),&messages[i].msg_len,sizeof(unsigned));
        if (error < 0) {
            for (unsigned j=i+1;j<completed;j++) close_rights(&messages[j].msg_hdr);
            result=i?(long)i:error; break;
        }
    }
    for (unsigned i=0;i<count;i++) release(items[i].buffer,items[i].local,items[i].size);
    release(memory,local,size); return result;
}

#define _GNU_SOURCE
#include "socket_ancillary.h"
#include "socket_namespace.h"
#include "ipc_credentials.h"
#include "watch_calls.h"
#include "fs_rpc.h"
#include "fs_buffer.h"
#include "adapter_buffer.h"
#include "task_send.h"
#include "task_receive.h"
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
/* Runs in the short-lived private-table helper. These are our writable native
 * headers, never application msghdrs. No syscall, allocation or caller FD. */
long md_socket_ancillary_collect(struct md_task_receive_frame *frame) {
    frame->count=0;
    while (frame->cursor<frame->input.count) {
        struct msghdr *m;
        if (frame->input.batch) {
            struct mmsghdr *batch=(void *)frame->input.messages;
            if (batch[frame->cursor].msg_len==UINT_MAX) return 0;
            m=&batch[frame->cursor++].msg_hdr;
        } else {
            if (frame->result<0) return 0;
            m=(void *)frame->input.messages; ++frame->cursor;
        }
        for (struct cmsghdr *h=CMSG_FIRSTHDR(m);h;h=next_header(m,h)) {
            if (h->cmsg_len<CMSG_LEN(0)) return -EPROTO;
            if (h->cmsg_level!=SOL_SOCKET || h->cmsg_type!=SCM_RIGHTS) continue;
            size_t n=(h->cmsg_len-CMSG_LEN(0))/sizeof(int);
            if (n>253-frame->count) return -EPROTO;
            int *fds=(void *)CMSG_DATA(h);
            for (unsigned i=0;i<n;++i) {
                frame->descriptors[frame->count++]=fds[i];
                fds[i]=(int)frame->total++;
            }
        }
        if (frame->count) return 1;
    }
    return 0;
}

/* The kernel still transports data and SCM_RIGHTS. An explicit guest credential
 * message adds one sealed, connection-scoped identity capability; the receiving
 * adapter removes it before publishing ancillary data. No stream framing. */
static long message_rpc(const struct md_fs *fs, int socket, int token, struct ucred *out) {
    if (!fs->endpoint[0]) return -ENODATA;
    struct md_fs_request q = {.operation=MD_FS_IPC,
        .flags=MD_IPC_MESSAGE_READ,
        .directory={socket,token}};
    struct md_fs_response reply;
    long r = md_fs_buffer_received(&q, &reply);
    if (!r) r = reply.result.error;
    if (r == -ENOTSUP || r == -EAFNOSUPPORT || r == -EPROTOTYPE) r = -ENODATA;
    if (r) return r;
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
extern long md_guest_buffer_control(unsigned, unsigned long, unsigned long);
struct outgoing {
    struct ucred claimed;
    struct md_task_send send;
    int used;
};
static long use_token(void *context, struct md_fs_buffer_frame *frame) {
    struct outgoing *out=context;
    out->used=1;
    memcpy(frame->value,&out->send,sizeof(out->send));
    return md_guest_buffer_control(MD_FS_BUFFER_TASK_SEND,0,0);
}
static long send_owned(void *context, const unsigned long *a, int anchor) {
    struct outgoing *out=context;
    if (anchor>=0) {
        if (out->send.count==MD_TASK_SEND_INPUTS) return -EINVAL;
        out->send.keep[out->send.count++]=anchor;
    }
    out->send.message=a[1]; out->send.socket=(int)a[0]; out->send.flags=(int)a[2];
    struct md_fs_request q={.operation=MD_FS_IPC,.flags=MD_IPC_MESSAGE_CREATE,
        .directory={(int)a[0],-1},.offset=out->claimed.pid,
        .attributes={.uid=out->claimed.uid,.gid=out->claimed.gid}};
    struct md_fs_response reply={0};
    long r=md_fs_buffer_use(&q,&reply,use_token,out);
    if (out->used) return r;
    if (!r) r=reply.result.error;
    if (r==-ENOTSUP || r==-EAFNOSUPPORT || r==-EPROTOTYPE) r=-ENODATA;
    return r;
}
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
    size_t offset = CMSG_ALIGN(m.msg_controllen), size = offset+CMSG_SPACE(sizeof(int));
    _Alignas(struct cmsghdr) char local[1024];
    void *storage = size < m.msg_controllen ? NULL : buffer(size,local,sizeof(local));
    if (!storage) return -ENOMEM;
    memset(storage,0,size);
    r = md_read_memory(storage,m.msg_control,m.msg_controllen);
    if (!r) {
        struct outgoing out={.send={.count=1,.keep={(int)a[0]}}};
        found=0;
        for (size_t pos=0;m.msg_controllen-pos>=sizeof(struct cmsghdr);) {
            struct cmsghdr *h=(void *)((char *)storage+pos);
            if (h->cmsg_len<CMSG_LEN(0) || h->cmsg_len>m.msg_controllen-pos) { r=-EINVAL; break; }
            if (h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_CREDENTIALS) {
                if (found || h->cmsg_len!=CMSG_LEN(sizeof(claimed))) { r=-EINVAL; break; }
                found=1; credential_offset=pos+CMSG_LEN(0);
                memcpy(&out.claimed,CMSG_DATA(h),sizeof(out.claimed));
            } else if (h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_RIGHTS) {
                size_t count=(h->cmsg_len-CMSG_LEN(0))/sizeof(int);
                if (count>MD_TASK_SEND_INPUTS-out.send.count) { r=-EINVAL; break; }
                memcpy(out.send.keep+out.send.count,CMSG_DATA(h),count*sizeof(int));
                out.send.count+=count;
            }
            if (CMSG_ALIGN(h->cmsg_len)>m.msg_controllen-pos) break;
            pos+=CMSG_ALIGN(h->cmsg_len);
        }
        if (!found) r=-EINVAL;
        if (r) { release(storage,local,size); return r; }
        struct ucred native = {(pid_t)RAW0(getpid),(uid_t)RAW0(getuid),(gid_t)RAW0(getgid)};
        memcpy((char *)storage+credential_offset,&native,sizeof(native));
        struct cmsghdr *h = (void *)((char *)storage+offset);
        *h = (struct cmsghdr){.cmsg_len=CMSG_LEN(sizeof(int)),.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS};
        int fd=-1; memcpy(CMSG_DATA(h),&fd,sizeof(fd));
        out.send.token_slot=(uintptr_t)CMSG_DATA(h);
        m.msg_control=storage; m.msg_controllen=size;
        unsigned long args[6]; memcpy(args,a,sizeof(args)); args[1]=(unsigned long)&m;
        r = md_socket_address_send(fs,exe,args,send_owned,&out);
        if (!out.used && r==-ENODATA) r=md_socket_address_call(fs,exe,SYS_sendmsg,a);
    }
    release(storage,local,size); return r;
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
static long publish_rights(void *out, size_t used, size_t capacity,
        int *fds, size_t count, int *flags, unsigned receive_flags) {
    size_t room=used<capacity?capacity-used:0;
    if (room<CMSG_LEN(sizeof(int))) { *flags|=MSG_CTRUNC; return used; }
    size_t delivered=0;
    long error=md_fs_buffer_publish(fds,(unsigned)count,(char *)out+used,room,receive_flags,flags,&delivered);
    return error ? error : (long)(used+delivered);
}
static long publish(const struct md_fs *fs, int socket, const struct msghdr *original,
        struct msghdr m, void *destination, unsigned receive_flags) {
    size_t capacity=original->msg_control?original->msg_controllen:0;
    struct ucred claimed={0}; int have_claim=0;
    /* Identify capabilities before rebuilding headers: the kernel can coalesce
     * ordinary descriptors and the identity descriptor into one SCM_RIGHTS. */
    for (struct cmsghdr *h=CMSG_FIRSTHDR(&m); h; h=next_header(&m,h)) {
        if (h->cmsg_level!=SOL_SOCKET || h->cmsg_type!=SCM_RIGHTS) continue;
        size_t count=(h->cmsg_len-CMSG_LEN(0))/sizeof(int);
        int *fds=(void *)CMSG_DATA(h);
        for (size_t i=0;i<count;i++) {
            struct ucred value;
            long status=message_rpc(fs,0,fds[i],&value);
            if (!status) { claimed=value; have_claim=1; fds[i]=-1; }
            else if (status != -ENODATA) return status;
        }
    }
    void *out=original->msg_control; size_t used=0;
    for (struct cmsghdr *h=CMSG_FIRSTHDR(&m); h; h=next_header(&m,h)) {
        const void *data=CMSG_DATA(h); size_t n=h->cmsg_len-CMSG_LEN(0);
        if (h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_CREDENTIALS && n==sizeof(claimed) && have_claim) data=&claimed;
        if (h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_RIGHTS) {
            int *fds=(void *)CMSG_DATA(h); size_t count=0;
            for (size_t i=0;i<n/sizeof(int);i++) if (fds[i]>=0) fds[count++]=fds[i];
            for (size_t i=count;i<n/sizeof(int);i++) fds[i]=-1;
            if (!count) continue;
            long published=publish_rights(out,used,capacity,fds,count,&m.msg_flags,receive_flags);
            if (published<0) return published;
            used=(size_t)published;
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
static long receive_owned(struct md_task_receive input, int *accepted) {
    *accepted=0;
    long address=md_adapter_buffer_take();
    if (address<0) return address;
    struct md_task_receive_frame *frame=(void *)address;
    frame->input=input;
    long result=md_guest_buffer_control(MD_FS_BUFFER_TASK_RECEIVE,0,0);
    if (!result) { *accepted=1; result=frame->result; }
    long released=md_adapter_buffer_release();
    return result<0 ? result : released ? released : result;
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
    int accepted=0;
    r=receive_owned((struct md_task_receive){.socket=(int)a[0],.messages=(uintptr_t)&m,
        .flags=(int)a[2],.count=1},&accepted);
    if (accepted && r >= 0) {
        long error=publish(fs,(int)a[0],&original,m,(void *)a[1],(unsigned)a[2]);
        if (error < 0) r=error;
    }
    md_guest_buffer_control(MD_FS_BUFFER_RECEIVED_DROP,0,0);
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
    int accepted=0;
    long result=prepared ? receive_owned((struct md_task_receive){.socket=(int)a[0],
        .messages=(uintptr_t)messages,.count=prepared,.batch=1,.flags=(int)a[3],.timeout=a[4]},&accepted) : error;
    unsigned completed=0;
    while (accepted && completed<prepared && messages[completed].msg_len!=UINT_MAX) ++completed;
    for (unsigned i=0;i<completed;i++) {
        void *destination=(void *)(a[1]+(unsigned long)i*sizeof(*messages));
        struct item *item=&items[i];
        error=publish(fs,(int)a[0],&item->original,messages[i].msg_hdr,destination,(unsigned)a[3]);
        if (!error) error=md_write_memory((char *)destination+offsetof(struct mmsghdr,msg_len),&messages[i].msg_len,sizeof(unsigned));
        if (error < 0) {
            result=i?(long)i:error; break;
        }
    }
    if (prepared) md_guest_buffer_control(MD_FS_BUFFER_RECEIVED_DROP,0,0);
    for (unsigned i=0;i<count;i++) release(items[i].buffer,items[i].local,items[i].size);
    release(memory,local,size); return result;
}

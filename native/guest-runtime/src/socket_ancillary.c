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
#include "task_outgoing.h"
#include "interception.h"
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
static void *buffer(size_t size, void *local, size_t capacity) {
    if (size <= capacity) return local;
    if (size > 16*1024*1024) return NULL;
    long p = RAW6(mmap, 0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p < 0 ? NULL : (void *)p;
}
static void release(void *p, void *local, size_t size) { if (p && p != local) RAW2(munmap,p,size); }
extern long md_guest_buffer_control(unsigned, unsigned long, unsigned long);
static long capture_inputs(long state, struct md_fd_capture_frame *f, const int *numbers, unsigned count) {
    while (state>0 && state!=MD_IPC_TASK_IO) {
        if (state==MD_FD_CAPTURE_ADMIT) {
            /* Admission must not turn an originally invalid source slot into
             * the infrastructure endpoint. The source-table turn is held. */
            for (unsigned i=0;i<count;++i) {
                long valid=RAW2(fcntl,numbers[i],F_GETFD);
                if (valid<0) return md_guest_buffer_control(MD_FS_BUFFER_IPC_CAPTURE_SENT,valid,0);
            }
            long fd=md_guest_buffer_admit(MD_FS_BUFFER_IPC_ADMIT);
            if (fd<0) return md_guest_buffer_control(MD_FS_BUFFER_IPC_CAPTURE_SENT,fd,0);
            state=md_guest_buffer_control(MD_FS_BUFFER_IPC_CAPTURE_READY,0,0);
        } else if (state==MD_FD_CAPTURE_CHECK) {
            struct md_fd_channel_observation *o=&f->observation;
            *o=(struct md_fd_channel_observation){.length=sizeof(o->cookie)};
            long flags=RAW2(fcntl,f->endpoint,F_GETFD);
            o->error=flags<0 ? (int)flags : (int)RAW5(getsockopt,f->endpoint,SOL_SOCKET,SO_COOKIE,&o->cookie,&o->length);
            if (flags>=0) o->flags=(unsigned)flags;
            state=md_guest_buffer_control(MD_FS_BUFFER_IPC_CAPTURE_OBSERVED,0,0);
        } else if (state==MD_FD_CAPTURE_SEND) {
            if (!f->count || f->count>253 || f->offset>count || f->count>count-f->offset) return -EPROTO;
            _Alignas(struct cmsghdr) char control[CMSG_SPACE(253*sizeof(int))];
            struct iovec data={&f->token,sizeof(f->token)};
            struct msghdr m={.msg_iov=&data,.msg_iovlen=1,.msg_control=control,
                .msg_controllen=CMSG_SPACE(f->count*sizeof(int))};
            memset(control,0,m.msg_controllen);
            struct cmsghdr *h=CMSG_FIRSTHDR(&m);
            *h=(struct cmsghdr){.cmsg_len=CMSG_LEN(f->count*sizeof(int)),.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS};
            memcpy(CMSG_DATA(h),numbers+f->offset,f->count*sizeof(int));
            long sent=RAW3(sendmsg,f->endpoint,&m,MSG_DONTWAIT|MSG_NOSIGNAL);
            state=md_guest_buffer_control(MD_FS_BUFFER_IPC_CAPTURE_SENT,sent,0);
        } else return -EPROTO;
    }
    return state;
}
static long io_transfer(struct md_ipc_io_message *io, void *memory, size_t size,
        size_t offset, int control, int reading, int large) {
    char *small=control ? io->control : io->data;
    size_t capacity=control ? sizeof(io->control) : sizeof(io->data);
    while (size) {
        size_t n=size<capacity ? size : capacity;
        if (!large && (offset>capacity || n>capacity-offset)) return -EINVAL;
        void *part=small+(large ? 0 : offset);
        io->offset=offset; io->length=n;
        io->transfer=(control ? MD_IPC_IO_CONTROL_BYTES : 0)|(reading ? MD_IPC_IO_READ_BYTES : 0);
        long error=reading && large ? md_guest_buffer_control(MD_FS_BUFFER_IPC_IO_COPY,0,0) : 0;
        if (!error) error=reading ? md_write_memory(memory,part,n) : md_read_memory(part,memory,n);
        if (!error && !reading && large) error=md_guest_buffer_control(MD_FS_BUFFER_IPC_IO_COPY,0,0);
        if (error) return error;
        memory=(char *)memory+n; size-=n; offset+=n;
    }
    return 0;
}
struct io_vectors { struct iovec local[8], *items; size_t bytes; };
static long io_vectors_open(struct io_vectors *vectors, struct msghdr *m) {
    if (m->msg_iovlen>1024) return -EMSGSIZE;
    vectors->bytes=m->msg_iovlen*sizeof(struct iovec);
    vectors->items=buffer(vectors->bytes,vectors->local,sizeof(vectors->local));
    if (!vectors->items) return -ENOMEM;
    long error=md_read_memory(vectors->items,m->msg_iov,vectors->bytes);
    if (error) release(vectors->items,vectors->local,vectors->bytes);
    else m->msg_iov=vectors->items;
    return error;
}
static void io_vectors_close(struct io_vectors *vectors) {
    release(vectors->items,vectors->local,vectors->bytes);
}
static long io_prepare(struct md_ipc_io_message *io, const struct msghdr *m, int sending) {
    if (m->msg_iovlen>1024) return -EMSGSIZE;
    if (m->msg_namelen>sizeof(io->address)) return -EINVAL;
    io->size=0; io->control_size=m->msg_controllen;
    io->address_size=m->msg_name ? m->msg_namelen : 0; io->flags=0;
    for (size_t i=0;i<m->msg_iovlen;++i) {
        struct iovec v=m->msg_iov[i];
        if (v.iov_len>INT_MAX-io->size) return -EMSGSIZE;
        io->size+=v.iov_len;
    }
    long error=md_guest_buffer_control(MD_FS_BUFFER_IPC_IO_PREPARE,0,0);
    if (error) return error;
    if (!sending) return 0;
    size_t offset=0;
    for (size_t i=0;i<m->msg_iovlen;++i) {
        struct iovec v=m->msg_iov[i];
        if (v.iov_len>io->size-offset) return -EINVAL;
        error=io_transfer(io,v.iov_base,v.iov_len,offset,0,0,io->size>sizeof(io->data));
        if (error) return error;
        offset+=v.iov_len;
    }
    error=io_transfer(io,m->msg_control,io->control_size,0,1,0,io->control_size>sizeof(io->control));
    if (error) return error;
    if (md_read_memory(&io->address,m->msg_name,io->address_size)) return -EFAULT;
    return 0;
}
static long io_scatter(struct md_ipc_io_message *io, struct msghdr *m, long result, int batch) {
    if (result<0) return result;
    size_t copied=0, remaining=(size_t)result<io->size ? (size_t)result : io->size;
    for (size_t i=0;remaining && i<m->msg_iovlen;++i) {
        struct iovec v=m->msg_iov[i];
        size_t n=v.iov_len<remaining ? v.iov_len : remaining;
        long error=io_transfer(io,v.iov_base,n,copied,0,1,batch || io->size>sizeof(io->data));
        if (error) return error;
        copied+=n; remaining-=n;
    }
    if (io->control_size>m->msg_controllen || io->address_size>sizeof(io->address)) return -EPROTO;
    long error=io_transfer(io,m->msg_control,io->control_size,0,1,1,batch || m->msg_controllen>sizeof(io->control));
    if (error) return error;
    if (m->msg_name && md_write_memory(m->msg_name,&io->address,
            m->msg_namelen<io->address_size ? m->msg_namelen : io->address_size)) return -EFAULT;
    m->msg_controllen=io->control_size; m->msg_namelen=io->address_size; m->msg_flags=io->flags;
    return result;
}
static long send_captured(const struct msghdr *original, const unsigned long *a,
        void *control, size_t capacity, const struct iovec *sendto) {
    long address=md_adapter_buffer_take();
    if (address<0) return address;
    struct md_task_outgoing_frame *frame=(void *)address;
    frame->message=*original;
    frame->options=(struct md_ipc_send_options){.addressed=original->msg_name!=NULL,
        .length=original->msg_name ? original->msg_namelen : 0};
    frame->input=(struct md_task_send){.message=(uintptr_t)&frame->message,
        .token_slot=(uintptr_t)control+CMSG_LEN(0),
        .socket=(int)a[0],.flags=(int)a[2],.count=1,.keep={(int)a[0]}};
    if (sendto) { frame->input.sendto=1; frame->input.payload=*sendto; }
    long result=frame->options.length>sizeof(frame->options.address) ? -EINVAL :
        md_read_memory(&frame->options.address,original->msg_name,frame->options.length);
    size_t misc=0, credential_offset=0;
    /* Copy and normalize once. All non-right headers retain their bytes and
     * order; the kernel remains responsible for their protocol validation. */
    for (size_t pos=0;!result && original->msg_controllen-pos>=sizeof(struct cmsghdr);) {
        struct cmsghdr h;
        if (md_read_memory(&h,(char *)original->msg_control+pos,sizeof(h))<0) { result=-EFAULT; break; }
        if (h.cmsg_len<CMSG_LEN(0) || h.cmsg_len>original->msg_controllen-pos) { result=-EINVAL; break; }
        if (h.cmsg_level==SOL_SOCKET && h.cmsg_type==SCM_RIGHTS) {
            size_t count=(h.cmsg_len-CMSG_LEN(0))/sizeof(int);
            if (count>MD_TASK_SEND_INPUTS-frame->input.count) { result=-EINVAL; break; }
            result=md_read_memory(frame->input.keep+frame->input.count,
                (char *)original->msg_control+pos+CMSG_LEN(0),count*sizeof(int));
            frame->input.count+=count;
        } else {
            size_t step=CMSG_ALIGN(h.cmsg_len);
            if (step>capacity-misc) { result=-EINVAL; break; }
            result=md_read_memory((char *)control+misc,(char *)original->msg_control+pos,h.cmsg_len);
            if (result) break;
            memset((char *)control+misc+h.cmsg_len,0,step-h.cmsg_len);
            if (h.cmsg_level==SOL_SOCKET && h.cmsg_type==SCM_CREDENTIALS) {
                if (frame->options.credentials || h.cmsg_len!=CMSG_LEN(sizeof(struct ucred))) { result=-EINVAL; break; }
                frame->options.credentials=1; credential_offset=misc+CMSG_LEN(0);
                memcpy(&frame->options.claimed,(char *)control+credential_offset,sizeof(struct ucred));
            }
            misc+=step;
        }
        if (CMSG_ALIGN(h.cmsg_len)>original->msg_controllen-pos) break;
        pos+=CMSG_ALIGN(h.cmsg_len);
    }
    if (!result) result=capture_inputs(md_guest_buffer_control(MD_FS_BUFFER_SEND_PREPARE,0,0),
        &frame->scratch.capture.capture,frame->input.keep,frame->input.count);
    if (!result) {
        unsigned data=frame->input.count-1;
        unsigned expected=(frame->transport==MD_IPC_TRANSPORT_ORIGINS_V1 && data ? 1 : data)
            +frame->destination.credentials;
        size_t rights=frame->rights ? CMSG_SPACE(frame->rights*sizeof(int)) : 0;
        if (frame->rights>253 || frame->rights!=expected || rights>capacity-misc) result=-EPROTO;
        else {
            if (frame->destination.credentials && frame->options.credentials) {
                struct ucred native={(pid_t)RAW0(getpid),(uid_t)RAW0(getuid),(gid_t)RAW0(getgid)};
                memcpy((char *)control+credential_offset,&native,sizeof(native));
            }
            if (misc) memmove((char *)control+rights,control,misc);
            /* recvmsg in the private helper fills the initial rights block. */
            frame->message.msg_control=rights+misc ? control : NULL;
            frame->message.msg_controllen=rights+misc;
            if (frame->brokered && rights) {
                struct cmsghdr *h=control;
                memset(control,0,rights);
                *h=(struct cmsghdr){.cmsg_len=CMSG_LEN(frame->rights*sizeof(int)),
                    .cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS};
            }
            if (frame->options.addressed) {
                frame->message.msg_name=&frame->destination.address;
                frame->message.msg_namelen=frame->destination.length;
            }
            if (frame->brokered) {
                struct io_vectors vectors;
                struct msghdr view=frame->message;
                frame->scratch.capture.io.batch_count=0;
                result=io_vectors_open(&vectors,&view);
                if (!result) {
                    result=io_prepare(&frame->scratch.capture.io,&view,1);
                    io_vectors_close(&vectors);
                }
            }
            if (!result) result=md_guest_buffer_control(MD_FS_BUFFER_SEND_COMMIT,0,0);
        }
    }
    long released=md_adapter_buffer_release();
    return result<0 ? result : released ? released : result;
}
long md_socket_ancillary_send(const struct md_fs *fs, const char *exe, const unsigned long *a) {
    struct msghdr m;
    long r = md_read_memory(&m, (void *)a[1], sizeof(m));
    if (r < 0 || !fs->endpoint[0] || ((!m.msg_control || !m.msg_controllen) && !m.msg_name))
        return md_socket_address_call(fs, exe, SYS_sendmsg, a);
    if (!m.msg_control || !m.msg_controllen) {
        sa_family_t family;
        if (m.msg_namelen<sizeof(family) || m.msg_namelen>sizeof(struct sockaddr_storage)
                || md_read_memory(&family,m.msg_name,sizeof(family)) || family!=AF_UNIX)
            return md_socket_address_call(fs,exe,SYS_sendmsg,a);
    }
    size_t size=CMSG_ALIGN(m.msg_controllen)+CMSG_SPACE(253*sizeof(int));
    _Alignas(struct cmsghdr) char local[4096];
    void *storage = size < m.msg_controllen ? NULL : buffer(size,local,sizeof(local));
    if (!storage) return -ENOMEM;
    r=send_captured(&m,a,storage,size,NULL);
    release(storage,local,size); return r;
}
long md_socket_ancillary_sendto(const struct md_fs *fs, const char *exe, const unsigned long *a) {
    sa_family_t family;
    if (!fs->endpoint[0] || !a[4] || a[5]<sizeof(family) || a[5]>sizeof(struct sockaddr_storage)
            || md_read_memory(&family,(void *)a[4],sizeof(family)) || family!=AF_UNIX)
        return md_socket_address_call(fs,exe,SYS_sendto,a);
    struct iovec payload={(void *)a[1],a[2]};
    struct msghdr message={.msg_name=(void *)a[4],.msg_namelen=(unsigned)a[5],.msg_iov=&payload,.msg_iovlen=1};
    unsigned long args[6]={a[0],(uintptr_t)&message,a[3]};
    return send_captured(&message,args,NULL,0,&payload);
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
        int *fds, const unsigned char *watched, size_t count, int *flags, unsigned receive_flags) {
    size_t room=used<capacity?capacity-used:0;
    if (room<CMSG_LEN(sizeof(int))) { *flags|=MSG_CTRUNC; return used; }
    size_t delivered=0;
    long error=md_fs_buffer_publish(fds,watched,(unsigned)count,(char *)out+used,room,receive_flags,flags,&delivered);
    return error ? error : (long)(used+delivered);
}
static long publish(const struct md_fs *fs, int socket, const struct msghdr *original,
        struct msghdr m, void *destination, unsigned receive_flags) {
    size_t capacity=original->msg_control?original->msg_controllen:0;
    struct ucred claimed={0}; int have_claim=0;
    int indices[253]; struct md_received_message plan; unsigned entries=0;
    plan.count=0;
    for (struct cmsghdr *h=CMSG_FIRSTHDR(&m);h;h=next_header(&m,h)) {
        if (h->cmsg_level!=SOL_SOCKET || h->cmsg_type!=SCM_RIGHTS) continue;
        size_t count=(h->cmsg_len-CMSG_LEN(0))/sizeof(int);
        if (count>253-entries) return -EPROTO;
        memcpy(indices+entries,CMSG_DATA(h),count*sizeof(int)); entries+=count;
    }
    if (entries) {
        long error=md_fs_buffer_inspect(indices,entries,&plan);
        if (error) return error;
        if (plan.count>254 || plan.first[0] || plan.first[entries]!=plan.count) return -EPROTO;
        for (unsigned i=0;i<entries;++i)
            if (plan.first[i]>plan.first[i+1] || plan.first[i+1]>plan.count) return -EPROTO;
    }
    /* Identify capabilities before rebuilding headers: the kernel can coalesce
     * ordinary descriptors and the identity descriptor into one SCM_RIGHTS. */
    for (unsigned i=0;i<plan.count;++i) if (plan.entries[i].flags&MD_RECEIVED_CREDENTIALS) {
        claimed=plan.entries[i].credentials; have_claim=1;
    }
    unsigned entry=0;
    void *out=original->msg_control; size_t used=0;
    for (struct cmsghdr *h=CMSG_FIRSTHDR(&m); h; h=next_header(&m,h)) {
        const void *data=CMSG_DATA(h); size_t n=h->cmsg_len-CMSG_LEN(0);
        if (h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_CREDENTIALS && n==sizeof(claimed) && have_claim) data=&claimed;
        if (h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_RIGHTS) {
            size_t count=0; unsigned char watched[253];
            for (size_t i=0;i<n/sizeof(int);i++,entry++) {
                for (unsigned j=plan.first[entry];j<plan.first[entry+1];++j) {
                    const struct md_received_info *info=&plan.entries[j];
                    if (info->flags&MD_RECEIVED_CREDENTIALS) continue;
                    if (count==253 || info->index<0) return -EPROTO;
                    watched[count]=!!(info->flags&MD_RECEIVED_WATCH);
                    indices[count++]=info->index;
                }
            }
            if (!count) continue;
            long published=publish_rights(out,used,capacity,indices,watched,count,&m.msg_flags,receive_flags);
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
static long receive_batch_owned(struct md_task_receive_frame *frame, int *accepted) {
    struct md_task_receive *input=&frame->input;
    struct mmsghdr *messages=(void *)input->messages;
    struct entry { struct io_vectors vectors; struct msghdr view; int opened; };
    struct entry local[4];
    size_t size=input->count*sizeof(struct entry);
    struct entry *entries=buffer(size,local,sizeof(local));
    if (!entries) return -ENOMEM;
    struct md_ipc_io_message *io=&frame->io;
    io->timed=input->timeout!=0; io->timeout=(struct timespec){0};
    long result=input->timeout ? md_read_memory(&io->timeout,(void *)input->timeout,sizeof(io->timeout)) : 0;
    unsigned prepared=0;
    while (!result && prepared<input->count) {
        struct entry *entry=&entries[prepared];
        *entry=(struct entry){0};
        entry->view=messages[prepared].msg_hdr;
        result=(int)entry->view.msg_namelen<0 ? -EINVAL : io_vectors_open(&entry->vectors,&entry->view);
        io->batch_count=input->count; io->batch_index=prepared;
        io->vector_error=(int)result;
        if (result==-EFAULT || result==-EMSGSIZE || result==-EINVAL) {
            io->size=io->control_size=io->address_size=0;
            result=md_guest_buffer_control(MD_FS_BUFFER_IPC_IO_PREPARE,0,0);
            ++prepared; break;
        }
        if (result) break;
        entry->opened=1; ++prepared;
        result=io_prepare(io,&entry->view,0);
    }
    if (!result) {
        result=md_guest_buffer_control(MD_FS_BUFFER_IPC_RECEIVE,0,0); *accepted=1;
        unsigned completed=io->batch_count;
        if (completed>input->count) result=-EPROTO;
        else for (unsigned i=0;i<completed;++i) {
            io->batch_index=i;
            long length=md_guest_buffer_control(MD_FS_BUFFER_IPC_IO_SELECT,0,0);
            if (length>=0) length=io_scatter(io,&entries[i].view,length,1);
            if (length<0) { result=i ? (long)i : length; break; }
            messages[i].msg_hdr.msg_namelen=entries[i].view.msg_namelen;
            messages[i].msg_hdr.msg_controllen=entries[i].view.msg_controllen;
            messages[i].msg_hdr.msg_flags=entries[i].view.msg_flags;
            messages[i].msg_len=(unsigned)length;
        }
        if (input->timeout && result>=0 && md_write_memory((void *)input->timeout,&io->timeout,sizeof(io->timeout)))
            result=-EFAULT;
    }
    for (unsigned i=0;i<prepared;++i) if (entries[i].opened) io_vectors_close(&entries[i].vectors);
    release(entries,local,size); return result;
}
static long receive_owned(struct md_task_receive input, int *accepted) {
    *accepted=0;
    long address=md_adapter_buffer_take();
    if (address<0) return address;
    struct md_task_receive_frame *frame=(void *)address;
    frame->input=input;
    long result=capture_inputs(md_guest_buffer_control(MD_FS_BUFFER_TASK_RECEIVE,0,0),
        &frame->capture,&frame->input.socket,1);
    if (result==MD_IPC_TASK_IO) {
        if (input.batch) result=receive_batch_owned(frame,accepted);
        else {
            struct msghdr *m=(void *)input.messages;
            struct msghdr view=*m;
            struct io_vectors vectors;
            frame->io.batch_count=0;
            result=io_vectors_open(&vectors,&view);
            if (!result) {
                result=io_prepare(&frame->io,&view,0);
                if (!result) {
                    result=md_guest_buffer_control(MD_FS_BUFFER_IPC_RECEIVE,0,0);
                    *accepted=1;
                    result=io_scatter(&frame->io,&view,result,0);
                    m->msg_namelen=view.msg_namelen; m->msg_controllen=view.msg_controllen; m->msg_flags=view.msg_flags;
                }
                io_vectors_close(&vectors);
            }
        }
    } else if (!result) { *accepted=1; result=frame->result; }
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
        messages[prepared].msg_len=UINT_MAX;
        error=md_read_memory(&messages[prepared].msg_hdr,(void *)(a[1]+prepared*sizeof(*messages)),sizeof(struct msghdr));
        if (error < 0) {
            /* Keep failed input validation inside the native batch, after its
             * successful prefix and before consuming the faulting message. */
            messages[prepared++].msg_hdr=(struct msghdr){.msg_iov=NULL,.msg_iovlen=1};
            break;
        }
        item->original=messages[prepared].msg_hdr;
        if ((int)item->original.msg_namelen<0) { ++prepared; break; }
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

#include "fs_buffer.h"
#include "adapter_buffer.h"
#include "fs_wire.h"
#include "interception.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>

extern long md_guest_buffer_control(unsigned, unsigned long, unsigned long);
extern long md_guest_open_anchor(int, const char *, int, unsigned, int);
int md_fs_buffer_accepts(const struct md_fs_request *q) {
    return md_adapter_buffer_ready() && q && md_fs_buffer_operation(q->operation);
}
static long check_channels(struct md_fs_buffer_frame *frame, long result) {
    /* EVENT_WAIT: each reply selects one ambiguous slot under the table turn;
     * cancellation keeps that slot uncertain, never admits another channel. */
    while (result==MD_FS_BUFFER_CHANNEL_CHECK) {
        int fd=frame->channel.number;
        struct md_fd_channel_observation *o=&frame->channel.observation;
        *o=(struct md_fd_channel_observation){.length=sizeof(o->cookie)};
        long flags=RAW3(fcntl,fd,F_GETFD,0);
        o->error=flags<0 ? (int)flags : (int)RAW5(getsockopt,fd,SOL_SOCKET,SO_COOKIE,&o->cookie,&o->length);
        if (!o->error) o->flags=(unsigned)flags;
        result=md_guest_buffer_control(MD_FS_BUFFER_CHANNEL_OBSERVED,0,0);
    }
    return result;
}
static long receive_rights(struct md_fs_buffer_frame *frame, unsigned flags) {
    struct md_fd_receipt *receipt=(void *)frame->receipt;
    int error=md_fd_receipt_reset(receipt,1);
    if (error) return error;
    frame->receive.token=0; frame->receive.number=-1;
    receipt->vector=(struct iovec){&frame->receive.token,sizeof(frame->receive.token)};
    long result=check_channels(frame,md_guest_buffer_control(MD_FS_BUFFER_RIGHTS_BEGIN,0,0));
    if (!result && frame->receive.number<0) {
        result=RAW2(prctl,MD_GUEST_BUFFER,MD_FS_BUFFER_IMPORT);
        if (result>=0) result=md_guest_buffer_control(MD_FS_BUFFER_RIGHTS_READY,0,0);
    }
    if (!result) result=RAW3(recvmsg,frame->receive.number,&receipt->message,
        MSG_DONTWAIT|((flags&O_CLOEXEC) ? MSG_CMSG_CLOEXEC : 0));
    return md_guest_buffer_control(MD_FS_BUFFER_RIGHTS_DONE,(unsigned long)result,0);
}
static long receive_result(struct md_fs_buffer_frame *frame, const struct md_fs_request *q,
        struct md_fs_response *out, int (*deliver)(void *, const void *, size_t), void *context) {
    long result=0;
    out->delivery=frame->reply.delivery;
    out->result=frame->reply.result;
    const void *data=md_fs_operation_value(q->operation) ? (const void *)frame->value : frame->reply.data;
    size_t capacity=md_fs_operation_value(q->operation) ? sizeof(frame->value) : sizeof(out->data);
    if (out->result.size<=sizeof(out->data))
        memcpy(out->data,data,out->result.size);
    unsigned transfer=frame->transfer;
    unsigned descriptors=transfer!=MD_FS_BUFFER_NO_FD;
    if (out->delivery!=MD_FS_REPLIED || out->result.fd!=-1 || out->result.open_completion.kind
            || transfer>MD_FS_BUFFER_TASK_PATH
            || !md_fs_result_valid(q,&out->result,data,capacity,descriptors)) result=-EPROTO;
    else if (transfer==MD_FS_BUFFER_TASK_PATH) {
        if (q->operation!=MD_FS_TASK_PATH || frame->source[sizeof(frame->source)-1]
                || !md_prefix(frame->source,"/proc/")) result=-EPROTO;
        else if (q->mode==MD_FS_TASK_CHDIR) out->result.error=(int)RAW1(chdir,frame->source);
        else if (q->mode==MD_FS_TASK_FCHDIR) {
            long changed=RAW1(fchdir,q->directory[0]);
            long completed=md_guest_buffer_control(MD_FS_BUFFER_TASK_DONE,(unsigned long)changed,0);
            out->result.error=(int)(completed ? completed : changed);
        }
        else if (q->mode==MD_FS_TASK_TRUNCATE) out->result.error=(int)RAW2(truncate,frame->source,q->offset);
        else result=-EPROTO;
    }
    else if (transfer==MD_FS_BUFFER_ADDFD) {
        long fd=RAW1(prctl,MD_GUEST_BUFFER);
        if (fd<0) out->result.error=(int)fd;
        else out->result.fd=(int)fd;
    } else if (transfer==MD_FS_BUFFER_RIGHTS) {
        long fd=receive_rights(frame,q->flags);
        if (fd<0) out->result.error=(int)fd;
        else out->result.fd=(int)fd;
    } else if (transfer==MD_FS_BUFFER_ANCHOR) {
        if (frame->source[sizeof(frame->source)-1] || !md_prefix(frame->source,"/proc/")) result=-EPROTO;
        else {
            long fd=md_guest_open_anchor(AT_FDCWD,frame->source,
                O_PATH|(q->flags&(O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW)),0,MD_FS_BUFFER_SOURCE);
            if (fd<0) out->result.error=(int)fd;
            else out->result.fd=(int)fd;
        }
    }
    if ((q->operation==MD_FS_WATCH_READ || q->operation==MD_FS_GETDENTS) && !out->result.error) {
        int copied=result ? (int)result : deliver ? deliver(context,out->data,out->result.size) : 0;
        long committed=md_guest_buffer_control(MD_FS_BUFFER_ACK,(unsigned long)(long)copied,0);
        if (committed) out->delivery=MD_FS_UNCONFIRMED;
        result=copied ? copied : committed;
    }
    if (!result && !out->result.error && !out->result.host_path && md_fs_operation_value(q->operation)) {
        if (deliver) result=deliver(context,data,out->result.size);
        else if (out->result.size>sizeof(out->data)) result=-EOVERFLOW;
    }
    return result;
}
static long exchange(const struct md_fs_request *q, struct md_fs_response *out,
        int (*deliver)(void *, const void *, size_t), void *context, unsigned command,
        struct md_command_recipe *recipe) {
    long address=md_adapter_buffer_take();
    if (address<0) return address;
    struct md_fs_buffer_frame *frame=(void *)address;
    long result=0;
    frame->input.base[0]=q->directory[0]; frame->input.base[1]=q->directory[1];
    frame->input.flags=q->flags; frame->input.mode=q->mode; frame->input.capacity=q->capacity;
    frame->input.resolve=q->resolve; frame->input.offset=q->offset;
    frame->input.attributes=q->attributes;
    frame->input.value_size=q->value_size;
    if (q->value_size>MD_FS_VALUE_MAX) result=-EINVAL;
    else if (q->value_size) result=md_read_memory(frame->value,q->value,q->value_size);
    frame->input.length[0]=frame->input.length[1]=0;
    for (unsigned i=0;i<2 && !result;++i) {
        frame->input.capture_length[i]=0;
        frame->input.capture_flags[i]=q->capture[i].flags;
        if (q->capture[i].path) {
            size_t n=md_length(q->capture[i].path);
            if (n>=PATH_MAX) { result=-ENAMETOOLONG; break; }
            frame->input.capture_length[i]=n+1;
            memcpy(frame->input.capture_path[i],q->capture[i].path,n+1);
        }
        frame->input.object[i][0]=0;
        if (q->object[i]) {
            if (!md_fs_object_id_valid(q->object[i])) { result=-EINVAL; break; }
            memcpy(frame->input.object[i],q->object[i],33);
        }
        if (!q->path[i]) continue;
        size_t n=0;
        while (q->path[i][n] && n<PATH_MAX-1) ++n;
        if (q->path[i][n]) result=-ENAMETOOLONG;
        else {
            frame->input.length[i]=n+1;
            memcpy(frame->input.path[i],q->path[i],n+1);
        }
    }
    if (!result) result=check_channels(frame,md_guest_buffer_control(command,q->operation,0));
    if (result==MD_FS_BUFFER_EXPORT) {
        uint64_t request=frame->export.request;
        unsigned mask=frame->export.mask;
        long fd=frame->export.number;
        long sent=-EPROTO;
        if (request && mask && !(mask&~3U)) {
            if (fd<0) fd=RAW2(prctl,MD_GUEST_BUFFER,MD_FS_BUFFER_EXPORT);
            struct md_fs_rights rights={0};
            for (unsigned i=0;i<2;++i)
                if (mask&(1U<<i)) rights.fd[rights.count++]=q->directory[i];
            sent=fd<0 ? fd : md_fs_send((int)fd,&request,sizeof(request),&rights);
            if (sent>=0) sent=sent==sizeof(request) ? 0 : -EIO;
        }
        result=md_guest_buffer_control(MD_FS_BUFFER_SENT,(unsigned long)sent,0);
    }
    if (!result && recipe) memcpy(recipe,&frame->command,sizeof(*recipe));
    if (!result && out) result=receive_result(frame,q,out,deliver,context);
    long released=md_adapter_buffer_release();
    return result ? result : released;
}
long md_fs_buffer_proc_link(int process, void *out, size_t capacity) {
    if (process<=0 || !capacity) return -EINVAL;
    long address=md_adapter_buffer_take();
    if (address<0) return address;
    struct md_fs_buffer_frame *frame=(void *)address;
    long result=md_guest_buffer_control(MD_FS_BUFFER_PROC_LINK,(unsigned)process,0);
    if (result>=0) {
        if (result>=PATH_MAX || (size_t)result>=sizeof(frame->reply.data)) result=-EPROTO;
        else {
            size_t count=(size_t)result<capacity ? (size_t)result : capacity;
            long error=md_write_memory(out,frame->reply.data,count);
            result=error<0 ? error : (long)count;
        }
    }
    long released=md_adapter_buffer_release();
    return result<0 ? result : released ? released : result;
}
long md_fs_buffer_snapshot(unsigned flags, long (*produce)(void *, void *, size_t), void *context) {
    if (!produce) return -EINVAL;
    long address=md_adapter_buffer_take();
    if (address<0) return address;
    struct md_fs_buffer_frame *frame=(void *)address;
    long result=md_guest_buffer_control(MD_FS_BUFFER_SNAPSHOT_BEGIN,flags,0);
    while (!result) {
        long size=produce(context,frame->snapshot.data,sizeof(frame->snapshot.data));
        if (size<0) { result=size; break; }
        if (!size) break;
        if ((size_t)size>sizeof(frame->snapshot.data)) { result=-EOVERFLOW; break; }
        frame->snapshot.size=(size_t)size;
        result=md_guest_buffer_control(MD_FS_BUFFER_SNAPSHOT_APPEND,0,0);
    }
    struct md_fs_response out={0};
    if (!result) result=md_guest_buffer_control(MD_FS_BUFFER_SNAPSHOT_FINISH,0,0);
    if (!result) {
        struct md_fs_request q={.operation=MD_FS_TEMPORARY,.directory={-1,-1},.flags=flags};
        result=receive_result(frame,&q,&out,NULL,NULL);
        if (!result) result=out.result.error;
    }
    long released=md_adapter_buffer_release();
    return result ? result : released ? released : out.result.fd;
}
long md_fs_buffer_call(const struct md_fs_request *q, struct md_fs_response *out,
        int (*deliver)(void *, const void *, size_t), void *context) {
    if (!md_fs_buffer_accepts(q)) return -EINVAL;
    return exchange(q,out,deliver,context,MD_FS_BUFFER_CALL,NULL);
}
long md_fs_buffer_exec_prepare(const struct md_fs_request *q, struct md_command_recipe *recipe) {
    return exchange(q,NULL,NULL,NULL,MD_FS_BUFFER_EXEC_PREPARE,recipe);
}
void md_fs_buffer_exec_cancel(void) {
    md_guest_buffer_control(MD_FS_BUFFER_EXEC_CANCEL,0,0);
}

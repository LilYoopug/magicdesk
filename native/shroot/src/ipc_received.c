#include "ipc_received.h"
#include "ipc_capsule.h"
#include "fs_engine.h"
#include "fd_selector.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static int unrecognized(int error) {
    return error==-ENODATA || error==-ENOTSUP || error==-EAFNOSUPPORT || error==-EPROTOTYPE;
}
static int selectors(struct md_fs_context *context, const struct md_received_fds *source,
        unsigned index, unsigned *out) {
    struct md_fd_object *origin=source->origins ? source->origins[index] : NULL;
    unsigned mask=md_fd_object_selectors(origin);
    if (mask) { *out=mask; return 0; }
    struct md_fs_request q={.actor=context->actor,.peer=context->peer,
        .operation=MD_FS_WATCH_CONTAINS,.directory={source->fds[index],-1}};
    struct md_fs_result result;
    md_fs_context_execute(context,&q,&result,NULL);
    if (!result.error && result.position) *out|=1U<<MD_FD_SELECTOR_WATCH;
    return result.error;
}
static int native_entry(struct md_fs_context *context,const struct md_received_fds *source,
        unsigned index,int adapted,struct md_received_info *entry,struct md_received_fds **data) {
    entry->index=(int)index;
    int error=selectors(context,source,index,&entry->selectors);
    if (error || !adapted) return error;
    struct md_received_fds *payload=NULL;
    error=md_received_fds_reserve(&payload,1);
    if (!error) {
        int copy=fcntl(source->fds[index],F_DUPFD_CLOEXEC,0);
        if (copy<0) error=-errno; else payload->fds[payload->count++]=copy;
    }
    if (!error && source->origins) error=md_received_fds_annotate(payload,source->origins+index,1);
    entry->index=*data ? (int)(*data)->count : 0;
    if (!error) error=md_received_fds_join(data,&payload);
    md_received_fds_release(payload); return error;
}
int md_ipc_received_message(struct md_ipc_capsules **cache, struct md_fs_context *context,
        const struct md_received_fds *source, const int *indices, unsigned count,
        struct md_received_message *out, struct md_received_fds **expanded) {
    if (!cache || !context || !source || !source->count || !indices || !count || count>253
            || !out || !expanded || *expanded) return -EINVAL;
    for (unsigned i=0;i<count;++i)
        if (indices[i]<1 || (unsigned)indices[i]>=source->count) return -EBADF;
    struct md_ipc_credentials *authority=NULL;
    struct md_ipc_binding binding={0};
    int error=md_fs_ipc_authority(context->filesystem,&authority);
    if (!error) error=md_ipc_credentials_bind(authority,source->fds[0],&binding);
    int framed=!error && binding.transport==MD_IPC_TRANSPORT_ORIGINS_V1;
    int adapted=!error;
    if (unrecognized(error)) error=0;
    if (!error && !adapted) {
        int fds[253];
        for (unsigned i=0;i<count;++i) fds[i]=source->fds[indices[i]];
        error=md_ipc_credentials_native(authority,fds,count);
    }
    struct md_received_message plan={0};
    struct md_received_fds *data=NULL;
    int have_capsule=0;
    for (unsigned i=0;i<count && !error;++i) {
        int fd=source->fds[indices[i]];
        plan.first[i]=plan.count;
        struct md_fs_request q={.actor=context->actor,.peer=context->peer,
            .operation=MD_FS_IPC,.flags=MD_IPC_MESSAGE_READ,.directory={source->fds[0],fd}};
        struct md_fs_result result;
        md_fs_context_execute(context,&q,&result,NULL);
        if (!result.error) {
            struct md_received_fds *sender=NULL;
            error=plan.count==254 ? -EOVERFLOW : md_received_fds_reserve(&sender,1);
            if (error) { if (result.fd>=0) close(result.fd); break; }
            if (result.fd<0) { md_received_fds_release(sender); error=-EPROTO; break; }
            sender->fds[sender->count++]=result.fd;
            unsigned index=data ? data->count : 0;
            error=md_received_fds_join(&data,&sender); md_received_fds_release(sender);
            if (error) break;
            plan.entries[plan.count++]=(struct md_received_info){.index=(int)index,.flags=MD_RECEIVED_CREDENTIALS,
                .credentials={(pid_t)result.position,result.info.uid,result.info.gid}};
        } else if (!unrecognized(result.error)) error=result.error;
        else if (framed) {
            if (!*cache) error=md_ipc_capsules_new(&binding,cache);
            struct md_received_fds *payload=NULL;
            if (!error) error=md_ipc_capsules_receive(*cache,&binding,fd,&payload);
            if (error==-ENODATA && binding.receive_only) {
                error=native_entry(context,source,(unsigned)indices[i],adapted,&plan.entries[plan.count++],&data);
                continue;
            }
            if (!error && (have_capsule || count>2)) error=-EPROTO;
            if (!error && payload->count>254-plan.count) error=-EOVERFLOW;
            unsigned offset=data ? data->count : 0;
            for (unsigned j=0;payload && j<payload->count && !error;++j) {
                struct md_received_info *entry=&plan.entries[plan.count++];
                entry->index=(int)(offset+j);
                error=selectors(context,payload,j,&entry->selectors);
            }
            if (!error) error=md_received_fds_join(&data,&payload);
            md_received_fds_release(payload); have_capsule=1;
        } else {
            struct md_received_info *entry=&plan.entries[plan.count++];
            error=native_entry(context,source,(unsigned)indices[i],adapted,entry,&data);
        }
    }
    md_ipc_binding_release(&binding);
    if (error) { md_received_fds_release(data); return error; }
    plan.first[count]=plan.count;
    *out=plan; *expanded=data; return 0;
}

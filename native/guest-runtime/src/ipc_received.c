#include "ipc_received.h"
#include "ipc_capsule.h"
#include "fs_engine.h"
#include "fd_selector.h"
#include <errno.h>
#include <string.h>

static int unrecognized(int error) {
    return error==-ENODATA || error==-ENOTSUP || error==-EAFNOSUPPORT || error==-EPROTOTYPE;
}
static int selectors(struct md_fs_context *context, const struct md_received_fds *source,
        unsigned index, unsigned *out) {
    struct md_fd_object *origin=source->origins ? source->origins[index] : NULL;
    if (origin && origin->type->selectors) { *out=origin->type->selectors; return 0; }
    struct md_fs_request q={.actor=context->actor,.peer=context->peer,
        .operation=MD_FS_WATCH_CONTAINS,.directory={source->fds[index],-1}};
    struct md_fs_result result;
    md_fs_context_execute(context,&q,&result,NULL);
    if (!result.error && result.position) *out|=1U<<MD_FD_SELECTOR_WATCH;
    return result.error;
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
    for (unsigned i=0;i<count && !error;++i) {
        int fd=source->fds[indices[i]];
        plan.first[i]=plan.count;
        struct md_fs_request q={.actor=context->actor,.peer=context->peer,
            .operation=MD_FS_IPC,.flags=MD_IPC_MESSAGE_READ,.directory={source->fds[0],fd}};
        struct md_fs_result result;
        md_fs_context_execute(context,&q,&result,NULL);
        if (!result.error) {
            if (plan.count==254) { error=-EOVERFLOW; break; }
            plan.entries[plan.count++]=(struct md_received_info){.index=-1,.flags=MD_RECEIVED_CREDENTIALS,
                .credentials={(pid_t)result.position,result.info.uid,result.info.gid}};
        } else if (!unrecognized(result.error)) error=result.error;
        else if (framed) {
            if (data || count>2) { error=-EPROTO; break; }
            if (!*cache) error=md_ipc_capsules_new(&binding,cache);
            if (!error) error=md_ipc_capsules_receive(*cache,&binding,fd,&data);
            if (!error && data->count>254-plan.count) error=-EOVERFLOW;
            for (unsigned j=0;data && j<data->count && !error;++j) {
                struct md_received_info *entry=&plan.entries[plan.count++];
                entry->index=(int)j;
                error=selectors(context,data,j,&entry->selectors);
            }
        } else {
            struct md_received_info *entry=&plan.entries[plan.count++];
            entry->index=indices[i]; error=selectors(context,source,(unsigned)indices[i],&entry->selectors);
        }
    }
    md_ipc_binding_release(&binding);
    if (error) { md_received_fds_release(data); return error; }
    plan.first[count]=plan.count;
    *out=plan; *expanded=data; return 0;
}

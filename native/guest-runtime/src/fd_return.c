#define _GNU_SOURCE
#include "fd_return.h"
#include "fd_channel.h"
#include <errno.h>
#include <fcntl.h>

static int release(struct md_fd_return *r) {
    int error=0;
    if (r->channel_order.queue) {
        if (md_resource_order_cancel(&r->channel_order)==1) {
            error=md_fd_channel_output_discard(r->channel);
            int ended=md_resource_order_complete(&r->channel_order);
            if (!error) error=ended;
        }
    }
    md_fd_delivery_dispose(&r->delivery);
    md_fd_channel_release(r->channel);
    if (r->files.table && md_fd_order_cancel(&r->files)==1) {
        int ended=md_fd_order_complete(&r->files);
        if (!error) error=ended;
    }
    *r=(struct md_fd_return){0}; return error;
}
int md_fd_return_begin(struct md_fd_return *r, struct md_fd_origins *files, int source,
        struct md_fs_anchor *origin, unsigned flags, struct md_fd_receipt *receipt,
        struct md_resource_wakeup *wake) {
    if (!r || !files || source<0 || !receipt) return -EINVAL;
    if (r->files.table || r->delivery.capacity) return -EBUSY;
    int error=md_fd_delivery_prepare_mapped(&r->delivery,files,&origin,flags,1,
        &r->update,&r->number,receipt);
    if (!error) {
        r->source=source; r->endpoint=-1;
        error=md_fd_order_begin(files,&r->files,wake);
        if (error>=0) return 0;
    }
    release(r); return error;
}
int md_fd_return_vector_begin(struct md_fd_return *r, struct md_fd_origins *files,
        const int *sources, unsigned count, const struct md_fd_return_publication *publication,
        struct md_resource_wakeup *wake) {
    if (!r || !files || !sources || !count || count>253) return -EINVAL;
    if (r->files.table || r->delivery.capacity) return -EBUSY;
    for (unsigned i=0;i<count;++i) if (sources[i]<0) return -EBADF;
    int error=0;
    if (publication) {
        if (!!publication->memory==!!publication->observation) return -EINVAL;
        if (publication->observation) {
            if (publication->directory<0 || publication->observation->capacity) return -EINVAL;
            error=md_fd_delivery_prepare_observed(&r->delivery,files,publication->origins,
                publication->flags,count,publication->updates,publication->numbers,publication->observation);
        } else error=md_fd_delivery_prepare_mapped(&r->delivery,files,publication->origins,
            publication->flags,count,publication->updates,publication->numbers,publication->memory);
    }
    if (error) return error;
    r->vector=sources; r->count=count; r->endpoint=-1;
    if (publication) { r->observation=publication->observation; r->observation_directory=publication->directory; }
    error=md_fd_order_begin(files,&r->files,wake);
    if (error>=0) return 0;
    release(r); return error;
}
int md_fd_return_progress(struct md_fd_return *r, struct md_resource_wakeup *wake) {
    if (!r || !r->files.table) return -EINVAL;
    if (r->offered) return -EALREADY;
    int error=0;
    if (md_fd_order_state(&r->files)==MD_RESOURCE_ORDER_READY) {
        error=md_fd_order_start(&r->files);
        if (error) return error;
    }
    if (md_fd_order_state(&r->files)!=MD_RESOURCE_ORDER_RUNNING) return MD_FD_RETURN_WAIT;
    if (!r->channel) {
        error=md_fd_origins_channel(r->files.table,&r->endpoint,&r->channel);
        if (error==-ESTALE) {
            error=md_fd_origins_channel_candidate(r->files.table,&r->endpoint,&r->channel);
            if (error) return error;
            r->checking=1;
        }
        if (!error && !r->channel) error=md_fd_channel_new(&r->channel);
        if (error) return error;
    }
    if (r->checking) return MD_FD_RETURN_CHECK;
    if (r->endpoint<0) { r->admission=1; return MD_FD_RETURN_ADMIT; }
    if (!r->channel_order.queue) {
        error=md_fd_channel_output_begin(r->channel,&r->channel_order,wake);
        if (error<0) return error;
    }
    if (md_resource_order_state(&r->channel_order)!=MD_RESOURCE_ORDER_READY) return MD_FD_RETURN_WAIT;
    error=md_resource_order_start(&r->channel_order);
    if (!error && r->observation) error=md_fd_table_observation_begin(r->observation,r->observation_directory,r->count);
    if (!error) error=r->vector ? md_fd_channel_output_vector(r->channel,r->vector,r->count,&r->request)
        : md_fd_channel_output_send(r->channel,r->source,&r->request);
    if (error) return error;
    r->offered=1; return MD_FD_RETURN_READY;
}
int md_fd_return_observed(struct md_fd_return *r, const struct md_fd_channel_observation *observation) {
    if (!r || !r->checking || md_fd_order_state(&r->files)!=MD_RESOURCE_ORDER_RUNNING) return -EINVAL;
    int error=md_fd_channel_resolve(r->channel,r->files.table,r->endpoint,observation);
    if (error) return error;
    md_fd_channel_release(r->channel); r->channel=NULL; r->endpoint=-1; r->checking=0;
    return 0;
}
int md_fd_return_install(struct md_fd_return *r, int listener, uint64_t notification) {
    if (!r || !r->admission || r->endpoint>=0 || !r->channel
            || md_fd_order_state(&r->files)!=MD_RESOURCE_ORDER_RUNNING) return -EPERM;
    int installed=md_fd_channel_admit(r->channel,r->files.table,listener,notification);
    if (installed>=0) r->endpoint=installed;
    return installed;
}
int md_fd_return_finish(struct md_fd_return *r, long received, uint64_t token) {
    if (!r || !r->files.table || received < -4095) return -EINVAL;
    int result=received<0 ? (int)received : -EPROTO;
    if (r->offered && r->delivery.capacity) {
        int count=md_fd_delivery_publish(&r->delivery);
        if (count<0) result=count;
        else if (count) {
            /* Never lose an installed caller-owned FD because a later guest
             * acknowledgement failed. Publication does not turn a vector's
             * native output error into success; scalar opens return that FD. */
            if (!r->vector) result=r->number;
            else if (received==(long)sizeof(uint64_t) && token==r->request) result=0;
        } else if (received==(long)sizeof(uint64_t) && token==r->request
                && (r->vector || (r->delivery.receipt->message.msg_flags&MSG_CTRUNC))) result=r->vector ? 0 : -EMFILE;
    } else if (r->offered && r->vector) {
        if (received==(long)sizeof(uint64_t) && token==r->request) result=0;
    }
    int error=release(r);
    return result<0 && error ? error : result;
}
int md_fd_return_cancel(struct md_fd_return *r) {
    if (!r) return -EINVAL;
    int error=0;
    if (r->offered && r->delivery.capacity) {
        int count=md_fd_delivery_publish(&r->delivery);
        if (count<0) error=count;
    }
    int ended=release(r); return error ? error : ended;
}

#define _GNU_SOURCE
#include "fs_buffer_service.h"
#include "fs_buffer.h"
#include "fs_worker.h"
#include "fs_engine.h"
#include "task_resources.h"
#include "task_descriptor.h"
#include "fd_channel.h"
#include "inode_watch.h"
#include "ofd_order.h"
#include "file_open_job.h"
#include "fifo_description.h"
#include "exec_prepare.h"
#include "file_snapshot.h"
#include "ipc_credentials.h"
#include "received_fds.h"
#include "ipc_received.h"
#include "ipc_capsule.h"
#include "descriptor_inode.h"
#include "proc_paths.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

struct md_fs_buffer_service {
    struct md_fs_worker *worker;
    struct md_task_registry *tasks;
    struct md_resource_wakeup *wake;
    struct md_fs_buffer_request *requests;
    struct md_ipc_capsules *capsules; /* filesystem worker until stop/join */
    md_control_factory control;
    md_control_query control_query;
    md_control_capture control_capture;
    md_exec_capture exec_capture;
    md_root_capture root_capture;
    void (*complete)(struct md_fs_buffer_request *, pid_t, int);
    int (*admit)(pid_t);
};
void md_fs_buffer_admission(struct md_fs_buffer_service *s,int (*admit)(pid_t)) { s->admit=admit; }
struct md_fs_buffer_request {
    struct md_fs_work work;
    struct md_fs_buffer_service *service;
    struct md_fs_buffer_request *next;
    struct md_interception_buffer buffer;
    struct md_fd_order files;
    struct md_fs_order order;
    struct md_ofd_order cursor;
    int cursor_waiting;
    int captured_only;
    int status_only;
    struct md_fs_result status_result;
    int adopted;
    int64_t position;
    struct md_fs_context context;
    struct md_fs_buffer_frame *output;
    struct md_fs_request request;
    struct md_fs_buffer_open opened;
    struct md_open_job opening;
    int fifo_control;
    struct md_command_images images;
    struct md_fs_anchor *image_origin;
    struct md_program *proc_image;
    struct md_file_snapshot snapshot;
    enum { SNAPSHOT_NONE, SNAPSHOT_BEGIN, SNAPSHOT_APPEND, SNAPSHOT_FINISH } snapshot_phase;
    int snapshot_waiting;
    size_t snapshot_size;
    struct md_fs_anchor *input[2];
    struct md_task_snapshot *root[2];
    struct md_program *proc_object[2];
    struct md_fd_object *reopened;
    struct md_fd_object *control_input;
    int control_descriptor;
    struct md_landlock_policy *landlock;
    int captured[2];
    struct md_received_fds *received;
    struct md_received_fds *expanded;
    unsigned received_count;
    struct md_fd_channel *export;
    int channel_checking;
    struct md_fd_channel_capture export_capture;
    unsigned export_mask;
    unsigned capture_mask;
    unsigned capture_active;
    int capturing;
    int export_number, exporting;
    pid_t actor;
    int submitted, cancelled, error, executable;
    int reserved, delivering, finishing, delivered;
    int task_pending, task_started, task_descriptor;
    char path[];
};
static int retains_context(const struct md_fs_buffer_request *r) {
    return r->request.operation==MD_FS_CHROOT || r->request.operation==MD_FS_MOUNT || (r->request.operation==MD_FS_TASK_PATH
        && r->request.mode==MD_FS_TASK_FCHDIR);
}
void md_fs_buffer_open_release(struct md_fs_buffer_open *o) {
    if (o->fd>=0) close(o->fd);
    if (o->completion.kind==MD_OPEN_PIPE) close(o->completion.control);
    md_fs_anchor_release(o->origin);
    md_fd_object_release(o->object);
    *o=(struct md_fs_buffer_open){.fd=-1};
}
struct md_fd_object *md_fs_buffer_open_object(const struct md_fs_buffer_open *o) {
    return o->object ? o->object : md_fs_anchor_object(o->origin);
}
int md_fs_buffer_open_take(struct md_fs_buffer_request *r, struct md_fs_buffer_open *out) {
    if (!r || !out || out->fd>=0 || out->origin || out->object) return -EINVAL;
    if (r->task_pending) return 0;
    if (r->opened.fd<0) return 0;
    *out=r->opened; r->opened=(struct md_fs_buffer_open){.fd=-1}; return 1;
}
static void dispose(struct md_fs_buffer_request *r) {
    if (r->fifo_control>=0) close(r->fifo_control);
    if (r->control_descriptor>=0) close(r->control_descriptor);
    md_landlock_release(r->landlock);
    struct md_fs_buffer_request **p=&r->service->requests;
    while (*p && *p!=r) p=&(*p)->next;
    if (*p) *p=r->next;
    if (r->task_started) md_domain_set_cwd(r->context.task.fs,NULL);
    md_fd_channel_capture_cancel(&r->export_capture);
    if (r->order.fs && md_fs_order_cancel(&r->order)==1) md_fs_order_complete(&r->order);
    if (r->files.table && md_fd_order_cancel(&r->files)==1) md_fd_order_complete(&r->files);
    if (r->cursor.owner && md_ofd_order_cancel(&r->cursor)==1) md_ofd_order_complete(&r->cursor);
    for (unsigned i=0;i<2;++i) {
        md_fs_anchor_release(r->input[i]);
        if (r->root[i]) { md_task_snapshot_release(r->root[i]); free(r->root[i]); }
        if (r->proc_object[i]) {
            if (r->proc_object[i]->fd>=0) close(r->proc_object[i]->fd);
            md_fs_anchor_release(r->proc_object[i]->origin);
            free(r->proc_object[i]);
        }
        if (r->captured[i]>=0) close(r->captured[i]);
    }
    md_fs_context_end(&r->context);
    md_fd_object_release(r->reopened);
    md_fd_object_release(r->control_input);
    md_received_fds_release(r->received);
    md_received_fds_release(r->expanded);
    md_fd_channel_release(r->export);
    md_fs_buffer_open_release(&r->opened);
    md_command_images_close(&r->images);
    md_fs_anchor_release(r->image_origin);
    if (r->proc_image) {
        if (r->proc_image->fd>=0) close(r->proc_image->fd);
        md_fs_anchor_release(r->proc_image->origin);
        free(r->proc_image);
    }
    md_file_snapshot_close(&r->snapshot);
    md_buffer_release(&r->buffer);
    free(r);
}
int md_fs_buffer_task_pending(const struct md_fs_buffer_request *r) {
    return r && r->task_pending;
}
int md_fs_buffer_task_start(struct md_fs_buffer_request *r, int descriptor) {
    if (!md_fs_buffer_task_pending(r) || r->task_started || descriptor!=r->task_descriptor
            || md_fd_order_state(&r->files)!=MD_RESOURCE_ORDER_RUNNING
            || md_fs_order_state(&r->order)!=MD_RESOURCE_ORDER_RUNNING) return -EINVAL;
    r->task_started=1; return 0;
}
int md_fs_buffer_task_finish(struct md_fs_buffer_request **owner, long result) {
    struct md_fs_buffer_request *r=owner ? *owner : NULL;
    if (!md_fs_buffer_task_pending(r) || result>0 || result < -4095
            || (!r->task_started && !result)) return -EINVAL;
    int error=result ? 0 : md_domain_set_cwd(r->context.task.fs,
        md_domain_restricted(r->context.task.fs) ? NULL : r->opened.origin);
    r->task_started=0; *owner=NULL; dispose(r); return error;
}
static int finish(struct md_fs_buffer_request *r, int delivered) {
    r->delivering=0; r->finishing=1; r->delivered=delivered;
    int error=md_fs_worker_submit(r->service->worker,&r->work);
    if (!error) r->submitted=1;
    return error;
}
int md_fs_buffer_ack_pending(const struct md_fs_buffer_request *r) {
    return r && r->delivering;
}
int md_fs_buffer_ack(struct md_fs_buffer_request *r, int copied) {
    if (!md_fs_buffer_ack_pending(r) || copied>0 || copied < -4095) return -EINVAL;
    return finish(r,!copied);
}
int md_fs_buffer_snapshot_pending(const struct md_fs_buffer_request *r) {
    return r && r->snapshot_waiting;
}
int md_fs_buffer_snapshot_advance(struct md_fs_buffer_request *r, int finish) {
    if (!md_fs_buffer_snapshot_pending(r)) return -EINVAL;
    if (!finish) {
        size_t size=r->output->snapshot.size;
        if (!size || size>sizeof(r->output->snapshot.data)) return -EINVAL;
        memcpy(r->path,r->output->snapshot.data,size);
        r->snapshot_size=size;
    }
    r->snapshot_phase=finish ? SNAPSHOT_FINISH : SNAPSHOT_APPEND;
    r->snapshot_waiting=0;
    int error=md_fs_worker_submit(r->service->worker,&r->work);
    if (!error) r->submitted=1;
    return error;
}
static int ready(struct md_fs_work *work) {
    struct md_fs_buffer_request *r=(void *)work;
    return r->cancelled || !r->service->admit || r->service->admit(r->actor);
}
static int complete(struct md_fs_work *work) {
    struct md_fs_buffer_request *r=(void *)work;
    if (!ready(work)) {
        r->submitted=1; md_fs_worker_publish(r->service->worker,work); return 0;
    }
    r->submitted=0;
    if (!r->cancelled && r->executable && r->error==-EREMOTE && r->proc_image) {
        r->error=r->service->exec_capture
            ? r->service->exec_capture(r->actor,r->proc_image) : -EOPNOTSUPP;
        if (!r->error) {
            /* EVENT_WAIT: preparation resumes with the authorized image;
             * cancellation releases its ownership without a guest FD. */
            r->error=md_fs_worker_submit(r->service->worker,&r->work);
            if (!r->error) { r->submitted=1; return 0; }
        }
    }
    if (!r->cancelled && !r->error && r->snapshot_phase
            && r->snapshot_phase!=SNAPSHOT_FINISH) {
        /* EVENT_WAIT: the caller copies the next chunk or completes the file.
         * Task cancellation closes the construction FD outside its table. */
        r->snapshot_waiting=1;
        r->service->complete(r,r->actor,0);
        return 0;
    }
    if (r->request.operation==MD_FS_CHROOT || r->request.operation==MD_FS_MOUNT) {
        if (r->order.fs) {
            int error=md_fs_order_complete(&r->order);
            if (!r->error) r->error=error;
        }
        if (r->files.table) {
            int error=md_fd_order_complete(&r->files);
            if (!r->error) r->error=error;
        }
    }
    if (!r->cancelled && !r->error && r->opened.fd>=0 &&
            r->request.operation==MD_FS_TASK_PATH && r->request.mode==MD_FS_TASK_FCHDIR) {
        /* EVENT_WAIT: fchdir completion; cancellation releases exact owners. */
        r->task_pending=1;
        r->service->complete(r,r->actor,0);
        return 0;
    }
    if (!r->cancelled && !r->error && r->opened.completion.kind && r->opened.completion.kind!=MD_OPEN_CALLER) {
        int error=md_open_job_start(&r->opening,r->opened.fd,r->request.flags,r->opened.completion);
        if (!error) {
            close(r->opened.fd); r->opened.fd=-1;
            if (r->opened.completion.kind==MD_OPEN_PIPE) r->fifo_control=r->opened.completion.control;
            r->opened.completion=(struct md_open_completion){0};
            return 0;
        }
        r->error=error;
    }
    if (r->reserved && !r->finishing) {
        if (r->cancelled) {
            /* The reply was never offered to the task. Restore its records. */
            if (!finish(r,0)) return 0;
        } else {
            r->delivering=1;
            r->service->complete(r,r->actor,r->error);
            return 0;
        }
    }
    if (!r->cancelled) r->service->complete(r,r->actor,r->error);
    dispose(r); return 0;
}
int md_fs_buffer_children(const struct md_fs_buffer_service *s) {
    if (!s) return 0;
    for (const struct md_fs_buffer_request *r=s->requests;r;r=r->next)
        if (r->opening.pid) return 1;
    return 0;
}
int md_fs_buffer_child(struct md_fs_buffer_service *s, pid_t pid, int status) {
    if (!s) return 0;
    struct md_fs_buffer_request *r=s->requests;
    while (r && r->opening.pid!=pid) r=r->next;
    if (!r) return 0;
    if (!WIFEXITED(status) && !WIFSIGNALED(status)) return -EPROTO;
    struct md_open_observation observation={0};
    int result=md_open_job_finish(&r->opening,status,&observation);
    if (result>=0) {
        r->opened.fd=result;
        if (!r->cancelled && observation.initial_reader) {
            r->opened.object=md_fifo_description_new(r->opened.origin,result,r->fifo_control,observation.writers);
            if (!r->opened.object) result=-errno;
            else r->output->reply.result.selectors=md_fd_object_selectors(r->opened.object);
        }
    }
    if (r->fifo_control>=0) { close(r->fifo_control); r->fifo_control=-1; }
    if (result<0) {
        if (r->opened.fd>=0) { close(r->opened.fd); r->opened.fd=-1; }
        r->output->reply.result.error=result;
        r->output->transfer=MD_FS_BUFFER_NO_FD;
    }
    complete(&r->work); return 1;
}
static void submit(struct md_fs_buffer_request *r, int error) {
    if (r->files.table && !retains_context(r)) {
        int released=md_fd_order_complete(&r->files);
        if (!error) error=released;
    }
    if (!error && (r->request.operation==MD_FS_GETDENTS || r->request.operation==MD_FS_SEEKDIR)) {
        int ready=md_ofd_order_begin(md_fs_worker_cursors(r->service->worker),r->captured[0],
            r->request.operation==MD_FS_GETDENTS,&r->cursor,r->service->wake);
        if (ready<0) error=ready;
        else if (!ready) { r->cursor_waiting=1; return; }
        else if (r->cursor.owner) error=md_ofd_order_start(&r->cursor);
    }
    if (!error) error=md_fs_worker_submit(r->service->worker,&r->work);
    if (error) { r->error=error; complete(&r->work); }
    else r->submitted=1;
}
int md_fs_buffer_export_pending(const struct md_fs_buffer_request *r) {
    return r && (r->exporting || r->channel_checking);
}
int md_fs_buffer_export_install(struct md_fs_buffer_request *r, int listener, uint64_t notification) {
    if (!r || !r->exporting || r->export_number>=0
            || md_fd_order_state(&r->files)!=MD_RESOURCE_ORDER_RUNNING) return -EPERM;
    int installed=md_fd_channel_admit(r->export,r->files.table,listener,notification);
    if (installed>=0) r->export_number=installed;
    return installed;
}
int md_fs_buffer_export_sent(struct md_fs_buffer_request *r, int error) {
    if (!r || !r->exporting || error>0 || error < -4095) return -EINVAL;
    struct md_fd_channel_input message;
    int received=md_fd_channel_capture_finish(&r->export_capture,&message);
    if (!error) error=received;
    if (!error) {
        unsigned index=0;
        for (unsigned i=0;i<2;++i)
            if (r->export_mask&(1U<<i)) r->request.directory[i]=r->captured[i]=message.fd[index++];
        message.count=0;
    }
    md_fd_channel_input_close(&message);
    r->exporting=0;
    submit(r,error); return 0;
}
static int export_begin(struct md_fs_buffer_request *r) {
    int error=md_fd_origins_channel(r->files.table,&r->export_number,&r->export);
    if (error==-ESTALE) {
        error=md_fd_origins_channel_candidate(r->files.table,&r->export_number,&r->export);
        if (error) return error;
        r->channel_checking=1;
        r->output->channel.number=r->export_number;
        r->output->channel.observation=(struct md_fd_channel_observation){0};
        r->service->complete(r,r->actor,MD_FS_BUFFER_CHANNEL_CHECK);
        return 0;
    }
    if (!error && !r->export) error=md_fd_channel_new(&r->export);
    if (error) return error;
    error=md_fd_channel_capture_begin(r->export,r->context.peer,
        !!(r->export_mask&1)+!!(r->export_mask&2),&r->export_capture);
    if (error) return error;
    r->output->export.request=r->export_capture.request;
    r->output->export.mask=r->export_mask;
    r->output->export.number=r->export_number;
    r->exporting=1;
    /* EVENT_WAIT: caller exports the selected inputs then acknowledges send;
     * task death drains/discards its queue entry and releases the table turn. */
    r->service->complete(r,r->actor,MD_FS_BUFFER_EXPORT);
    return 0;
}
int md_fs_buffer_capture_pending(const struct md_fs_buffer_request *r) {
    return r && r->capturing;
}
int md_fs_buffer_capture_start(struct md_fs_buffer_request *r) {
    if (!r || r->capturing!=1 || r->cancelled
            || md_fd_order_state(&r->files)!=MD_RESOURCE_ORDER_RUNNING
            || md_fs_order_state(&r->order)!=MD_RESOURCE_ORDER_RUNNING) return -EINVAL;
    r->capturing=2; return 0;
}
int md_fs_buffer_capture_target(const struct md_fs_buffer_request *r, struct md_fs_task_capture *out) {
    if (!r || !r->capturing || !out || !r->capture_mask) return -EINVAL;
    *out=r->request.capture[r->capture_mask&1 ? 0 : 1];
    return out->path ? 0 : -EINVAL;
}
static void capture_begin(struct md_fs_buffer_request *r) {
    r->capture_active=r->capture_mask&1 ? 1 : 2;
    if (r->capture_mask==3 && r->request.capture[0].flags==r->request.capture[1].flags
            && !strcmp(r->request.capture[0].path,r->request.capture[1].path)) r->capture_active=3;
    r->capturing=1;
    r->service->complete(r,r->actor,0);
}
int md_fs_buffer_capture_finish(struct md_fs_buffer_request *r, int descriptor, int error) {
    if (!r || !r->capturing || error>0 || error < -4095 || (!error && descriptor<0)) {
        if (descriptor>=0) close(descriptor);
        return -EINVAL;
    }
    r->capturing=0;
    if (r->cancelled) {
        if (descriptor>=0) close(descriptor);
        dispose(r); return 0;
    }
    if (!error) {
        int owned=0;
        for (unsigned i=0;i<2;++i) if (r->capture_active&(1U<<i)) {
            r->request.directory[i]=descriptor;
            r->request.capture[i]=(struct md_fs_task_capture){0};
            if (!owned) { r->captured[i]=descriptor; owned=1; }
        }
        if (!owned) { close(descriptor); error=-EPROTO; }
    } else if (descriptor>=0) close(descriptor);
    r->capture_mask&=~r->capture_active;
    r->capture_active=0;
    if (!error && r->capture_mask) { capture_begin(r); return 0; }
    int released=retains_context(r) ? 0 : md_fs_order_complete(&r->order);
    if (!error) error=released;
    if (!error && r->export_mask) {
        error=export_begin(r);
        if (!error) return 0;
    }
    submit(r,error); return 0;
}
int md_fs_buffer_channel_observed(struct md_fs_buffer_request *r) {
    if (!r || !r->channel_checking || md_fd_order_state(&r->files)!=MD_RESOURCE_ORDER_RUNNING) return -EINVAL;
    int error=md_fd_channel_resolve(r->export,r->files.table,r->export_number,&r->output->channel.observation);
    md_fd_channel_release(r->export); r->export=NULL; r->export_number=-1;
    r->channel_checking=0;
    if (!error) error=export_begin(r);
    if (error) submit(r,error);
    return 0;
}
static int inspect_received(struct md_fs_buffer_request *r) {
    int indices[253]; memcpy(indices,r->path,r->received_count*sizeof(*indices));
    return md_ipc_received_message(&r->service->capsules,&r->context,r->received,
        indices,r->received_count,&r->output->received_message,&r->expanded);
}
int md_fs_buffer_inspect_take(struct md_fs_buffer_request *r, struct md_received_fds **out) {
    if (!r || !out || *out) return -EINVAL;
    if (!r->received) return 0;
    if (r->submitted || r->error) return -EINVAL;
    *out=r->expanded; r->expanded=NULL; return 1;
}
static int control_open(void *context,const struct md_control_file_ops *ops,void *data,
        const struct md_identity *identity,int flags) {
    struct md_fs_buffer_request *r=context;
    if (!r->service->control) return -EOPNOTSUPP;
    if (r->opened.object) return -EBUSY;
    r->opened.object=r->service->control(ops,data,identity,flags,&r->control_descriptor);
    return r->opened.object ? 0 : -errno;
}
void md_fs_buffer_control_factory(struct md_fs_buffer_service *s,md_control_factory factory) {
    s->control=factory;
}
void md_fs_buffer_control_query(struct md_fs_buffer_service *s,md_control_query query) {
    s->control_query=query;
}
void md_fs_buffer_control_capture(struct md_fs_buffer_service *s,md_control_capture capture) {
    s->control_capture=capture;
}
void md_fs_buffer_exec_capture(struct md_fs_buffer_service *s,md_exec_capture capture) {
    s->exec_capture=capture;
}
void md_fs_buffer_root_capture(struct md_fs_buffer_service *s,md_root_capture capture) {
    s->root_capture=capture;
}
static int resolve_proc_objects(struct md_fs_buffer_request *r) {
    for (unsigned i=0;i<2;++i) if (r->proc_object[i]) {
        struct md_program *image=r->proc_object[i];
        if (image->fd>=0) {
            r->captured[i]=image->fd; image->fd=-1;
            r->input[i]=image->origin; image->origin=NULL;
        } else {
            struct md_fs_request q={.actor=r->context.actor,.peer=r->context.peer,.operation=MD_FS_OPEN_OBJECT,
                .directory={-1,-1},.path={image->identity.object,NULL},.flags=O_PATH|O_CLOEXEC};
            struct md_fs_output out={.origin=&r->input[i]};
            struct md_fs_result result;
            md_fs_context_execute(&r->context,&q,&result,&out);
            if (result.error) { if (result.fd>=0) close(result.fd); return result.error; }
            r->captured[i]=result.fd;
        }
        r->request.directory[i]=r->captured[i];
        r->request.origin[i]=r->input[i];
        free(image); r->proc_object[i]=NULL;
    }
    for (unsigned i=0;i<2;++i) if (r->root[i]) {
        struct md_fs_context context=r->context;
        context.task=*r->root[i];
        context.task.identity=r->context.task.identity;
        context.task.landlock=r->context.task.landlock;
        struct md_fs_request q={.actor=context.actor,.peer=context.peer,.operation=MD_FS_OPEN,
            .directory={-1,-1},.path={"/",NULL},.flags=O_PATH|O_DIRECTORY|O_CLOEXEC};
        struct md_fs_output out={.origin=&r->input[i]};
        struct md_fs_result result;
        md_fs_context_execute(&context,&q,&result,&out);
        if (result.fd>=0) close(result.fd);
        if (result.error) return result.error;
        if (!r->input[i] || result.host_path || result.open_completion.kind) return -EPROTO;
        r->request.origin[i]=r->input[i];
        r->request.directory[i]=md_fs_anchor_fd(r->input[i]);
        md_task_snapshot_release(r->root[i]); free(r->root[i]); r->root[i]=NULL;
    }
    return 0;
}
static void prepare_open(struct md_fs_buffer_request *,struct md_filesystem *);
static void run(struct md_fs_work *work, struct md_filesystem *fs, int error) {
    struct md_fs_buffer_request *r=(void *)work;
    r->error=error;
    if (error) return;
    if (r->adopted) {
        r->adopted=0;
        prepare_open(r,fs); return;
    }
    if (r->finishing) {
        if (r->request.operation==MD_FS_GETDENTS) {
            if (r->delivered && lseek(r->captured[0],r->position,SEEK_SET)!=r->position)
                r->error=-errno;
        } else r->error=md_inode_watch_complete(fs->store,r->captured[0],r->delivered);
        r->reserved=0;
        return;
    }
    r->context.filesystem=fs;
    r->error=resolve_proc_objects(r);
    if (r->error) return;
    if (r->received) { r->error=inspect_received(r); return; }
    if (r->status_only) {
        /* The walker still needs scratch space to report an unexecuted
         * provider boundary. Only its delegation marker leaves this worker. */
        char boundary[PATH_MAX];
        struct md_fs_output output={.data=boundary,.capacity=sizeof(boundary)};
        md_fs_context_execute(&r->context,&r->request,&r->status_result,&output);
        return;
    }
    if (r->executable) {
        r->error=md_fs_command_prepare(&r->context,&r->request,&r->proc_image,&r->output->command,&r->images,
            &r->image_origin);
        return;
    }
    struct md_fs_response *reply=&r->output->reply;
    if (r->reopened && !(r->request.flags&O_PATH)) {
        int mode=r->request.flags&O_ACCMODE;
        r->error=md_descriptor_inode_access(r->reopened,&r->context.task.identity,
            mode==O_RDONLY ? R_OK : mode==O_WRONLY ? W_OK : R_OK|W_OK);
        if (r->error) return;
    }
    memset(&reply->result,0,sizeof(reply->result));
    r->output->transfer=MD_FS_BUFFER_NO_FD;
    memset(r->output->source,0,sizeof(r->output->source));
    struct md_fs_output output={.data=reply->data,.capacity=sizeof(reply->data),
        .reserve_watch=r->request.operation==MD_FS_WATCH_READ,
        .directory_position=r->request.operation==MD_FS_GETDENTS ? &r->position : NULL,
        .origin=md_fs_operation_has_origin(r->request.operation) ? &r->opened.origin : NULL,
        .control=control_open,.control_context=r,.landlock=&r->landlock};
    if (md_fs_operation_value(r->request.operation)) {
        output.data=r->output->value; output.capacity=sizeof(r->output->value);
    }
    if (r->snapshot_phase) {
        if (r->snapshot_phase==SNAPSHOT_BEGIN) {
            r->error=md_file_snapshot_begin(&r->snapshot,fs->store,r->snapshot.flags);
            return;
        }
        if (r->snapshot_phase==SNAPSHOT_APPEND) {
            r->error=md_file_snapshot_append(&r->snapshot,r->path,r->snapshot_size);
            return;
        }
        int fd=md_file_snapshot_finish(&r->snapshot);
        if (fd<0) { r->error=fd; return; }
        reply->result.fd=fd;
        md_fs_context_capture_result(&r->context,&reply->result,&r->opened.origin);
        r->request.flags=r->snapshot.flags;
    } else md_fs_context_execute(&r->context,&r->request,&reply->result,&output);
    r->reserved=(output.reserve_watch || output.directory_position) && !reply->result.error;
    r->opened.fd=reply->result.fd; reply->result.fd=-1;
    if (!reply->result.error && r->opened.fd>=0 && r->control_descriptor>=0) {
        close(r->opened.fd); r->opened.fd=r->control_descriptor; r->control_descriptor=-1;
    }
    reply->result.selectors=md_fd_object_selectors(r->opened.object);
    r->opened.completion=reply->result.open_completion;
    reply->result.open_completion=(struct md_open_completion){0};
    prepare_open(r,fs);
}
static void prepare_open(struct md_fs_buffer_request *r,struct md_filesystem *fs) {
    struct md_fs_response *reply=&r->output->reply;
    if (r->opened.fd>=0) {
        if (r->reopened) {
            md_fs_anchor_release(r->opened.origin); r->opened.origin=NULL;
            md_fd_object_release(r->opened.object);
            r->opened.object=md_fd_object_retain(r->reopened);
        }
        reply->result.selectors=md_fd_object_selectors(r->opened.object);
        if (r->request.operation==MD_FS_TASK_PATH) {
            if (r->opened.completion.kind) { r->error=-EPROTO; return; }
            r->opened.task_path=r->request.mode;
            r->output->transfer=MD_FS_BUFFER_TASK_PATH;
            snprintf(r->output->source,sizeof(r->output->source),"/proc/%d/fd/%d",getpid(),r->opened.fd);
            reply->delivery=MD_FS_REPLIED;
            return;
        }
        if (r->opened.completion.kind==MD_OPEN_CALLER) {
            r->opened.flags=r->request.flags;
            r->output->transfer=MD_FS_BUFFER_CALLER_OPEN;
            snprintf(r->output->source,sizeof(r->output->source),"/proc/%d/fd/%d",getpid(),r->opened.fd);
            reply->delivery=MD_FS_REPLIED; return;
        }
        if (r->opened.completion.kind) {
            r->opened.flags=O_CLOEXEC;
            r->output->transfer=MD_FS_BUFFER_ADDFD;
            reply->delivery=MD_FS_REPLIED;
            return;
        }
        int flags=fcntl(r->opened.fd,F_GETFL);
        if (flags<0) { r->error=-errno; return; }
        r->opened.flags=(flags&O_PATH) || r->snapshot_phase || r->request.operation==MD_FS_FSOPEN
            || r->request.operation==MD_FS_FDINFO
            ? r->request.flags : O_CLOEXEC;
        r->output->transfer=(flags&O_PATH) ? MD_FS_BUFFER_ANCHOR : MD_FS_BUFFER_ADDFD;
        if (!(flags&O_PATH)) {
            reply->delivery=MD_FS_REPLIED;
            return;
        }
        if (r->request.flags&O_NOFOLLOW) {
            struct stat st;
            if (fstat(r->opened.fd,&st)) { r->error=-errno; return; }
            if (S_ISDIR(st.st_mode)) {
                snprintf(r->output->source,sizeof(r->output->source),"/proc/%d/fd/%d/.",getpid(),r->opened.fd);
            } else {
                int source=md_inode_descriptor_source(fs->store,r->opened.fd,
                    r->output->source,sizeof(r->output->source));
                if (source) {
                    if (source==-EXDEV) r->output->transfer=MD_FS_BUFFER_RIGHTS;
                    else { r->error=source; return; }
                }
            }
        } else snprintf(r->output->source,sizeof(r->output->source),"/proc/%d/fd/%d",getpid(),r->opened.fd);
    }
    reply->delivery=MD_FS_REPLIED;
}
struct md_fs_buffer_service *md_fs_buffer_service_new(struct md_fs_worker *worker,
        struct md_task_registry *tasks, struct md_resource_wakeup *wake,
        void (*callback)(struct md_fs_buffer_request *,pid_t,int)) {
    if (!worker || !tasks || !wake || !callback) return NULL;
    struct md_fs_buffer_service *s=calloc(1,sizeof(*s));
    if (s) *s=(struct md_fs_buffer_service){.worker=worker,.tasks=tasks,.wake=wake,.complete=callback};
    return s;
}
void md_fs_buffer_service_destroy(struct md_fs_buffer_service *s) {
    if (!s) return;
    while (s->requests) dispose(s->requests);
    md_ipc_capsules_free(s->capsules);
    free(s);
}
static struct md_fs_buffer_request *request_new(struct md_fs_buffer_service *s,pid_t actor,size_t extra) {
    struct md_fs_buffer_request *r=calloc(1,sizeof(*r)+extra);
    if (!r) return NULL;
    r->service=s; r->actor=actor; r->opened.fd=r->control_descriptor=r->fifo_control=-1;
    r->images=(struct md_command_images){.program=-1,.loader=-1};
    r->snapshot.fd=-1; r->captured[0]=r->captured[1]=-1;
    return r;
}
static int request_admit(struct md_fs_buffer_request *r,struct md_guest_domain *fs,
        struct md_fs_buffer_request **out) {
    struct md_fs_buffer_service *s=r->service;
    int error=md_task_registry_read(s->tasks,r->actor,0,&r->context.task);
    if (!error) r->request.peer=r->context.peer=r->context.task.tgid;
    if (!error && r->context.task.fs!=fs) error=-ESTALE;
    if (!error) {
        error=md_fd_order_begin(r->context.task.files,&r->files,s->wake);
        if (error>0) error=0;
    }
    if (error) { dispose(r); return error; }
    r->work=(struct md_fs_work){.run=run,.complete=complete,.ready=ready};
    r->next=s->requests; s->requests=r; *out=r;
    return 0;
}
int md_fs_buffer_invoke_status(struct md_fs_buffer_service *s,pid_t actor,struct md_guest_domain *fs,
        const struct md_fs_request *q,struct md_fs_buffer_request **out) {
    if (!s || !out || *out || !q || (q->operation!=MD_FS_UNLINK && q->operation!=MD_FS_RENAME
            && q->operation!=MD_FS_LINK && q->operation!=MD_FS_MKDIR)) return -EINVAL;
    size_t lengths[2]={0};
    for (unsigned i=0;i<2;++i) if (q->path[i]) {
        lengths[i]=strnlen(q->path[i],PATH_MAX)+1;
        if (lengths[i]>PATH_MAX) return -ENAMETOOLONG;
    }
    struct md_fs_buffer_request *r=request_new(s,actor,lengths[0]+lengths[1]);
    if (!r) return -ENOMEM;
    r->captured_only=r->status_only=1;
    r->request=(struct md_fs_request){.actor=actor,.operation=q->operation,.flags=q->flags,
        .mode=q->mode,.directory={q->directory[0],q->directory[1]},.attributes=q->attributes};
    size_t offset=0;
    for (unsigned i=0;i<2;++i) if (lengths[i]) {
        memcpy(r->path+offset,q->path[i],lengths[i]);
        r->request.path[i]=r->path+offset; offset+=lengths[i];
    }
    int error=md_fs_request_validate(&r->request);
    if (error) { dispose(r); return error; }
    return request_admit(r,fs,out);
}
const struct md_fs_result *md_fs_buffer_status_result(const struct md_fs_buffer_request *r) {
    return r && r->status_only ? &r->status_result : NULL;
}
static int begin(struct md_fs_buffer_service *s, pid_t actor, struct md_guest_domain *fs, unsigned operation,
        const struct md_interception_buffer *buffer, struct md_fs_buffer_request **out, int executable,
        int snapshot, unsigned snapshot_flags) {
    if (!s || !out || *out) return -EINVAL;
    struct md_buffer_span span;
    int error=md_buffer_span(buffer,&span);
    if (error) return error;
    if (span.size<sizeof(struct md_fs_buffer_frame)) return -EINVAL;
    const struct md_fs_buffer_frame *input=span.data;
    struct md_fs_request q={.actor=actor,.operation=operation,
        .directory={input->input.base[0],input->input.base[1]},
        .flags=input->input.flags,.mode=input->input.mode,.resolve=input->input.resolve,
        .capacity=input->input.capacity,.offset=input->input.offset,.attributes=input->input.attributes,
        .value_size=input->input.value_size};
    size_t lengths[2]={input->input.length[0],input->input.length[1]};
    size_t captures[2]={input->input.capture_length[0],input->input.capture_length[1]};
    size_t capture_bytes=0;
    for (unsigned i=0;i<2;++i) {
        if (captures[i]>PATH_MAX || (captures[i] && (snapshot || executable))) return -EINVAL;
        capture_bytes+=captures[i];
        q.capture[i].flags=input->input.capture_flags[i];
        if (!captures[i] && q.capture[i].flags) return -EINVAL;
    }
    char objects[2][33]={{0}};
    size_t object_bytes=0;
    if (!snapshot) for (unsigned i=0;i<2;++i) if (input->input.object[i][0]) {
        memcpy(objects[i],input->input.object[i],sizeof(objects[i]));
        if (executable || q.directory[i]!=-1 || !md_fs_object_id_valid(objects[i])) return -EINVAL;
        object_bytes+=sizeof(objects[i]);
    }
    if (snapshot) {
        error=md_file_snapshot_flags(snapshot_flags);
        if (error) return error;
        q=(struct md_fs_request){.actor=actor,.operation=MD_FS_TEMPORARY,.directory={-1,-1}};
        lengths[0]=lengths[1]=0;
    }
    if (executable) {
        if (operation!=MD_FS_OPEN_IMAGE || !lengths[0] || q.directory[1]!=-1
                || q.flags&~O_NOFOLLOW || q.mode&~(MD_EXEC_INACCESSIBLE|MD_EXEC_OBJECT)
                || q.capacity || q.resolve || q.offset<0 || q.offset>INT_MAX
                || (!!(q.mode&MD_EXEC_OBJECT)!=!!lengths[1])) return -EINVAL;
    } else if (!md_fs_operation_valid(operation) || (operation==MD_FS_OPEN && !lengths[0])) return -EINVAL;
    for (unsigned i=0;i<2;++i)
        if (lengths[i]>PATH_MAX || (q.directory[i]<0 && q.directory[i]!=-1 && q.directory[i]!=AT_FDCWD))
            return -EINVAL;
    for (unsigned i=0;i<2;++i)
        if ((md_fs_operation_data_inputs(operation)&(1U<<i)) && q.directory[i]==AT_FDCWD)
            return -EBADF;
    if (q.value_size>MD_FS_VALUE_MAX || (q.value_size && !md_fs_operation_value(operation))) return -EINVAL;
    struct md_fs_buffer_request *r=request_new(s,actor,lengths[0]+lengths[1]+q.value_size+object_bytes+capture_bytes
        +(snapshot ? sizeof(input->snapshot.data) : 0));
    if (!r) return -ENOMEM;
    r->executable=executable;
    r->snapshot=(struct md_file_snapshot){.fd=-1,.flags=snapshot_flags};
    r->snapshot_phase=snapshot ? SNAPSHOT_BEGIN : SNAPSHOT_NONE;
    r->request=q;
    r->task_descriptor=q.directory[0];
    error=md_buffer_pin(buffer,&r->buffer);
    if (!error) {
        r->output=span.data;
        size_t offset=0;
        for (unsigned i=0;i<2 && !error;++i) {
            if (captures[i]) {
                char *path=r->path+offset;
                memcpy(path,input->input.capture_path[i],captures[i]);
                if (memchr(path,0,captures[i])!=path+captures[i]-1) error=-EINVAL;
                r->request.capture[i].path=path; offset+=captures[i];
                r->capture_mask|=1U<<i;
            }
            if (objects[i][0]) {
                memcpy(r->path+offset,objects[i],sizeof(objects[i]));
                r->request.object[i]=r->path+offset; offset+=sizeof(objects[i]);
            }
            if (lengths[i]) {
                char *path=r->path+offset;
                memcpy(path,input->input.path[i],lengths[i]);
                if (memchr(path,0,lengths[i])!=path+lengths[i]-1) error=-EINVAL;
                r->request.path[i]=path; offset+=lengths[i];
            }
        }
        if (!error && q.value_size) {
            memcpy(r->path+offset,input->value,q.value_size);
            r->request.value=r->path+offset;
        }
        if (!error && executable) {
            if ((!*r->request.path[0] && q.directory[0]<0)
                    || ((q.mode&MD_EXEC_OBJECT) && strlen(r->request.path[1])!=32)) error=-EINVAL;
        } else if (!error) error=md_fs_request_validate(&r->request);
    }
    if (error) { dispose(r); return error; }
    return request_admit(r,fs,out);
}
int md_fs_buffer_begin(struct md_fs_buffer_service *s, pid_t actor, struct md_guest_domain *fs, unsigned operation,
        const struct md_interception_buffer *buffer, struct md_fs_buffer_request **out) {
    return begin(s,actor,fs,operation,buffer,out,0,0,0);
}
int md_fs_buffer_invoke(struct md_fs_buffer_service *s,pid_t actor,struct md_guest_domain *fs,unsigned operation,
        const struct md_interception_buffer *buffer,struct md_fs_buffer_request **out) {
    int error=begin(s,actor,fs,operation,buffer,out,0,0,0);
    if (!error) (*out)->captured_only=1;
    return error;
}
int md_fs_buffer_adopt(struct md_fs_buffer_service *s,pid_t actor,struct md_guest_domain *fs,unsigned operation,unsigned flags,
        const struct md_interception_buffer *buffer,struct md_fs_result *result,struct md_fs_buffer_open *opened,
        struct md_fs_buffer_request **out) {
    if (!s || !out || *out || !opened || opened->fd<0 || !result || result->error || result->host_path) return -EINVAL;
    struct md_buffer_span span;
    int error=md_buffer_span(buffer,&span);
    if (error) return error;
    if (span.size<sizeof(struct md_fs_buffer_frame)) return -EINVAL;
    struct md_fs_buffer_request *r=calloc(1,sizeof(*r));
    if (!r) return -ENOMEM;
    r->service=s; r->actor=actor; r->output=span.data;
    r->opened.fd=r->control_descriptor=r->fifo_control=r->snapshot.fd=-1;
    r->images=(struct md_command_images){.program=-1,.loader=-1};
    r->captured[0]=r->captured[1]=-1;
    r->request=(struct md_fs_request){.actor=actor,.operation=operation,.flags=flags,.directory={-1,-1}};
    error=md_buffer_pin(buffer,&r->buffer);
    if (!error) error=md_task_registry_read(s->tasks,actor,0,&r->context.task);
    if (!error && r->context.task.fs!=fs) error=-ESTALE;
    if (error) { dispose(r); return error; }
    r->output->reply.result=*result; r->output->reply.result.fd=-1;
    r->output->reply.result.open_completion=(struct md_open_completion){0};
    r->output->reply.result.selectors=md_fd_object_selectors(opened->object);
    r->output->transfer=MD_FS_BUFFER_NO_FD; memset(r->output->source,0,sizeof(r->output->source));
    r->opened=*opened; r->adopted=1;
    r->work=(struct md_fs_work){.run=run,.complete=complete,.ready=ready};
    r->next=s->requests; s->requests=r;
    error=md_fs_worker_submit(s->worker,&r->work);
    if (error) { r->opened=(struct md_fs_buffer_open){.fd=-1}; dispose(r); return error; }
    *opened=(struct md_fs_buffer_open){.fd=-1};
    r->submitted=1; *out=r; return 0;
}
int md_fs_buffer_inspect_begin(struct md_fs_buffer_service *s, pid_t actor, struct md_guest_domain *fs,
        const struct md_interception_buffer *buffer, struct md_received_fds *sources,
        struct md_fs_buffer_request **out) {
    if (!s || !out || *out || !sources || !sources->count) return -EINVAL;
    struct md_buffer_span span;
    int error=md_buffer_span(buffer,&span);
    if (error) return error;
    if (span.size<sizeof(struct md_fs_buffer_frame)) return -EINVAL;
    struct md_fs_buffer_frame *frame=span.data;
    unsigned count=frame->rights.count;
    if (!count || count>253) return -EINVAL;
    struct md_fs_buffer_request *r=calloc(1,sizeof(*r)+count*sizeof(int));
    if (!r) return -ENOMEM;
    r->service=s; r->actor=actor; r->output=frame; r->opened.fd=r->control_descriptor=r->fifo_control=-1;
    r->images=(struct md_command_images){.program=-1,.loader=-1};
    r->snapshot.fd=-1; r->captured[0]=r->captured[1]=-1;
    r->received=md_received_fds_retain(sources); r->received_count=count;
    memcpy(r->path,frame->rights.index,count*sizeof(int));
    for (unsigned i=0;i<count && !error;++i) {
        int index; memcpy(&index,r->path+i*sizeof(index),sizeof(index));
        if (index<1 || (unsigned)index>=sources->count) error=-EBADF;
    }
    if (!error) error=md_buffer_pin(buffer,&r->buffer);
    if (!error) error=md_task_registry_read(s->tasks,actor,0,&r->context.task);
    if (!error && r->context.task.fs!=fs) error=-ESTALE;
    if (error) { dispose(r); return error; }
    r->context.actor=actor; r->context.peer=r->context.task.tgid;
    r->context.authenticated=r->context.has_identity=1;
    r->work=(struct md_fs_work){.run=run,.complete=complete,.ready=ready};
    r->next=s->requests; s->requests=r;
    error=md_fs_worker_submit(s->worker,&r->work);
    if (error) { dispose(r); return error; }
    r->submitted=1; *out=r; return 0;
}
int md_fs_buffer_exec_begin(struct md_fs_buffer_service *s, pid_t actor, struct md_guest_domain *fs,
        const struct md_interception_buffer *buffer, struct md_fs_buffer_request **out) {
    return begin(s,actor,fs,MD_FS_OPEN_IMAGE,buffer,out,1,0,0);
}
int md_fs_buffer_snapshot_begin(struct md_fs_buffer_service *s, pid_t actor, struct md_guest_domain *fs,
        const struct md_interception_buffer *buffer, unsigned flags, struct md_fs_buffer_request **out) {
    return begin(s,actor,fs,MD_FS_TEMPORARY,buffer,out,0,1,flags);
}
struct md_landlock_policy *md_fs_buffer_landlock_take(struct md_fs_buffer_request *r) {
    if (r->error || r->output->reply.result.error) return NULL;
    struct md_landlock_policy *policy=r->landlock;
    r->landlock=NULL; return policy;
}
int md_fs_buffer_exec_take(struct md_fs_buffer_request *r, int out[2], unsigned *mount_flags, int *anonymous,
        struct md_fs_anchor **origin) {
    if (!r || !out || !mount_flags || !anonymous || !origin || *origin) return -EINVAL;
    if (!r->executable) return 0;
    if (r->error || r->images.program<0 || out[0]>=0 || out[1]>=0) return -EINVAL;
    out[0]=r->images.program; out[1]=r->images.loader;
    *mount_flags=r->images.mount_flags;
    *anonymous=r->images.anonymous;
    *origin=r->image_origin; r->image_origin=NULL;
    r->images=(struct md_command_images){.program=-1,.loader=-1}; return 1;
}
static struct md_fs_anchor *capture_origin(struct md_fs_buffer_request *r,unsigned index) {
    const struct md_fs_task_capture *capture=&r->request.capture[index];
    if (!capture->path || (capture->flags&O_NOFOLLOW)) return NULL;
    struct md_proc_path path=md_proc_path_for(capture->path,r->context.task.tid,r->context.task.tgid);
    enum md_proc_kind kind=path.kind==MD_PROC_FOREIGN ? path.foreign_kind : path.kind;
    if (kind!=MD_PROC_FD || !path.tail || *path.tail) return NULL;
    struct md_task_snapshot target={0};
    if (md_task_registry_read(r->service->tasks,path.process,r->context.task.tgid,&target)) return NULL;
    /* The held table turn also orders a sharing peer's close/unshare. Keep
     * provenance only for that exact owner; the captured FD is checked again
     * by the filesystem, and kernel proc lookup still enforces access. */
    struct md_fs_anchor *origin=target.files==r->files.table
        ? md_fd_origins_get(r->files.table,path.descriptor,NULL) : NULL;
    md_task_snapshot_release(&target);
    return origin;
}
static int capture_proc_object(struct md_fs_buffer_request *r,unsigned index) {
    const struct md_fs_task_capture *capture=&r->request.capture[index];
    if (!capture->path || (capture->flags&O_NOFOLLOW)) return 0;
    struct md_proc_path path=md_proc_path_for(capture->path,r->context.task.tid,r->context.task.tgid);
    enum md_proc_kind kind=path.kind==MD_PROC_FOREIGN ? path.foreign_kind : path.kind;
    if ((kind!=MD_PROC_ROOT && kind!=MD_PROC_EXE) || !path.tail || *path.tail) return 0;
    int error;
    if (kind==MD_PROC_EXE) {
        if (!r->service->exec_capture) return -EOPNOTSUPP;
        struct md_program *image=calloc(1,sizeof(*image));
        if (!image) return -ENOMEM;
        image->fd=-1;
        r->proc_object[index]=image;
        snprintf(image->identity.path,sizeof(image->identity.path),"%s",capture->path);
        error=r->service->exec_capture(r->actor,image);
    } else {
        if (!r->service->root_capture) return -EOPNOTSUPP;
        r->root[index]=calloc(1,sizeof(*r->root[index]));
        if (!r->root[index]) return -ENOMEM;
        error=r->service->root_capture(r->actor,path.process,r->root[index]);
    }
    if (error) return error;
    r->capture_mask&=~(1U<<index);
    r->request.capture[index]=(struct md_fs_task_capture){0};
    return 1;
}
int md_fs_buffer_progress(struct md_fs_buffer_service *s) {
    if (!s) return 0;
    for (struct md_fs_buffer_request *r=s->requests,*next; r; r=next) {
        next=r->next;
        if (!ready(&r->work)) continue;
        if (r->submitted || r->opening.pid || r->delivering || r->exporting || r->channel_checking
                || r->snapshot_waiting || r->task_pending || r->capturing) continue;
        if (r->cursor_waiting) {
            if (md_ofd_order_state(&r->cursor)!=MD_RESOURCE_ORDER_READY) continue;
            r->cursor_waiting=0;
            int error=md_ofd_order_start(&r->cursor);
            if (!error) error=md_fs_worker_submit(s->worker,&r->work);
            if (error) { r->error=error; complete(&r->work); }
            else r->submitted=1;
            continue;
        }
        if (md_fd_order_state(&r->files)==MD_RESOURCE_ORDER_READY) {
            int error=md_fd_order_start(&r->files);
            if (error) return error;
            error=md_fs_order_begin(r->context.task.fs,&r->order,s->wake);
            if (error<0) {
                int released=md_fd_order_complete(&r->files);
                if (released) return released;
                r->error=error; complete(&r->work); continue;
            }
        }
        if (md_fs_order_state(&r->order)!=MD_RESOURCE_ORDER_READY) continue;
        int error=md_fs_order_start(&r->order);
        if (error) return error;
        md_fs_anchor_release(r->context.task.cwd);
        md_domain_paths(r->context.task.fs,&r->context.task.root,&r->context.task.cwd);
        int process=-1;
        unsigned data=md_fs_operation_data_inputs(r->request.operation);
        if (r->executable && !*r->request.path[0]) data=1;
        for (unsigned i=0;i<2 && !error;++i) {
            int base=r->request.directory[i];
            int bind_source=(i==1 && r->request.operation==MD_FS_MOUNT && r->request.mode==MD_FS_MOUNT_BIND)
                || (!i && r->request.operation==MD_FS_OPEN_TREE);
            if (bind_source && (r->capture_mask&(1U<<i)) && s->control_capture && s->control_query) {
                int found=s->control_capture(r->actor,r->request.capture[i].path,&r->control_input);
                if (found<0) { error=found; break; }
                if (found) {
                    found=s->control_query(r->control_input,r->request.operation,&r->request.control);
                    if (found<=0) { error=found ? found : -EOPNOTSUPP; break; }
                    r->capture_mask&=~(1U<<i);
                    r->request.capture[i]=(struct md_fs_task_capture){0};
                    continue;
                }
            }
            if (r->capture_mask&(1U<<i)) {
                int captured=capture_proc_object(r,i);
                if (captured<0) { error=captured; break; }
                if (captured) continue;
                r->input[i]=r->request.operation==MD_FS_FDINFO ? NULL : capture_origin(r,i);
                r->request.origin[i]=r->input[i];
            }
            if (base>=0 && ((!i && (r->request.operation==MD_FS_FSCONFIG || r->request.operation==MD_FS_FSMOUNT
                        || r->request.operation==MD_FS_BPF || r->request.operation==MD_FS_LANDLOCK))
                    || (i==1 && r->request.operation==MD_FS_FDINFO)
                    || (bind_source
                        && r->request.path[i] && !*r->request.path[i]))
                    && s->control_query) {
                r->control_input=md_fd_origins_object(r->files.table,base,NULL);
                int found=s->control_query(r->control_input,r->request.operation,&r->request.control);
                if (found<0) { error=found; break; }
                if (found && r->request.operation!=MD_FS_FDINFO) continue;
            }
            if (base==AT_FDCWD) r->input[i]=md_fs_anchor_retain(r->context.task.cwd);
            else if (base>=0) r->input[i]=md_fd_origins_get(r->files.table,base,NULL);
            if (!i && base>=0 && !r->input[i] && r->request.operation==MD_FS_MOUNT && s->control_query) {
                struct md_fd_object *object=md_fd_origins_object(r->files.table,base,NULL);
                struct md_control_file file={0};
                int found=s->control_query(object,r->request.operation,&file);
                if (found>0 && file.ops->origin) r->input[i]=md_fs_anchor_retain(file.ops->origin(file.context));
                if (found>0 && !r->input[i]) error=-EOPNOTSUPP;
                else if (found<0) error=found;
                md_fd_object_release(object);
                if (error) break;
            }
            if (!i && base>=0 && r->request.operation==MD_FS_REOPEN) {
                struct md_fd_object *object=md_fd_origins_object(r->files.table,base,NULL);
                if (md_descriptor_inode_is(object)) r->reopened=object;
                else md_fd_object_release(object);
            }
            if (base!=-1) {
                r->request.origin[i]=r->input[i];
                if (r->input[i] && !(data&(1U<<i))) {
                    r->request.directory[i]=md_fs_anchor_fd(r->input[i]);
                } else if (r->captured_only) {
                    error=MD_FS_BUFFER_NEEDS_TASK;
                } else if (base>=0) {
                    int fd=md_task_descriptor_copy(r->actor,base,&process);
                    if (fd>=0) r->request.directory[i]=r->captured[i]=fd;
                    else if (md_task_descriptor_needs_export(fd))
                        r->export_mask|=1U<<i;
                    else error=fd;
                } else {
                    r->capture_mask|=1U<<i;
                    r->request.capture[i]=(struct md_fs_task_capture){".",O_PATH|O_DIRECTORY};
                }
            }
        }
        if (process>=0) close(process);
        r->context.actor=r->actor; r->context.authenticated=r->context.has_identity=1;
        if (!error && r->captured_only && (r->capture_mask || r->export_mask)) error=MD_FS_BUFFER_NEEDS_TASK;
        if (!error && r->capture_mask) {
            /* EVENT_WAIT: private-table cwd capture and exact helper reaping.
             * Cancellation retains both turns until helper completion. */
            capture_begin(r);
            continue;
        }
        /* Root replacement and task-affine fchdir publish CLONE_FS mutations,
         * rather than captured reads. Keep their context until completion. */
        int released=retains_context(r) ? 0 : md_fs_order_complete(&r->order);
        if (released) return released;
        if (!error && r->export_mask) {
            error=export_begin(r);
            if (!error) continue;
        }
        submit(r,error);
    }
    return 0;
}
void md_fs_buffer_cancel(struct md_fs_buffer_request **owner) {
    if (!owner || !*owner) return;
    struct md_fs_buffer_request *r=*owner; *owner=NULL;
    r->cancelled=1;
    if (r->capturing==2) return;
    if (r->opening.pid) {
        /* EVENT_WAIT: SIGKILL terminates this request's isolated open; its
         * terminal child event releases the retained mapping and origins. */
        md_open_job_cancel(&r->opening);
        return;
    }
    if (r->submitted) return;
    /* Once offered, a lost acknowledgement cannot prove that bytes were not
     * copied. Retire the reservation instead of duplicating delivered events. */
    if (r->reserved && !finish(r,r->delivering)) return;
    dispose(r);
}
void md_fs_buffer_describe(struct md_fs_buffer_service *s, int fd) {
    if (!s) return;
    for (struct md_fs_buffer_request *r=s->requests;r;r=r->next)
        dprintf(fd,"PROBE buffer-pending actor=%d operation=%u files=%d fs=%d submitted=%d cancelled=%d delivering=%d finishing=%d\n",
            r->actor,r->request.operation,md_fd_order_state(&r->files),md_fs_order_state(&r->order),
            r->submitted,r->cancelled,r->delivering,r->finishing);
}

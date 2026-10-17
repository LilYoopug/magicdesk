#define _GNU_SOURCE
#include "cooperative_channel.h"
#include "cooperative_entry.h"
#include "execution_window.h"
#include "file_metadata.h"
#include "fd_mutation.h"
#include "fs_engine.h"
#include "fs_mounts.h"
#include "fs_mount_internal.h"
#include "fs_native.h"
#include "fs_path_call.h"
#include "fs_wire.h"
#include "inode_internal.h"
#include "task_resources.h"
#include "task_status.h"
#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <sys/auxv.h>

/* Deliberately not linked into bootstrap/supervisor. A fixed, single-threaded
 * fixture actor is not a production replacement for lifecycle/filter admission. */
struct pipeline;
struct owner {
    struct md_filesystem fs;
    struct md_task_resources resources;
    struct md_identity identity;
    pid_t actor;
    uint64_t sequence, completed;
    int enabled;
    int profiling;
    int read_window;
    int tracked_files;
    struct md_fd_loan *custody;
    struct md_cooperative_client *fd_executor;
    struct pipeline *pipeline;
    unsigned retired_files;
    struct md_execution_window window;
    uint64_t leases;
    struct md_cost admission, mask;
    struct md_fs_statistics operations;
    struct md_inode_statistics storage;
};
struct pipeline {
    struct md_cooperative_channel *jobs, *guest;
    struct md_fd_order turn;
    struct md_fd_origin_update update;
    struct md_fd_mutation mutation;
    struct md_fs_anchor *held_origin;
    struct md_cooperative_response response;
    struct owner *owner;
    int operation, active, target, delivery[2], ack[2], signal_ack[2], lost;
    int reopen, reopenable, source, open_flags, engine_pidfd, prepared_open, plan_raced, direct_pending;
    unsigned direct_plans, source_borrowed, queued_closes;
    struct md_fs_anchor *retired[64];
    atomic_uint retired_read, retired_write, retired_waiting;
    unsigned count;
    int kind;
    const char *store;
    pthread_barrier_t startup;
    pid_t actor;
};
_Alignas(64) static _Thread_local struct pipeline *preparing_open;
int __real_mdi_backing_open(struct md_inode_store *,const struct mdi_node *,int);
int __wrap_mdi_backing_open(struct md_inode_store *store,const struct mdi_node *node,int flags) {
    /* Lab-only split after the real engine's walk and access checks. A pinned
     * regular object replaces data-open; all other flags/providers stay intact. */
    if (preparing_open && node->kind==S_IFREG && !(flags&~(O_CLOEXEC|O_LARGEFILE))) {
        int fd=__real_mdi_backing_open(store,node,O_PATH);
        if (fd>=0) preparing_open->prepared_open=1;
        return fd;
    }
    return __real_mdi_backing_open(store,node,flags);
}
void __real_md_view_capture(struct md_filesystem *,struct md_mount_namespace *,struct md_view_mount *,
    struct md_fs_result *,const struct md_fs_output *);
void __wrap_md_view_capture(struct md_filesystem *fs,struct md_mount_namespace *view,struct md_view_mount *mount,
        struct md_fs_result *out,const struct md_fs_output *output) {
    if (!preparing_open || preparing_open->reopen<6 || !preparing_open->prepared_open
            || out->error || out->fd<0 || !output || !output->origin) {
        __real_md_view_capture(fs,view,mount,out,output); return;
    }
    /* The origin owns the already-pinned O_PATH descriptor; the plan borrows
     * it until completion. Do not reopen and retain a second copy. */
    struct stat st;
    if (fstat(out->fd,&st)) out->error=-errno;
    struct md_fs_anchor *origin=out->error ? NULL : md_view_anchor_new(
        md_inode_store_lifetime(fs->store),view,mount,out->fd,st.st_dev,st.st_ino);
    if (!out->error && !origin) out->error=-errno;
    if (out->error) { assert(!close(out->fd)); out->fd=-1; return; }
    *output->origin=origin; preparing_open->source_borrowed=1;
}
static int pipeline_close(struct pipeline *,int);
static int64_t clock_ns(void) {
    struct timespec t; assert(!clock_gettime(CLOCK_MONOTONIC,&t));
    return (int64_t)t.tv_sec*1000000000+t.tv_nsec;
}
static int acquire_scope(void *context) {
    struct owner *owner=context;
    int error=md_inode_read_scope_begin(owner->fs.store);
    if (!error) ++owner->leases;
    return error;
}
static int release_scope(void *context) {
    return md_inode_read_scope_end(((struct owner *)context)->fs.store);
}
static void release_read(void *context) {
    assert(!md_execution_window_end(&((struct owner *)context)->window));
}
static int admit_read(struct owner *owner,int eligible) {
    if (!owner->read_window) return 0;
    return md_execution_window_admit(&owner->window,eligible ? owner : NULL,
        acquire_scope,release_scope,clock_ns(),32,100000);
}
static struct md_cooperative_request packet(int nr,const char *a,const char *b,unsigned flags,unsigned mode) {
    struct md_cooperative_request q={.syscall=nr,.flags=flags,.mode=mode};
    const char *path[2]={a ? a : "",b ? b : ""};
    for (unsigned i=0;i<2;++i) {
        size_t size=strlen(path[i])+1; assert(size<=PATH_MAX);
        q.length[i]=(uint32_t)size; memcpy(q.path[i],path[i],size);
    }
    return q;
}
static int executor_close(struct owner *owner,int fd) {
    if (owner->pipeline) return pipeline_close(owner->pipeline,fd);
    if (!owner->fd_executor) return close(fd) ? -errno : 0;
    struct md_cooperative_request q=packet(SYS_close,NULL,NULL,(unsigned)fd,0);
    struct md_cooperative_response out=md_cooperative_call(owner->fd_executor,&q);
    assert(out.outcome==MD_COOPERATIVE_COMPLETED && out.fd==-1);
    return out.error;
}
static int executor_install(struct owner *owner,int source) {
    if (!owner->fd_executor) return source;
    struct md_cooperative_client *client=owner->fd_executor;
    uint64_t sequence=client->sequence+1;
    assert(md_fs_send_fds(client->delivery,&sequence,sizeof(sequence),&source,1)==sizeof(sequence));
    struct md_cooperative_request q=packet(SYS_recvmsg,NULL,NULL,0,0);
    struct md_cooperative_response out=md_cooperative_call(client,&q);
    assert(!close(source));
    /* The number belongs to the executor/client table, never the engine's. */
    assert(out.outcome==MD_COOPERATIVE_COMPLETED && !out.error && out.fd>=0);
    return out.fd;
}
static struct md_cooperative_response execute(struct owner *owner,const struct md_cooperative_request *in) {
    struct md_cooperative_response out={.sequence=in->sequence,.outcome=MD_COOPERATIVE_DECLINED,.fd=-1};
    if (!owner->enabled) { out.error=-EAGAIN; return out; }
    if (in->syscall==SYS_close && owner->tracked_files) {
        struct md_fs_context context;
        out.error=md_fs_context_begin(&owner->fs,owner->actor,0,&context);
        if (out.error) return out;
        struct md_fd_order local_turn={0},*turn=owner->pipeline ? &owner->pipeline->turn : &local_turn;
        assert(md_fd_order_begin(context.task.files,turn,NULL)==1);
        assert(!md_fd_order_start(turn));
        unsigned long args[6]={in->flags};
        struct md_fd_mutation local_change,*change=owner->pipeline ? &owner->pipeline->mutation : &local_change;
        assert(!md_fd_mutation_prepare(context.task.files,SYS_close,args,change));
        if (owner->pipeline) {
            struct pipeline *p=owner->pipeline;
            /* Final anchor destruction must run in the engine's file table. */
            p->held_origin=md_fd_origins_get(context.task.files,(int)in->flags,NULL);
            p->operation=SYS_close; p->target=(int)in->flags; p->active=1;
        } else {
            out.error=executor_close(owner,(int)in->flags);
            assert(!md_fd_mutation_finish(change,context.task.files,out.error));
            assert(!md_fd_order_complete(turn));
        }
        md_fs_context_end(&context);
        out.outcome=MD_COOPERATIVE_COMPLETED; ++owner->completed;
        return out;
    }
    if (in->path[0][0]!='/' || (*in->path[1] && in->path[1][0]!='/')) {
        out.error=-EOPNOTSUPP; return out;
    }
    struct md_fs_request q={.actor=owner->actor,.peer=0,.directory={-1,-1},
        .path={in->path[0],in->path[1]}};
    if (in->syscall==SYS_openat) {
        if (*in->path[1] || (in->flags!=(O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC)
                && in->flags!=(O_RDONLY|O_CLOEXEC))) { out.error=-EOPNOTSUPP; return out; }
        md_fs_open_parameters(&q,in->flags,in->mode,0);
    } else if (in->syscall==SYS_newfstatat) {
        if (in->mode || *in->path[1]) { out.error=-EINVAL; return out; }
        q.operation=MD_FS_STAT; q.flags=in->flags;
    } else {
        if (in->syscall!=SYS_mkdirat && in->syscall!=SYS_unlinkat && in->syscall!=SYS_renameat2) {
            out.error=-EOPNOTSUPP; return out;
        }
        unsigned long args[6]={(unsigned long)AT_FDCWD,0,
            in->syscall==SYS_mkdirat ? in->mode : in->syscall==SYS_unlinkat ? in->flags : (unsigned long)AT_FDCWD,
            0,in->flags,0};
        assert(md_fs_path_call(&q,in->syscall,args));
        q.directory[1]=-1;
    }
    out.error=admit_read(owner,q.operation==MD_FS_STAT || (owner->pipeline && owner->pipeline->reopen>=8
        && q.operation==MD_FS_OPEN && q.flags==(O_RDONLY|O_CLOEXEC)));
    if (out.error) return out;
    struct md_fs_context context;
    int64_t admitted=md_cost_begin(owner->profiling ? &owner->admission : NULL);
    out.error=md_fs_context_begin(&owner->fs,owner->actor,0,&context);
    md_cost_end(owner->profiling ? &owner->admission : NULL,admitted);
    if (out.error) { release_read(owner); return out; }
    if (owner->profiling && q.attributes.creation_mask==MD_FS_CAPTURE_UMASK) {
        int64_t start=md_cost_begin(&owner->mask);
        long mask=md_task_umask(owner->actor);
        md_cost_end(&owner->mask,start);
        assert(mask>=0); q.attributes.creation_mask=(unsigned)mask;
    }
    struct md_fs_result result;
    if (owner->window.owner && owner->read_window!=1) owner->fs.store->directory_check_count=0;
    struct md_fs_anchor *origin=NULL;
    struct md_fs_output output={.origin=q.operation==MD_FS_OPEN ? &origin : NULL};
    if (owner->pipeline) owner->pipeline->prepared_open=owner->pipeline->source_borrowed=0;
    preparing_open=owner->pipeline && owner->pipeline->reopen>=4 && q.operation==MD_FS_OPEN
        && q.flags==(O_RDONLY|O_CLOEXEC) ? owner->pipeline : NULL;
    md_fs_context_execute(&context,&q,&result,owner->tracked_files ? &output : NULL);
    preparing_open=NULL;
    if (result.open_completion.kind || result.host_path || result.requires_control) {
        if (result.fd>=0) assert(!close(result.fd));
        if (result.open_completion.kind==MD_OPEN_PIPE) assert(!close(result.open_completion.control));
        result.fd=-1; result.error=-EOPNOTSUPP;
    }
    if (owner->tracked_files && result.fd>=0 && !result.error) {
        struct md_fd_order local_turn={0},*turn=owner->pipeline ? &owner->pipeline->turn : &local_turn;
        assert(md_fd_order_begin(context.task.files,turn,NULL)==1);
        assert(!md_fd_order_start(turn));
        struct md_fd_origin_update local_update={0},*update=owner->pipeline ? &owner->pipeline->update : &local_update;
        assert(!md_fd_origins_prepare(context.task.files,origin,
            in->flags&O_CLOEXEC ? FD_CLOEXEC : 0,update));
        if (owner->custody) assert(!md_fd_origins_prepare_loan(update,owner->custody));
        if (owner->pipeline) {
            struct pipeline *p=owner->pipeline;
            p->held_origin=origin; origin=NULL;
            p->operation=SYS_openat; p->active=1;
            p->open_flags=(int)in->flags&(O_ACCMODE|O_CLOEXEC);
            p->reopenable=0;
            if (p->reopen==1) {
                struct stat st; assert(!fstat(result.fd,&st));
                p->reopenable=S_ISREG(st.st_mode);
            } else if (p->reopen>=2) p->reopenable=1;
        } else {
            result.fd=executor_install(owner,result.fd);
            md_fd_origins_finish(update,result.fd);
            assert(!md_fd_order_complete(turn));
        }
    }
    md_fs_anchor_release(origin);
    md_fs_context_end(&context);
    out.outcome=MD_COOPERATIVE_COMPLETED; out.error=result.error; out.info=result.info;
    out.fd=result.fd;
    ++owner->completed;
    return out;
}
static void owner_open(struct owner *owner,const char *store,pid_t actor) {
    memset(owner,0,sizeof(*owner)); owner->actor=actor; owner->enabled=1;
    assert(!md_inode_store_open(store,0,&owner->fs.store));
    assert(!md_fs_mounts_open(&owner->fs,NULL,0));
    owner->fs.tasks=md_task_registry_create(); assert(owner->fs.tasks);
    owner->resources=(struct md_task_resources){.fs=md_domain_new(),.files=md_fd_origins_new(),
        .mounts=owner->fs.mounts};
    owner->identity=md_identity_new(0,0);
    assert(owner->resources.fs && owner->resources.files);
    assert(!md_task_registry_publish(owner->fs.tasks,actor,actor,&owner->identity,&owner->resources));
}
static void owner_close(struct owner *owner) {
    release_read(owner);
    if (owner->custody) {
        /* The sole client has exited and cannot reuse a slot. Reuse the real
         * operation-loan inventory to retire even unacknowledged publications. */
        md_fd_loan_end(owner->custody);
        struct md_fd_order turn={0};
        assert(md_fd_order_begin(owner->resources.files,&turn,NULL)==1);
        assert(!md_fd_order_start(&turn));
        int number,ready;
        while ((ready=md_fd_origins_loan_next(&turn,&number))>0) {
            assert(!executor_close(owner,number));
            assert(!md_fd_origins_close_range(turn.table,(unsigned)number,(unsigned)number,0));
            ++owner->retired_files;
        }
        assert(!ready && !md_fd_order_complete(&turn));
        md_fd_loan_release(owner->custody); owner->custody=NULL;
    }
    md_task_registry_forget(owner->fs.tasks,owner->actor);
    md_task_registry_destroy(owner->fs.tasks);
    md_identity_release(&owner->identity);
    md_domain_release(owner->resources.fs); md_fd_origins_release(owner->resources.files);
    md_fs_mounts_close(&owner->fs); md_inode_store_close(owner->fs.store);
}
static void profile_report(const struct owner *owner) {
    const struct md_inode_statistics *s=&owner->storage;
    const struct md_cost *costs[]={&owner->admission,&owner->mask,&s->prepare,&s->step,&s->lock,
        &s->version,&s->descriptor,&s->path,&s->transaction};
    const char *names[]={"admission","umask","prepare","step","lock","version","descriptor","path","transaction"};
    for (unsigned i=0;i<sizeof(costs)/sizeof(costs[0]);++i)
        printf("COOPERATIVE_PROFILE {\"phase\":\"%s\",\"calls\":%llu,\"nanoseconds\":%llu}\n",
            names[i],(unsigned long long)costs[i]->calls,(unsigned long long)costs[i]->nanoseconds);
    printf("COOPERATIVE_PROFILE {\"walkComponents\":%llu,\"materializations\":%llu,\"cacheHits\":%llu,\"cacheMisses\":%llu,\"writeAdmissions\":%llu}\n",
        (unsigned long long)s->walk_components,(unsigned long long)s->walk_materializations,
        (unsigned long long)s->metadata_cache_hits,(unsigned long long)s->metadata_cache_misses,
        (unsigned long long)s->write_admissions);
    md_fs_statistics_report(STDOUT_FILENO,&owner->operations);
    printf("COOPERATIVE_PROFILE {\"directoryCheckHits\":%llu,\"directoryCheckMisses\":%llu}\n",
        (unsigned long long)s->directory_check_hits,(unsigned long long)s->directory_check_misses);
}
static void prepare(const char *path,const char *executable) {
    struct md_inode_store *store=NULL;
    assert(!md_inode_store_open(path,1,&store));
    md_inode_store_close(store);
    /* Match a guest-created directory. Offline real-permission directories
     * deliberately exclude native leaves and measure a different storage path. */
    struct owner owner; owner_open(&owner,path,getpid());
    struct md_cooperative_request q=packet(SYS_mkdirat,"/bench",NULL,0,0755);
    struct md_cooperative_response out=execute(&owner,&q); assert(!out.error);
    q=packet(SYS_mkdirat,"/fixture",NULL,0,0755);
    out=execute(&owner,&q); assert(!out.error);
    q=packet(SYS_openat,"/bench/marker",NULL,O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0644);
    out=execute(&owner,&q); assert(!out.error && out.fd>=0);
    assert(write(out.fd,"marker",6)==6 && !close(out.fd));
    /* Run the identical binary from the store, without giving only the
     * production baseline an extra bind-mount topology. Outside timed work. */
    q=packet(SYS_openat,"/fixture/benchmark",NULL,O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0700);
    out=execute(&owner,&q); assert(!out.error && out.fd>=0);
    int source=open(executable,O_RDONLY|O_CLOEXEC); assert(source>=0);
    char buffer[65536]; ssize_t size;
    while ((size=read(source,buffer,sizeof(buffer)))>0) {
        ssize_t done=0;
        while (done<size) { ssize_t n=write(out.fd,buffer+done,(size_t)(size-done)); assert(n>0); done+=n; }
    }
    assert(!size && !close(source) && !close(out.fd));
    owner_close(&owner);
}
static double seconds(void) {
    struct timespec value; assert(!clock_gettime(CLOCK_MONOTONIC,&value));
    return value.tv_sec+value.tv_nsec/1e9;
}
static double cpu(const struct rusage *usage) {
    return usage->ru_utime.tv_sec+usage->ru_utime.tv_usec/1e6
        +usage->ru_stime.tv_sec+usage->ru_stime.tv_usec/1e6;
}
typedef struct md_cooperative_response (*invoke)(void *,const struct md_cooperative_request *);
static struct md_cooperative_response invoke_native(void *,const struct md_cooperative_request *);
static struct md_cooperative_response invoke_engine(void *context,const struct md_cooperative_request *q) {
    if (q->syscall==SYS_close && !((struct owner *)context)->tracked_files) return invoke_native(NULL,q);
    return execute(context,q);
}
static struct md_cooperative_response invoke_channel(void *context,const struct md_cooperative_request *q) {
    struct md_cooperative_client *client=context;
    if (q->syscall==SYS_close && client->closer && !client->channel->completion_queue) {
        if (client->channel->prepared_open) assert(!md_cooperative_sync(client));
        return md_cooperative_call(client->closer,q);
    }
    if (q->syscall==SYS_close && ((struct md_cooperative_client *)context)->channel->shared_files<2)
        return invoke_native(NULL,q);
    return md_cooperative_call(context,q);
}
static struct md_cooperative_response invoke_native(void *context,const struct md_cooperative_request *q) {
    (void)context;
    struct md_cooperative_response out={.outcome=MD_COOPERATIVE_COMPLETED,.fd=-1};
    long result;
    if (q->syscall==SYS_close) result=syscall(SYS_close,q->flags);
    else if (q->syscall==SYS_openat) {
        result=syscall(SYS_openat,AT_FDCWD,q->path[0],q->flags,q->mode);
        if (result>=0) out.fd=(int)result;
    } else if (q->syscall==SYS_newfstatat) {
        struct stat st;
        result=syscall(SYS_newfstatat,AT_FDCWD,q->path[0],&st,q->flags);
        if (!result) md_fs_stat_info(&st,&out.info);
    } else if (q->syscall==SYS_mkdirat) result=syscall(SYS_mkdirat,AT_FDCWD,q->path[0],q->mode);
    else if (q->syscall==SYS_unlinkat) result=syscall(SYS_unlinkat,AT_FDCWD,q->path[0],q->flags);
    else result=syscall(SYS_renameat2,AT_FDCWD,q->path[0],AT_FDCWD,q->path[1],q->flags);
    if (result<0) out.error=-errno;
    return out;
}
struct direct_client { const struct md_entry_api *api; struct md_entry_client client; unsigned completed,declined; };
static struct md_cooperative_response invoke_direct(void *context,const struct md_cooperative_request *q) {
    struct direct_client *client=context;
    struct stat st;
    struct md_entry_call call={.number=q->syscall,.args={AT_FDCWD,(uintptr_t)q->path[0]}};
    if (q->syscall==SYS_close) call.args[0]=q->flags;
    else if (q->syscall==SYS_newfstatat) { call.args[2]=(uintptr_t)&st; call.args[3]=q->flags; }
    else if (q->syscall==SYS_openat) { call.args[2]=q->flags; call.args[3]=q->mode; }
    else if (q->syscall==SYS_mkdirat) call.args[2]=q->mode;
    else if (q->syscall==SYS_unlinkat) call.args[2]=q->flags;
    else { call.args[2]=AT_FDCWD; call.args[3]=(uintptr_t)q->path[1]; call.args[4]=q->flags; }
    enum md_entry_outcome outcome=md_entry_invoke(client->api,&client->client,&call);
    assert(outcome!=MD_ENTRY_UNKNOWN);
    if (outcome==MD_ENTRY_DECLINED) { ++client->declined; return invoke_native(NULL,q); }
    ++client->completed;
    struct md_cooperative_response out={.outcome=MD_COOPERATIVE_COMPLETED,.fd=-1};
    if (call.result<0) out.error=(int)call.result;
    else if (q->syscall==SYS_newfstatat) md_fs_stat_info(&st,&out.info);
    else if (q->syscall==SYS_openat) out.fd=(int)call.result;
    return out;
}
static struct md_cooperative_response checked(invoke call,void *context,const struct md_cooperative_request *q,int error) {
    struct md_cooperative_response out=call(context,q);
    if (out.outcome!=MD_COOPERATIVE_COMPLETED || out.error!=error)
        fprintf(stderr,"cooperative nr=%d path=%s outcome=%d error=%d expected=%d\n",
            q->syscall,q->path[0],out.outcome,out.error,error);
    assert(out.outcome==MD_COOPERATIVE_COMPLETED && out.error==error);
    return out;
}
static unsigned fd_count(void) {
    DIR *directory=opendir("/proc/thread-self/fd"); assert(directory);
    unsigned count=0; struct dirent *entry;
    while ((entry=readdir(directory))) if (strcmp(entry->d_name,".") && strcmp(entry->d_name,"..")) ++count;
    assert(!closedir(directory)); return count;
}
static void close_result(invoke call,void *context,int fd) {
    struct md_cooperative_request q=packet(SYS_close,NULL,NULL,(unsigned)fd,0);
    checked(call,context,&q,0);
}
static void file_cycle(invoke call,void *context,const char *base,unsigned i,const char *bytes) {
    char a[PATH_MAX],b[PATH_MAX];
    assert(snprintf(a,sizeof(a),"%s/write-%d-%u",base,getpid(),i)<(int)sizeof(a));
    assert(snprintf(b,sizeof(b),"%s/moved-%d-%u",base,getpid(),i)<(int)sizeof(b));
    struct md_cooperative_request q=packet(SYS_openat,a,NULL,O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    struct md_cooperative_response out=checked(call,context,&q,0);
    assert(out.fd>=0 && write(out.fd,bytes,4096)==4096);
    close_result(call,context,out.fd);
    q=packet(SYS_renameat2,a,b,0,0); checked(call,context,&q,0);
    q=packet(SYS_unlinkat,b,NULL,0,0); checked(call,context,&q,0);
}
static void open_cycle(invoke call,void *context,const char *marker) {
    struct md_cooperative_request q=packet(SYS_openat,marker,NULL,O_RDONLY|O_CLOEXEC,0);
    struct md_cooperative_response out=checked(call,context,&q,0);
    assert(out.fd>=0); close_result(call,context,out.fd);
}
static void workload_flush(invoke call,void *context) {
    if (call==invoke_channel && ((struct md_cooperative_client *)context)->channel->completion_queue)
        assert(!md_cooperative_sync(context));
}
static void workload(const char *mode,const char *base,unsigned count,int kind,invoke call,void *context) {
    char a[PATH_MAX],b[PATH_MAX],marker[PATH_MAX];
    assert(snprintf(a,sizeof(a),"%s/entry-a",base)<(int)sizeof(a));
    assert(snprintf(b,sizeof(b),"%s/entry-b",base)<(int)sizeof(b));
    assert(snprintf(marker,sizeof(marker),"%s/marker",base)<(int)sizeof(marker));
    struct md_cooperative_request requests[]={packet(SYS_mkdirat,a,NULL,0,0700),
        packet(SYS_renameat2,a,b,0,0),packet(SYS_unlinkat,b,NULL,AT_REMOVEDIR,0),
        packet(SYS_newfstatat,marker,NULL,0,0)};
    unsigned first=kind==1 ? 3 : 0;
    char bytes[4096]; memset(bytes,42,sizeof(bytes));
    for (unsigned i=0;i<32;++i) {
        if (kind==3) open_cycle(call,context,marker);
        else if (kind==2) file_cycle(call,context,base,i,bytes);
        else for (unsigned j=first;j<4;++j) checked(call,context,&requests[j],0);
    }
    workload_flush(call,context);
    unsigned descriptors=fd_count();
    struct rusage before,after; assert(!getrusage(RUSAGE_SELF,&before));
    double start=seconds();
    for (unsigned i=0;i<count;++i) {
        if (kind==3) open_cycle(call,context,marker);
        else if (kind==2) file_cycle(call,context,base,i,bytes);
        else for (unsigned j=first;j<4;++j) checked(call,context,&requests[j],0);
    }
    workload_flush(call,context);
    double duration=seconds()-start;
    assert(!getrusage(RUSAGE_SELF,&after));
    assert(fd_count()==descriptors);
    printf("COOPERATIVE_BENCH {\"mode\":\"%s\",\"workload\":\"%s\",\"iterations\":%u,\"calls\":%u,\"seconds\":%.9f,\"callerCpuSeconds\":%.9f,\"voluntarySwitches\":%ld,\"involuntarySwitches\":%ld}\n",
        mode,kind==3 ? "opens" : kind==2 ? "files" : kind==1 ? "metadata" : "directories",count,
        count*(kind==3 ? 2 : kind==2 ? 5 : 4-first),duration,cpu(&after)-cpu(&before),
        after.ru_nvcsw-before.ru_nvcsw,after.ru_nivcsw-before.ru_nivcsw);
    fflush(stdout);
}
static volatile sig_atomic_t signals,reentrant;
static int signal_ack=-1;
static struct md_cooperative_client *signal_client;
static struct md_cooperative_request signal_request;
static void interrupt(int signal) {
    (void)signal;
    int saved=errno; ++signals;
    if (signal_client) {
        struct md_cooperative_response out=md_cooperative_call(signal_client,&signal_request);
        if (out.outcome==MD_COOPERATIVE_DECLINED && out.error==-EBUSY) ++reentrant;
    }
    char ack=1;
    if (write(signal_ack,&ack,1)!=1) _exit(98);
    errno=saved;
}
static void channel_checks(struct md_cooperative_client *client) {
    struct md_cooperative_request q=packet(SYS_mkdirat,"/bench/interrupted",NULL,0,0700);
    signal_request=q; signal_client=client;
    checked(invoke_channel,client,&q,0);
    assert(signals==1 && reentrant==1);
    signal_client=NULL;
    checked(invoke_channel,client,&q,-EEXIST);
    q=packet(SYS_unlinkat,"/bench/interrupted",NULL,AT_REMOVEDIR,0);
    checked(invoke_channel,client,&q,0);
    q=packet(SYS_newfstatat,"/bench/missing",NULL,0,0);
    checked(invoke_channel,client,&q,-ENOENT);
    q=packet(SYS_openat,"/bench/must-not-create",NULL,O_CREAT|O_TRUNC|O_RDWR,0600);
    struct md_cooperative_response out=md_cooperative_call(client,&q);
    assert(out.outcome==MD_COOPERATIVE_DECLINED && out.error==-EOPNOTSUPP);
    q=packet(SYS_newfstatat,"/bench/must-not-create",NULL,0,0);
    checked(invoke_channel,client,&q,-ENOENT);
    q.length[0]=PATH_MAX+1;
    out=md_cooperative_call(client,&q);
    assert(out.outcome==MD_COOPERATIVE_DECLINED && out.error==-EPROTO);
    q=packet(SYS_newfstatat,"/bench/marker",NULL,0,0);
    uint64_t sequence=client->sequence;
    --client->sequence;
    out=md_cooperative_call(client,&q);
    assert(out.outcome==MD_COOPERATIVE_DECLINED && out.error==-ESTALE);
    client->sequence=sequence;
    checked(invoke_channel,client,&q,0);
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        out=md_cooperative_call(client,&q);
        _exit(out.outcome==MD_COOPERATIVE_DECLINED && out.error==-EXDEV ? 0 : 99);
    }
    int status; assert(waitpid(child,&status,0)==child && status==0);
    assert(!prctl(PR_SET_DUMPABLE,0));
    checked(invoke_channel,client,&q,0);
    q=packet(SYS_openat,"/bench/received",NULL,O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    out=checked(invoke_channel,client,&q,0);
    int fd=out.fd;
    assert(fd>=0 && (fcntl(fd,F_GETFD)&FD_CLOEXEC) && write(fd,"data",4)==4);
    q=packet(SYS_renameat2,"/bench/received","/bench/received-renamed",0,0);
    checked(invoke_channel,client,&q,0);
    q=packet(SYS_openat,"/bench/received-renamed",NULL,O_RDONLY|O_CLOEXEC,0);
    out=checked(invoke_channel,client,&q,0);
    char value[4]; assert(read(out.fd,value,4)==4 && !memcmp(value,"data",4));
    close_result(invoke_channel,client,out.fd);
    q=packet(SYS_unlinkat,"/bench/received-renamed",NULL,0,0);
    checked(invoke_channel,client,&q,0);
    assert(pread(fd,value,4,0)==4 && !memcmp(value,"data",4));
    close_result(invoke_channel,client,fd);
    assert(!prctl(PR_SET_DUMPABLE,1));
}
static struct md_cooperative_channel *channel_new(void) {
    struct md_cooperative_channel *channel=mmap(NULL,sizeof(*channel),PROT_READ|PROT_WRITE,
        MAP_SHARED|MAP_ANONYMOUS,-1,0);
    assert(channel!=MAP_FAILED);
    atomic_init(&channel->state,MD_COOPERATIVE_IDLE);
    atomic_init(&channel->sleeping[0],0); atomic_init(&channel->sleeping[1],0);
    atomic_init(&channel->event[0],0); atomic_init(&channel->event[1],0);
    atomic_init(&channel->completion_write,0); atomic_init(&channel->completion_read,0);
    atomic_init(&channel->completion_waiting,0);
    return channel;
}
static void completion_event_wait(struct md_cooperative_channel *channel,unsigned event) {
    atomic_store_explicit(&channel->sleeping[1],1,memory_order_seq_cst);
    struct timespec timeout={5,0};
    /* EVENT_WAIT: producer fills the queue or registers backpressure; timeout
     * fails the fixture, never supplies evidence of queue progress. */
    if (atomic_load_explicit(&channel->event[1],memory_order_seq_cst)==event) {
        int result=(int)syscall(SYS_futex,&channel->event[1],FUTEX_WAIT,event,&timeout,NULL,0);
        assert(!result || errno==EAGAIN || errno==EINTR);
    }
    atomic_store_explicit(&channel->sleeping[1],0,memory_order_seq_cst);
}
static void completion_queue_contract(void) {
    struct md_cooperative_channel *channel=channel_new();
    channel->completion_queue=1; channel->shared_files=6;
    atomic_store(&channel->completion_read,UINT_MAX-31);
    atomic_store(&channel->completion_write,UINT_MAX-31);
    int ready[2]; assert(!pipe2(ready,O_CLOEXEC));
    fflush(NULL); pid_t child=fork(); assert(child>=0);
    if (!child) {
        assert(!close(ready[0]));
        struct md_cooperative_client client; md_cooperative_client_init(&client,channel,-1);
        struct md_cooperative_request q=packet(SYS_close,NULL,NULL,(unsigned)-1,0);
        for (unsigned i=0;i<65;++i) {
            checked(invoke_channel,&client,&q,-EBADF);
            if (i==63) assert(write(ready[1],"r",1)==1);
        }
        _exit(0);
    }
    assert(!close(ready[1]));
    struct pollfd event={.fd=ready[0],.events=POLLIN};
    /* EVENT_WAIT: producer confirms exactly 64 queued records. */
    assert(poll(&event,1,5000)==1);
    char value; assert(read(ready[0],&value,1)==1 && value=='r'); assert(!close(ready[0]));
    for (;;) {
        unsigned event=atomic_load_explicit(&channel->event[1],memory_order_acquire);
        if (atomic_load_explicit(&channel->completion_waiting,memory_order_acquire)) break;
        completion_event_wait(channel,event);
    }
    assert(atomic_load(&channel->completion_write)-atomic_load(&channel->completion_read)==64);
    for (unsigned i=0;i<65;) {
        unsigned event=atomic_load_explicit(&channel->event[1],memory_order_acquire);
        struct md_cooperative_completion completion;
        if (!md_cooperative_completion_peek(channel,&completion)) { completion_event_wait(channel,event); continue; }
        assert(completion.kind==MD_COOPERATIVE_CLOSED_FD && completion.fd==-1 && completion.error==-EBADF);
        md_cooperative_completion_consume(channel); ++i;
    }
    int status; assert(waitpid(child,&status,0)==child && status==0);
    assert(atomic_load(&channel->completion_read)==atomic_load(&channel->completion_write));
    assert(!munmap(channel,sizeof(*channel)));
    puts("PASS cooperative completion queue: deterministic capacity, wakeup and unsigned wraparound");
}
static void endpoint_wake_contract(void) {
    for (unsigned round=0;round<16;++round) {
        struct md_cooperative_channel *channel=channel_new(); channel->selective_wake=1;
        atomic_store(&channel->state,MD_COOPERATIVE_RUNNING);
        int ready[2]; assert(!pipe2(ready,O_CLOEXEC));
        pid_t children[2]; fflush(NULL);
        for (unsigned side=0;side<2;++side) {
            children[side]=fork(); assert(children[side]>=0);
            if (!children[side]) {
                assert(!close(ready[0]));
                atomic_store_explicit(&channel->sleeping[side],1,memory_order_seq_cst);
                char value=(char)side; assert(write(ready[1],&value,1)==1);
                struct timespec timeout={5,0};
                /* EVENT_WAIT: endpoint-specific event advances; timeout fails. */
                while (!atomic_load_explicit(&channel->event[side],memory_order_acquire)) {
                    int result=(int)syscall(SYS_futex,&channel->event[side],FUTEX_WAIT,0,&timeout,NULL,0);
                    assert(!result || errno==EAGAIN || errno==EINTR);
                }
                atomic_store_explicit(&channel->sleeping[side],0,memory_order_seq_cst);
                _exit(0);
            }
        }
        assert(!close(ready[1]));
        char values[2];
        for (unsigned i=0;i<2;++i) assert(read(ready[0],values+i,1)==1);
        assert(values[0]!=values[1] && !close(ready[0]));
        struct md_cooperative_response out={.outcome=MD_COOPERATIVE_COMPLETED,.fd=-1};
        int published=0; assert(!md_cooperative_reply(channel,&out,-1,&published) && published);
        int status; assert(waitpid(children[0],&status,0)==children[0] && status==0);
        assert(!atomic_load(&channel->event[1]));
        md_cooperative_close(channel);
        assert(waitpid(children[1],&status,0)==children[1] && status==0);
        assert(!munmap(channel,sizeof(*channel)));
    }
    puts("PASS cooperative notifications: two parked endpoints, reply wakes only guest, shutdown wakes owner");
}
struct shared_client {
    struct md_cooperative_channel *channel;
    pid_t parent;
    unsigned count;
    int kind, ack, lost, prepared;
    const char *name, *private_store;
    struct md_cooperative_channel *close_channel;
};
static void assert_private_store(const char *store) {
    if (!store) return;
    DIR *directory=opendir("/proc/self/fd"); assert(directory);
    struct dirent *entry;
    while ((entry=readdir(directory))) {
        if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        char target[PATH_MAX];
        ssize_t size=readlinkat(dirfd(directory),entry->d_name,target,sizeof(target)-1);
        assert(size>=0); target[size]=0;
        assert(!strstr(target,store));
    }
    assert(!closedir(directory));
}
static void deny_guest_syscall(unsigned number) {
    struct sock_filter filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,number,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program={.len=sizeof(filter)/sizeof(filter[0]),.filter=filter};
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
    assert(!syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program));
    errno=0; assert(syscall(number,-1,NULL,0)==-1 && errno==EPERM);
}
static int shared_client_run(void *data) {
    struct shared_client *args=data;
    assert(!prctl(PR_SET_PDEATHSIG,SIGKILL));
    if (getppid()!=args->parent) _exit(99);
    struct md_cooperative_client client;
    md_cooperative_client_init(&client,args->channel,-1);
    struct md_cooperative_client closer;
    if (args->close_channel) {
        md_cooperative_client_init(&closer,args->close_channel,-1); client.closer=&closer;
    }
    if (args->private_store) {
        assert_private_store(args->private_store);
        deny_guest_syscall(SYS_recvmsg);
    }
    if (args->lost) {
        if (args->lost==4) {
            assert(args->channel->prepared_open);
            deny_guest_syscall(SYS_openat);
        }
        struct md_cooperative_request q=packet(SYS_openat,args->prepared ? "/bench/marker" : "/bench/shared-lost",NULL,
            args->prepared ? O_RDONLY|O_CLOEXEC : O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,args->prepared ? 0 : 0600);
        if (args->lost==2) {
            q.sequence=1; assert(!md_cooperative_post(args->channel,&q));
            /* EVENT_WAIT: owner kills this client after FD publication but
             * before receipt consumption. The process alarm bounds failure. */
            for (;;) pause();
        }
        struct md_cooperative_response out=md_cooperative_call(&client,&q);
        if (args->lost==4) {
            assert(out.outcome==MD_COOPERATIVE_COMPLETED && out.error==-EPERM && out.fd==-1);
            assert(!md_cooperative_sync(&client));
            md_cooperative_close(args->channel);
        } else if (args->lost==3 || args->lost==5 || args->lost==6) {
            assert(out.outcome==MD_COOPERATIVE_COMPLETED && !out.error && out.fd>=0);
            assert(fcntl(out.fd,F_GETFD)&FD_CLOEXEC);
            if (args->channel->prepared_open) assert(!md_cooperative_sync(&client));
            if (args->lost==5 || args->lost==6) {
                assert(args->channel->completion_queue);
                if (args->lost==5) deny_guest_syscall(SYS_close);
                q=packet(SYS_close,NULL,NULL,(unsigned)out.fd,0);
                checked(invoke_channel,&client,&q,args->lost==5 ? -EPERM : 0);
            }
            /* Exit with a received application FD still open. */
            md_cooperative_close(args->channel);
        } else assert(out.outcome==MD_COOPERATIVE_UNKNOWN && out.error==-ESHUTDOWN && out.fd==-1);
        _exit(0);
    }
    signal_ack=args->ack;
    struct sigaction action={.sa_handler=interrupt}; sigemptyset(&action.sa_mask);
    assert(!sigaction(SIGUSR1,&action,NULL));
    channel_checks(&client);
    if (args->prepared) {
        struct md_cooperative_request q=packet(SYS_openat,"/bench/plan-source",NULL,O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);
        int fd=checked(invoke_channel,&client,&q,0).fd;
        assert(write(fd,"old",3)==3); close_result(invoke_channel,&client,fd);
        q=packet(SYS_openat,"/bench/plan-source",NULL,O_RDONLY|O_CLOEXEC,0);
        fd=checked(invoke_channel,&client,&q,0).fd;
        char bytes[3]; assert(read(fd,bytes,3)==3 && !memcmp(bytes,"old",3));
        assert(!(fcntl(fd,F_GETFL)&O_PATH)); close_result(invoke_channel,&client,fd);
        fd=checked(invoke_channel,&client,&q,0).fd;
        assert(read(fd,bytes,3)==3 && !memcmp(bytes,"new",3)); close_result(invoke_channel,&client,fd);
        q=packet(SYS_unlinkat,"/bench/plan-source",NULL,0,0);
        checked(invoke_channel,&client,&q,0);
    }
    if (args->close_channel) {
        int files[192];
        struct md_cooperative_request q=packet(SYS_openat,"/bench/marker",NULL,O_RDONLY|O_CLOEXEC,0);
        for (unsigned i=0;i<192;++i) files[i]=checked(invoke_channel,&client,&q,0).fd;
        for (unsigned i=0;i<192;++i) close_result(invoke_channel,&client,files[i]);
        q=packet(SYS_close,NULL,NULL,(unsigned)files[191],0);
        checked(invoke_channel,&client,&q,-EBADF);
    }
    workload(args->name ? args->name : args->channel->shared_files==4 ? "cooperative-fd-executor-parked"
        : args->channel->shared_files==3 ? "cooperative-fd-executor"
        : args->channel->shared_files==2 ? "cooperative-shared-tracked" : "cooperative-shared-files",
        "/bench",args->count,args->kind,invoke_channel,&client);
    if (args->channel->completion_queue) assert(!md_cooperative_sync(&client));
    assert_private_store(args->private_store);
    md_cooperative_close(args->channel);
    _exit(0);
}
static void run_shared_files(const char *store,unsigned count,int kind,int lost,int tracked) {
    struct md_cooperative_channel *channel=channel_new();
    channel->shared_files=channel->selective_wake=channel->adaptive_spin=1;
    channel->shared_files+=!!tracked;
    const char *budget=getenv("MD_LAB_SPIN_NS");
    channel->spin_ns=budget ? (unsigned)strtoul(budget,NULL,10) : 25000;
    assert(channel->spin_ns<=100000);
    unsigned initial=fd_count();
    int ack[2]; assert(!pipe2(ack,O_CLOEXEC));
    size_t stack_size=1024*1024;
    void *stack=mmap(NULL,stack_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(stack!=MAP_FAILED);
    struct shared_client args={.channel=channel,.parent=getpid(),.count=count,.kind=kind,.ack=ack[1],.lost=lost};
    fflush(NULL);
    /* Separate address spaces and allocators. Only the kernel file table is
     * shared. This exposes infrastructure slots, so remains a lab experiment. */
    pid_t child=clone(shared_client_run,(char *)stack+stack_size,CLONE_FILES|SIGCHLD,&args);
    assert(child>=0);
    struct owner owner; owner_open(&owner,store,child);
    owner.tracked_files=tracked;
    if (tracked) { owner.custody=md_fd_loan_new(owner.resources.files); assert(owner.custody); }
    struct rusage before,after; assert(!getrusage(RUSAGE_SELF,&before));
    for (;;) {
        struct md_cooperative_request q;
        int ready=md_cooperative_receive(channel,&q,release_read,&owner); assert(ready>=0);
        if (!ready) break;
        struct md_cooperative_response out={.sequence=q.sequence,.outcome=MD_COOPERATIVE_DECLINED,.error=-ESTALE,.fd=-1};
        if (q.sequence==owner.sequence+1) { owner.sequence=q.sequence; out=execute(&owner,&q); }
        if (lost==1) {
            assert(out.outcome==MD_COOPERATIVE_COMPLETED && !out.error && out.fd>=0);
            /* No receipt was published: the owner still owns this slot. */
            close_result(invoke_engine,&owner,out.fd); md_cooperative_close(channel); break;
        }
        if (!lost && q.sequence==1) {
            assert(!kill(child,SIGUSR1));
            struct pollfd event={.fd=ack[0],.events=POLLIN};
            /* EVENT_WAIT: signal reentry acknowledged; timeout fails. */
            assert(poll(&event,1,5000)==1 && (event.revents&POLLIN));
            char value; assert(read(ack[0],&value,1)==1 && value==1);
        }
        int published=0;
        int reply=md_cooperative_reply(channel,&out,-1,&published);
        if (!published && out.fd>=0) close_result(invoke_engine,&owner,out.fd);
        assert(!reply);
        if (lost==2) { assert(!kill(child,SIGKILL)); break; }
    }
    assert(!getrusage(RUSAGE_SELF,&after));
    int status; assert(waitpid(child,&status,0)==child);
    assert(lost==2 ? WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL : status==0);
    printf("COOPERATIVE_WORKER {\"invocationCpuSeconds\":%.9f,\"completed\":%llu,\"sharedFiles\":true,\"trackedFiles\":%s}\n",
        cpu(&after)-cpu(&before),(unsigned long long)owner.completed,tracked ? "true" : "false");
    owner_close(&owner);
    assert(owner.retired_files==(lost>=2 ? 1U : 0U));
    if (lost) {
        owner_open(&owner,store,getpid());
        struct md_cooperative_request q=packet(SYS_openat,"/bench/shared-lost",NULL,
            O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);
        checked(invoke_engine,&owner,&q,-EEXIST);
        q=packet(SYS_unlinkat,"/bench/shared-lost",NULL,0,0);
        checked(invoke_engine,&owner,&q,0);
        owner_close(&owner);
    }
    assert(!close(ack[0]) && !close(ack[1]));
    assert(fd_count()==initial);
    assert(!munmap(stack,stack_size) && !munmap(channel,sizeof(*channel)));
}
static void run_fd_executor(struct md_cooperative_channel *upstream,int delivery,
        int actor_pipe,int ack,unsigned count,int kind,int park) {
    /* Cost decomposition only: the engine's SQLite, root and backing FDs stay
     * in its private table. This relay owns delivery slots, not mount origins. */
    struct md_cooperative_client remote;
    md_cooperative_client_init(&remote,upstream,delivery);
    struct md_cooperative_channel *channel=channel_new();
    channel->shared_files=3+!!park; channel->selective_wake=channel->adaptive_spin=1;
    channel->spin_ns=upstream->spin_ns;
    size_t stack_size=1024*1024;
    void *stack=mmap(NULL,stack_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(stack!=MAP_FAILED);
    struct shared_client args={.channel=channel,.parent=getpid(),.count=count,.kind=kind,.ack=ack};
    pid_t actor=clone(shared_client_run,(char *)stack+stack_size,CLONE_FILES|SIGCHLD,&args);
    assert(actor>=0 && write(actor_pipe,&actor,sizeof(actor))==sizeof(actor));
    assert(!close(actor_pipe));
    unsigned initial=fd_count(),used=0,capacity=0;
    int *owned=NULL;
    uint64_t sequence=0,completed=0;
    struct rusage before,after; assert(!getrusage(RUSAGE_SELF,&before));
    for (;;) {
        struct md_cooperative_request q;
        int ready=md_cooperative_receive(channel,&q,NULL,NULL); assert(ready>=0);
        if (!ready) break;
        struct md_cooperative_response out={.sequence=q.sequence,.outcome=MD_COOPERATIVE_DECLINED,
            .error=-ESTALE,.fd=-1};
        if (q.sequence==sequence+1) {
            sequence=q.sequence; ++completed;
            if (q.syscall==SYS_close) {
                unsigned i=0;
                while (i<used && owned[i]!=(int)q.flags) ++i;
                out.outcome=MD_COOPERATIVE_COMPLETED; out.error=-EBADF;
                if (i<used) { assert(!close(owned[i])); owned[i]=owned[--used]; out.error=0; }
            } else {
                if (park && md_cooperative_delegate(channel)) break;
                out=md_cooperative_call(&remote,&q); out.sequence=q.sequence;
                if (out.outcome==MD_COOPERATIVE_UNKNOWN) { md_cooperative_close(channel); break; }
                if (out.fd>=0) {
                    if (used==capacity) {
                        capacity=capacity ? capacity*2 : 16;
                        owned=realloc(owned,capacity*sizeof(*owned)); assert(owned);
                    }
                    owned[used++]=out.fd;
                }
            }
        }
        int published=0;
        int error=md_cooperative_reply(channel,&out,-1,&published);
        if (error) { md_cooperative_close(channel); break; }
        assert(published);
    }
    int status; assert(waitpid(actor,&status,0)==actor && status==0);
    for (unsigned i=0;i<used;++i) assert(!close(owned[i]));
    free(owned);
    assert(fd_count()==initial && !getrusage(RUSAGE_SELF,&after));
    printf("COOPERATIVE_WORKER {\"invocationCpuSeconds\":%.9f,\"completed\":%llu,\"fdExecutor\":true}\n",
        cpu(&after)-cpu(&before),(unsigned long long)completed);
    md_cooperative_close(upstream);
    assert(!munmap(stack,stack_size) && !munmap(channel,sizeof(*channel)));
}
static void sidecar_loop(struct md_cooperative_channel *channel,int delivery,
        int actor_pipe,struct shared_client args) {
    size_t stack_size=1024*1024;
    void *stack=mmap(NULL,stack_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(stack!=MAP_FAILED);
    unsigned initial=fd_count(),used=0,capacity=0;
    int *owned=NULL,joined=0;
    args.parent=getpid();
    pid_t actor=clone(shared_client_run,(char *)stack+stack_size,CLONE_FILES|SIGCHLD,&args);
    assert(actor>=0 && write(actor_pipe,&actor,sizeof(actor))==sizeof(actor));
    assert(!close(actor_pipe)); --initial;
    uint64_t sequence=0,completed=0;
    struct rusage before,after; assert(!getrusage(RUSAGE_SELF,&before));
    for (;;) {
        struct md_cooperative_request q;
        int ready=md_cooperative_receive(channel,&q,NULL,NULL); assert(ready>=0);
        if (!ready) break;
        struct md_cooperative_response out={.sequence=q.sequence,.outcome=MD_COOPERATIVE_COMPLETED,.fd=-1};
        assert(q.sequence==++sequence); ++completed;
        if (q.syscall==SYS_recvmsg) {
            assert(!joined);
            uint64_t received=0; unsigned count=0; int fd=-1;
            assert(md_fs_receive_fds(delivery,&received,sizeof(received),&fd,1,&count)==sizeof(received));
            assert(received==q.sequence && count==1 && fd>=0);
            if (used==capacity) {
                capacity=capacity ? capacity*2 : 16;
                owned=realloc(owned,capacity*sizeof(*owned)); assert(owned);
            }
            owned[used++]=fd; out.fd=fd;
        } else if (q.syscall==SYS_close) {
            unsigned i=0;
            while (i<used && owned[i]!=(int)q.flags) ++i;
            out.error=-EBADF;
            if (i<used) { assert(!close(owned[i])); owned[i]=owned[--used]; out.error=0; }
        } else {
            assert(q.syscall==SYS_wait4 && !joined);
            /* EVENT_WAIT: the exact actor exits; the fixture alarm bounds failure. */
            int status; assert(waitpid(actor,&status,0)==actor);
            assert(args.lost==2 ? WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL : status==0);
            joined=1;
        }
        int published=0;
        assert(!md_cooperative_reply(channel,&out,-1,&published) && published);
    }
    assert(joined && !used && fd_count()==initial && !getrusage(RUSAGE_SELF,&after));
    printf("COOPERATIVE_WORKER {\"invocationCpuSeconds\":%.9f,\"completed\":%llu,\"fdSidecar\":true}\n",
        cpu(&after)-cpu(&before),(unsigned long long)completed);
    free(owned); assert(!munmap(stack,stack_size));
}
static void run_sidecar(const char *store,unsigned count,int kind,int lost,int park) {
    unsigned initial=fd_count();
    struct md_cooperative_channel *guest=channel_new(),*executor=channel_new();
    guest->shared_files=5; executor->shared_files=1;
    guest->selective_wake=executor->selective_wake=1;
    guest->adaptive_spin=executor->adaptive_spin=1;
    const char *budget=getenv("MD_LAB_SPIN_NS");
    guest->spin_ns=executor->spin_ns=budget ? (unsigned)strtoul(budget,NULL,10) : 25000;
    assert(guest->spin_ns<=100000);
    int delivery[2],ack[2],actor_pipe[2];
    assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,delivery));
    assert(!pipe2(ack,O_CLOEXEC) && !pipe2(actor_pipe,O_CLOEXEC));
    fflush(NULL);
    pid_t parent=getpid(),child=fork(); assert(child>=0);
    if (!child) {
        assert(!prctl(PR_SET_PDEATHSIG,SIGKILL));
        if (getppid()!=parent) _exit(99);
        assert(!close(delivery[0]) && !close(ack[0]) && !close(actor_pipe[0]));
        /* Fork before opening the store: no SQLite/backing FD enters this table.
         * Only this sidecar shares the client's file table, not its address space. */
        struct shared_client args={.channel=guest,.count=count,.kind=kind,.ack=ack[1],.lost=lost,
            .private_store=store,.name=park ? "cooperative-fd-sidecar-parked" : "cooperative-fd-sidecar"};
        sidecar_loop(executor,delivery[1],actor_pipe[1],args);
        assert(!close(delivery[1]) && !close(ack[1]));
        fflush(stdout); _exit(0);
    }
    assert(!close(delivery[1]) && !close(ack[1]) && !close(actor_pipe[1]));
    struct pollfd event={.fd=actor_pipe[0],.events=POLLIN};
    /* EVENT_WAIT: the sidecar publishes its client identity; timeout fails. */
    assert(poll(&event,1,5000)==1 && (event.revents&POLLIN));
    pid_t actor; assert(read(actor_pipe[0],&actor,sizeof(actor))==sizeof(actor) && actor>0);
    assert(!close(actor_pipe[0]));
    struct md_cooperative_client remote;
    md_cooperative_client_init(&remote,executor,delivery[0]);
    struct owner owner; owner_open(&owner,store,actor);
    owner.fd_executor=&remote; owner.tracked_files=1;
    owner.custody=md_fd_loan_new(owner.resources.files); assert(owner.custody);
    struct rusage before,after; assert(!getrusage(RUSAGE_SELF,&before));
    for (;;) {
        struct md_cooperative_request q;
        int ready=md_cooperative_receive(guest,&q,release_read,&owner); assert(ready>=0);
        if (!ready) break;
        struct md_cooperative_response out={.sequence=q.sequence,.outcome=MD_COOPERATIVE_DECLINED,.error=-ESTALE,.fd=-1};
        if (q.sequence==owner.sequence+1) {
            owner.sequence=q.sequence;
            if (park && (q.syscall==SYS_openat || q.syscall==SYS_close)) assert(!md_cooperative_delegate(guest));
            out=execute(&owner,&q);
        }
        if (lost==1) {
            assert(out.outcome==MD_COOPERATIVE_COMPLETED && !out.error && out.fd>=0);
            close_result(invoke_engine,&owner,out.fd); md_cooperative_close(guest); break;
        }
        if (!lost && q.sequence==1) {
            assert(!kill(actor,SIGUSR1));
            event=(struct pollfd){.fd=ack[0],.events=POLLIN};
            /* EVENT_WAIT: guest signal reentry acknowledges the outstanding call. */
            assert(poll(&event,1,5000)==1 && (event.revents&POLLIN));
            char value; assert(read(ack[0],&value,1)==1 && value==1);
        }
        int published=0;
        assert(!md_cooperative_reply(guest,&out,-1,&published) && published);
        if (lost==2) { assert(!kill(actor,SIGKILL)); break; }
    }
    assert(!getrusage(RUSAGE_SELF,&after));
    struct md_cooperative_request join=packet(SYS_wait4,NULL,NULL,0,0);
    checked(invoke_channel,&remote,&join,0);
    printf("COOPERATIVE_WORKER {\"invocationCpuSeconds\":%.9f,\"completed\":%llu,\"privateEngine\":true,\"trackedFiles\":true}\n",
        cpu(&after)-cpu(&before),(unsigned long long)owner.completed);
    owner_close(&owner);
    assert(owner.retired_files==(lost>=2 ? 1U : 0U));
    md_cooperative_close(executor);
    int status; assert(waitpid(child,&status,0)==child && status==0);
    if (lost) {
        owner_open(&owner,store,getpid());
        struct md_cooperative_request q=packet(SYS_openat,"/bench/shared-lost",NULL,O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);
        checked(invoke_engine,&owner,&q,-EEXIST);
        q=packet(SYS_unlinkat,"/bench/shared-lost",NULL,0,0);
        checked(invoke_engine,&owner,&q,0); owner_close(&owner);
    }
    assert(!close(delivery[0]) && !close(ack[0]));
    assert(!munmap(guest,sizeof(*guest)) && !munmap(executor,sizeof(*executor)));
    assert(fd_count()==initial);
}
static void pipeline_retire(void *data) {
    struct pipeline *p=data;
    if (p->direct_pending && atomic_load_explicit(&p->guest->state,memory_order_acquire)==MD_COOPERATIVE_RECEIPT) {
        struct md_cooperative_response out=p->guest->response;
        assert(out.sequence==p->response.sequence && out.outcome==MD_COOPERATIVE_COMPLETED);
        assert(out.error<=0 && (out.error ? out.fd==-1 : out.fd>=0));
        md_fd_origins_finish(&p->update,out.fd);
        assert(!md_fd_order_complete(&p->turn));
        md_fs_anchor_release(p->held_origin); p->held_origin=NULL;
        if (!p->source_borrowed) assert(!close(p->source));
        p->source=-1;
        p->active=p->direct_pending=0;
        assert(!md_cooperative_receipt_complete(p->guest));
    }
    if (p->active && !p->direct_pending && atomic_load_explicit(&p->jobs->state,memory_order_acquire)==MD_COOPERATIVE_IDLE) {
        /* Only the engine may destroy anchors holding its private descriptors. */
        md_fs_anchor_release(p->held_origin); p->held_origin=NULL; p->active=0;
        if (p->source>=0) {
            if (!p->source_borrowed) assert(!close(p->source));
            p->source=-1;
        }
    }
    struct md_cooperative_completion completion;
    while (p->guest->completion_queue && md_cooperative_completion_peek(p->guest,&completion)) {
        if (completion.kind==MD_COOPERATIVE_OPENED) {
            assert(p->active && p->direct_pending && completion.sequence==p->response.sequence);
            assert(completion.error<=0 && (completion.error ? completion.fd==-1 : completion.fd>=0));
            md_fd_origins_finish(&p->update,completion.fd);
            assert(!md_fd_order_complete(&p->turn));
            md_fs_anchor_release(p->held_origin); p->held_origin=NULL;
            if (!p->source_borrowed) assert(!close(p->source));
            p->source=-1; p->active=p->direct_pending=0;
        } else {
            assert(completion.kind==MD_COOPERATIVE_CLOSED_FD && !p->active);
            struct md_fd_order turn={0};
            assert(md_fd_order_begin(p->owner->resources.files,&turn,NULL)==1 && !md_fd_order_start(&turn));
            unsigned long args[6]={(unsigned long)completion.fd};
            struct md_fd_mutation mutation;
            assert(!md_fd_mutation_prepare(turn.table,SYS_close,args,&mutation));
            assert(!md_fd_mutation_finish(&mutation,turn.table,completion.error));
            assert(!md_fd_order_complete(&turn)); ++p->queued_closes;
        }
        md_cooperative_completion_consume(p->guest);
    }
    unsigned read=atomic_load_explicit(&p->retired_read,memory_order_relaxed);
    while (read!=atomic_load_explicit(&p->retired_write,memory_order_acquire)) {
        md_fs_anchor_release(p->retired[read%64]);
        atomic_store_explicit(&p->retired_read,++read,memory_order_seq_cst);
        if (atomic_load_explicit(&p->retired_waiting,memory_order_seq_cst))
            assert(syscall(SYS_futex,&p->retired_read,FUTEX_WAKE,1,NULL,NULL,0)>=0);
    }
}
static void pipeline_before_wait(void *data) {
    struct pipeline *p=data;
    pipeline_retire(p);
    release_read(p->owner);
    assert(!p->owner->window.owner && !p->owner->fs.store->locked);
}
static void pipeline_retire_origin(struct pipeline *p,struct md_fs_anchor *origin) {
    if (!origin) return;
    unsigned write=atomic_load_explicit(&p->retired_write,memory_order_relaxed);
    for (;;) {
        unsigned read=atomic_load_explicit(&p->retired_read,memory_order_acquire);
        if (write-read<64) break;
        atomic_store_explicit(&p->retired_waiting,1,memory_order_seq_cst);
        md_cooperative_notify_owner(p->guest);
        struct timespec timeout={5,0};
        /* EVENT_WAIT: engine drains bounded retirement queue; timeout fails. */
        if (atomic_load_explicit(&p->retired_read,memory_order_seq_cst)==read) {
            int result=(int)syscall(SYS_futex,&p->retired_read,FUTEX_WAIT,read,&timeout,NULL,0);
            assert(!result || errno==EAGAIN || errno==EINTR);
        }
        atomic_store_explicit(&p->retired_waiting,0,memory_order_seq_cst);
    }
    p->retired[write%64]=origin;
    atomic_store_explicit(&p->retired_write,write+1,memory_order_release);
    /* The next engine request drains these references. Only a full queue
     * wakes an idle engine and waits for private-anchor retirement capacity. */
}
static struct md_cooperative_response pipeline_local_close(struct pipeline *p,const struct md_cooperative_request *q) {
    struct md_cooperative_response out={.sequence=q->sequence,.outcome=MD_COOPERATIVE_COMPLETED,.fd=-1};
    struct md_fs_context context;
    out.error=md_fs_context_begin(&p->owner->fs,p->actor,0,&context);
    if (out.error) return out;
    struct md_fd_order turn={0};
    assert(md_fd_order_begin(context.task.files,&turn,NULL)==1 && !md_fd_order_start(&turn));
    struct md_fs_anchor *held=md_fd_origins_get(context.task.files,(int)q->flags,NULL);
    unsigned long args[6]={q->flags};
    struct md_fd_mutation change;
    assert(!md_fd_mutation_prepare(context.task.files,SYS_close,args,&change));
    out.error=close((int)q->flags) ? -errno : 0;
    assert(!md_fd_mutation_finish(&change,context.task.files,out.error));
    assert(!md_fd_order_complete(&turn)); md_fs_context_end(&context);
    pipeline_retire_origin(p,held);
    return out;
}
static int pipeline_close(struct pipeline *p,int fd) {
    assert(!p->active);
    struct md_cooperative_request q=packet(SYS_close,NULL,NULL,(unsigned)fd,1);
    assert(!md_cooperative_post(p->jobs,&q));
    /* EVENT_WAIT: cold teardown close acknowledgement; alarm bounds failure. */
    int error; assert(read(p->ack[0],&error,sizeof(error))==sizeof(error));
    return error;
}
static void pipeline_barrier(struct pipeline *p) {
    /* EVENT_WAIT: helper has a private table and published the exact actor PID. */
    int error=pthread_barrier_wait(&p->startup);
    assert(!error || error==PTHREAD_BARRIER_SERIAL_THREAD);
}
static void *pipeline_worker(void *data) {
    struct pipeline *p=data;
    /* Shared runtime memory, separate kernel file table. Guest address space
     * remains separate. The engine stays the thread-group leader so existing
     * /proc/self/fd paths still refer to the engine's table. */
    assert(!unshare(CLONE_FILES));
    assert(!close(p->delivery[0]) && !close(p->ack[0]) && !close(p->signal_ack[0]));
    unsigned initial=fd_count();
    size_t stack_size=1024*1024;
    void *stack=mmap(NULL,stack_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(stack!=MAP_FAILED);
    struct shared_client args={.channel=p->guest,.parent=getpid(),.count=p->count,.kind=p->kind,
        .ack=p->signal_ack[1],.lost=p->lost,.prepared=p->reopen>=4,
        .name=p->reopen==8 ? "cooperative-guest-window" : p->reopen==7 ? "cooperative-guest-queued" : p->reopen==6 ? "cooperative-guest-pin"
            : p->reopen==5 ? "cooperative-guest-plan" : p->reopen==4 ? "cooperative-fd-plan"
            : p->reopen==3 ? "cooperative-fd-local-close" : p->reopen==2 ? "cooperative-fd-pidfd"
            : p->reopen ? "cooperative-fd-reopen" : "cooperative-fd-pipeline",
        .private_store=p->store,.close_channel=p->reopen>=3 ? p->jobs : NULL};
    p->actor=clone(shared_client_run,(char *)stack+stack_size,CLONE_FILES|SIGCHLD,&args);
    assert(p->actor>=0); pipeline_barrier(p);
    struct rusage before,after; assert(!getrusage(RUSAGE_THREAD,&before));
    uint64_t completed=0,close_sequence=0,prepared_opens=0;
    for (;;) {
        struct md_cooperative_request q;
        int ready=md_cooperative_receive(p->jobs,&q,NULL,NULL); assert(ready>=0);
        if (!ready) break;
        ++completed;
        if (!q.mode && p->reopen>=3) {
            assert(q.syscall==SYS_close && q.sequence==++close_sequence);
            struct md_cooperative_response out=pipeline_local_close(p,&q);
            int published=0;
            assert(!md_cooperative_reply(p->jobs,&out,-1,&published) && published);
            continue;
        }
        if (q.mode==2) {
            assert(q.syscall==SYS_pidfd_getfd && p->reopen>=2);
            int fd=(int)syscall(SYS_pidfd_getfd,p->engine_pidfd,q.flags,0);
            assert(fd>=0 && (fcntl(fd,F_GETFD)&FD_CLOEXEC));
            char bytes[8]; size_t size=strlen(q.path[0]); assert(size<=sizeof(bytes));
            assert(read(fd,bytes,size)==(ssize_t)size && !memcmp(bytes,q.path[0],size));
            if (q.length[1]>1) assert(write(fd,q.path[1],q.length[1]-1)==q.length[1]-1);
            assert(!close(fd) && !md_cooperative_retire(p->jobs));
            int error=0; assert(write(p->ack[1],&error,sizeof(error))==sizeof(error));
            continue;
        }
        if (q.mode==1) {
            assert(q.syscall==SYS_close);
            int error=close((int)q.flags) ? -errno : 0;
            assert(!md_cooperative_retire(p->jobs));
            assert(write(p->ack[1],&error,sizeof(error))==sizeof(error));
            continue;
        }
        assert(p->active && q.syscall==p->operation && q.sequence==p->response.sequence);
        struct md_cooperative_response out=p->response;
        if (q.syscall==SYS_openat) {
            int fd=-1;
            if (p->prepared_open) {
                char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d",p->source);
                fd=open(path,p->open_flags); assert(fd>=0);
                struct stat st; assert(!fstat(fd,&st));
                assert(st.st_dev==p->held_origin->device && st.st_ino==p->held_origin->inode);
                ++prepared_opens;
            } else if (p->reopen>=2) {
                fd=(int)syscall(SYS_pidfd_getfd,p->engine_pidfd,p->source,0);
                if (fd<0) perror("lab same-process pidfd_getfd");
                assert(fd>=0);
            } else if (p->reopenable) {
                /* Ordinary files only: a fresh open description, not dup's
                 * shared offset. The engine pins this exact source slot until
                 * this completion. General devices/sockets still need rights. */
                char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d",p->source);
                fd=open(path,p->open_flags); assert(fd>=0);
            } else {
                unsigned count=0; uint64_t sequence=0;
                assert(md_fs_receive_fds(p->delivery[1],&sequence,sizeof(sequence),&fd,1,&count)==sizeof(sequence));
                assert(count==1 && fd>=0 && sequence==q.sequence);
            }
            struct md_fs_anchor *old=md_fd_origins_get(p->turn.table,fd,NULL);
            assert(!old);
            md_fd_origins_finish(&p->update,fd); out.fd=fd;
        } else {
            assert(q.syscall==SYS_close);
            out.error=close(p->target) ? -errno : 0;
            assert(!md_fd_mutation_finish(&p->mutation,p->turn.table,out.error));
        }
        assert(!md_fd_order_complete(&p->turn));
        /* Save everything needed before retiring: a subsequent guest request
         * may let the engine reuse the job immediately after publication. */
        struct md_cooperative_channel *guest=p->guest;
        int lost=p->lost,ack=p->ack[1]; pid_t actor=p->actor;
        assert(!md_cooperative_retire(p->jobs));
        if (lost!=1) {
            int published=0;
            assert(!md_cooperative_reply(guest,&out,-1,&published) && published);
        }
        if (lost==2) assert(!kill(actor,SIGKILL));
        if (lost==1 || lost==2) {
            int error=0; assert(write(ack,&error,sizeof(error))==sizeof(error));
        }
    }
    assert(fd_count()==initial && !getrusage(RUSAGE_THREAD,&after));
    printf("COOPERATIVE_WORKER {\"invocationThreadCpuSeconds\":%.9f,\"completed\":%llu,\"pipelineCompletion\":true,\"preparedOpens\":%llu}\n",
        cpu(&after)-cpu(&before),(unsigned long long)completed,(unsigned long long)prepared_opens);
    assert(!close(p->delivery[1]) && !close(p->ack[1]) && !close(p->signal_ack[1]));
    if (p->engine_pidfd>=0) assert(!close(p->engine_pidfd));
    assert(!munmap(stack,stack_size)); return NULL;
}
static void pipeline_pidfd_contract(struct pipeline *p) {
    if (p->reopen<2) return;
    int file=(int)syscall(SYS_memfd_create,"pipeline-ofd",1U); assert(file>=0);
    assert(write(file,"abcdef",6)==6 && lseek(file,1,SEEK_SET)==1);
    int stream[2],pipe[2];
    assert(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,stream));
    assert(!pipe2(pipe,O_CLOEXEC));
    assert(write(stream[1],"s",1)==1 && write(pipe[1],"p",1)==1);
    const int source[]={file,stream[0],pipe[0]};
    const char *expected[]={"bc","s","p"};
    for (unsigned i=0;i<3;++i) {
        struct md_cooperative_request q=packet(SYS_pidfd_getfd,expected[i],i==1 ? "r" : NULL,(unsigned)source[i],2);
        assert(!md_cooperative_post(p->jobs,&q));
        /* EVENT_WAIT: helper consumed the exact duplicate; alarm bounds failure. */
        int error; assert(read(p->ack[0],&error,sizeof(error))==sizeof(error) && !error);
    }
    assert(lseek(file,0,SEEK_CUR)==3);
    char value; assert(read(stream[1],&value,1)==1 && value=='r');
    assert(!close(file) && !close(stream[0]) && !close(stream[1]) && !close(pipe[0]) && !close(pipe[1]));
}
static void run_pipeline(const char *store,unsigned count,int kind,int lost,int reopen) {
    unsigned initial=fd_count();
    struct pipeline p={.guest=channel_new(),.jobs=channel_new(),.store=store,.count=count,.kind=kind,
        .lost=lost,.reopen=reopen,.source=-1};
    atomic_init(&p.retired_read,0); atomic_init(&p.retired_write,0); atomic_init(&p.retired_waiting,0);
    p.jobs->shared_files=1;
    p.guest->shared_files=6; p.guest->park_owner_handoff=1;
    p.guest->prepared_open=reopen>=5;
    p.guest->completion_queue=reopen>=7;
    p.guest->selective_wake=p.jobs->selective_wake=1;
    p.guest->adaptive_spin=p.jobs->adaptive_spin=1;
    const char *budget=getenv("MD_LAB_SPIN_NS");
    p.guest->spin_ns=p.jobs->spin_ns=budget ? (unsigned)strtoul(budget,NULL,10) : 25000;
    const char *helper_budget=getenv("MD_LAB_HELPER_SPIN_NS");
    if (helper_budget) {
        p.jobs->receive_spin_ns=(unsigned)strtoul(helper_budget,NULL,10);
        p.jobs->receive_spin_override=1;
    }
    assert(p.jobs->receive_spin_ns<=100000);
    assert(p.guest->spin_ns<=100000);
    assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,p.delivery));
    assert(!pipe2(p.ack,O_CLOEXEC) && !pipe2(p.signal_ack,O_CLOEXEC));
    p.engine_pidfd=reopen>=2 ? (int)syscall(SYS_pidfd_open,getpid(),0) : -1;
    assert(reopen<2 || p.engine_pidfd>=0);
    assert(!pthread_barrier_init(&p.startup,NULL,2));
    pthread_t thread; fflush(NULL);
    assert(!pthread_create(&thread,NULL,pipeline_worker,&p)); pipeline_barrier(&p);
    assert(!close(p.delivery[1]) && !close(p.ack[1]) && !close(p.signal_ack[1]));
    struct owner owner; owner_open(&owner,store,p.actor);
    owner.pipeline=&p; p.owner=&owner; owner.tracked_files=1;
    owner.read_window=reopen>=8;
    owner.custody=md_fd_loan_new(owner.resources.files); assert(owner.custody);
    struct rusage before,after; assert(!getrusage(RUSAGE_THREAD,&before));
    for (;;) {
        struct md_cooperative_request q;
        int ready=md_cooperative_receive(p.guest,&q,pipeline_before_wait,&p); assert(ready>=0);
        pipeline_retire(&p); assert(!p.active);
        if (!ready) break;
        /* The guest has finished its initial FD inventory and is now waiting.
         * Probe copies must not race that deliberately quiescent observation. */
        if (!owner.sequence) pipeline_pidfd_contract(&p);
        struct md_cooperative_response out={.sequence=q.sequence,.outcome=MD_COOPERATIVE_DECLINED,.error=-ESTALE,.fd=-1};
        if (q.sequence==owner.sequence+1) { owner.sequence=q.sequence; out=execute(&owner,&q); }
        if (!lost && q.sequence==1) {
            assert(!kill(p.actor,SIGUSR1));
            struct pollfd event={.fd=p.signal_ack[0],.events=POLLIN};
            /* EVENT_WAIT: original guest acknowledges signal-handler reentry. */
            assert(poll(&event,1,5000)==1 && (event.revents&POLLIN));
            char value; assert(read(p.signal_ack[0],&value,1)==1 && value==1);
        }
        if (p.active) {
            p.response=out;
            if (p.prepared_open && !p.plan_raced && !strcmp(q.path[0],"/bench/plan-source")) {
                release_read(&owner);
                struct md_fs_request mutation={.actor=p.actor,.operation=MD_FS_UNLINK,.directory={-1,-1},
                    .path={"/bench/plan-source",""}};
                struct md_fs_result result;
                md_fs_execute(&owner.fs,&mutation,&result,NULL); assert(!result.error);
                md_fs_open_parameters(&mutation,O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600,0);
                md_fs_execute(&owner.fs,&mutation,&result,NULL); assert(!result.error && result.fd>=0);
                assert(write(result.fd,"new",3)==3 && !close(result.fd)); p.plan_raced=1;
            }
            if (p.prepared_open && reopen>=5) {
                p.source=out.fd;
                out.fd=-1; out.outcome=MD_COOPERATIVE_PLAN;
                out.open_plan.owner=getpid(); out.open_plan.pin=p.source; out.open_plan.flags=p.open_flags;
                out.open_plan.device=p.held_origin->device; out.open_plan.inode=p.held_origin->inode;
                if (lost!=1) {
                    int published=0;
                    assert(!md_cooperative_reply(p.guest,&out,-1,&published) && published);
                    ++p.direct_plans;
                }
                if (lost==1 || lost==2) {
                    if (lost==1) md_cooperative_close(p.guest);
                    else assert(!kill(p.actor,SIGKILL));
                    md_fd_origins_finish(&p.update,-1); assert(!md_fd_order_complete(&p.turn));
                    pipeline_retire(&p); break;
                }
                p.direct_pending=1;
                continue;
            }
            if (out.fd>=0) {
                if (p.reopenable) p.source=out.fd;
                else assert(md_fs_send_fds(p.delivery[0],&q.sequence,sizeof(q.sequence),&out.fd,1)==sizeof(q.sequence));
            }
            struct md_cooperative_request job=packet(p.operation,NULL,NULL,0,3); job.sequence=q.sequence;
            assert(!md_cooperative_post(p.jobs,&job));
            if (out.fd>=0 && !p.reopenable) assert(!close(out.fd));
            if (lost==1 || lost==2) {
                /* EVENT_WAIT: fault injection completes delivery before teardown. */
                int error; assert(read(p.ack[0],&error,sizeof(error))==sizeof(error) && !error);
                if (lost==1) md_cooperative_close(p.guest);
                pipeline_retire(&p); break;
            }
        } else {
            int published=0;
            assert(!md_cooperative_reply(p.guest,&out,-1,&published) && published);
        }
    }
    assert(!getrusage(RUSAGE_THREAD,&after));
    /* EVENT_WAIT: exact actor exit establishes exclusive FD retirement. */
    int status; assert(waitpid(p.actor,&status,0)==p.actor);
    assert(lost==2 ? WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL : status==0);
    pipeline_retire(&p); assert(!p.active);
    assert(atomic_load(&p.retired_read)==atomic_load(&p.retired_write));
    owner_close(&owner);
    assert(owner.retired_files==(lost && !(reopen>=5 && lost!=3 && lost!=5) ? 1U : 0U));
    if (lost==4) assert(p.direct_plans==1);
    if (lost==5 || lost==6) assert(p.queued_closes==1);
    assert(atomic_load(&p.guest->completion_read)==atomic_load(&p.guest->completion_write));
    md_cooperative_close(p.jobs); assert(!pthread_join(thread,NULL));
    printf("COOPERATIVE_WORKER {\"invocationThreadCpuSeconds\":%.9f,\"completed\":%llu,\"pipelineEngine\":true,\"directPlans\":%u,\"queuedCloses\":%u,\"readLeases\":%llu}\n",
        cpu(&after)-cpu(&before),(unsigned long long)owner.completed,p.direct_plans,p.queued_closes,(unsigned long long)owner.leases);
    if (lost && reopen<4) {
        owner_open(&owner,store,getpid());
        struct md_cooperative_request q=packet(SYS_openat,"/bench/shared-lost",NULL,O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);
        checked(invoke_engine,&owner,&q,-EEXIST);
        q=packet(SYS_unlinkat,"/bench/shared-lost",NULL,0,0);
        checked(invoke_engine,&owner,&q,0); owner_close(&owner);
    }
    assert(!close(p.delivery[0]) && !close(p.ack[0]) && !close(p.signal_ack[0]));
    if (p.engine_pidfd>=0) assert(!close(p.engine_pidfd));
    assert(!pthread_barrier_destroy(&p.startup));
    assert(!munmap(p.guest,sizeof(*p.guest)) && !munmap(p.jobs,sizeof(*p.jobs)));
    assert(fd_count()==initial);
}
static void run_channel(const char *store,unsigned count,int metadata,int lost_response,int bounded) {
    struct md_cooperative_channel *channel=channel_new();
    if (bounded) {
        channel->selective_wake=1;
        channel->adaptive_spin=bounded>=2;
        const char *budget=getenv("MD_LAB_SPIN_NS");
        channel->spin_ns=budget ? (unsigned)strtoul(budget,NULL,10) : 10000;
        assert(channel->spin_ns<=100000);
    }
    int ack[2]; assert(!pipe2(ack,O_CLOEXEC));
    int delivery[2]; assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,delivery));
    int actor_pipe[2]={-1,-1};
    if (bounded>=5) assert(!pipe2(actor_pipe,O_CLOEXEC));
    fflush(NULL);
    pid_t parent=getpid(),child=fork(); assert(child>=0);
    if (!child) {
        close(ack[0]); signal_ack=ack[1]; close(delivery[0]);
        assert(!prctl(PR_SET_PDEATHSIG,SIGKILL));
        if (getppid()!=parent) _exit(99);
        if (bounded>=5) {
            assert(!close(actor_pipe[0]));
            run_fd_executor(channel,delivery[1],actor_pipe[1],ack[1],count,metadata,bounded==6);
            assert(!close(delivery[1]) && !close(ack[1]));
            fflush(stdout); _exit(0);
        }
        struct md_cooperative_client client;
        md_cooperative_client_init(&client,channel,delivery[1]);
        struct sigaction action={.sa_handler=interrupt}; sigemptyset(&action.sa_mask);
        assert(!sigaction(SIGUSR1,&action,NULL));
        if (lost_response) {
            struct md_cooperative_request q=packet(SYS_openat,"/bench/lost-response",NULL,
                O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);
            struct md_cooperative_response out=md_cooperative_call(&client,&q);
            assert(out.outcome==MD_COOPERATIVE_UNKNOWN && out.error==-ESHUTDOWN && out.fd==-1);
        } else {
            channel_checks(&client);
            workload(bounded==4 ? "cooperative-leased-recheck" : bounded==3 ? "cooperative-leased" : bounded==2 ? "cooperative-adaptive" : bounded ? "cooperative-bounded" : "cooperative",
                "/bench",count,metadata,invoke_channel,&client);
            md_cooperative_close(channel);
        }
        close(delivery[1]); _exit(0);
    }
    close(ack[1]); close(delivery[1]);
    pid_t actor=child;
    if (bounded>=5) {
        assert(!close(actor_pipe[1]));
        struct pollfd event={.fd=actor_pipe[0],.events=POLLIN};
        /* EVENT_WAIT: executor publishes the actual client's identity; timeout fails. */
        assert(poll(&event,1,5000)==1 && (event.revents&POLLIN));
        assert(read(actor_pipe[0],&actor,sizeof(actor))==sizeof(actor) && actor>0);
        assert(!close(actor_pipe[0]));
    }
    unsigned descriptors=fd_count();
    struct owner owner; owner_open(&owner,store,actor);
    owner.read_window=bounded>=3 && bounded<=4 ? bounded-2 : 0;
    struct rusage before,after; assert(!getrusage(RUSAGE_SELF,&before));
    for (;;) {
        struct md_cooperative_request q;
        int ready=md_cooperative_receive(channel,&q,release_read,&owner); assert(ready>=0);
        if (!ready) break;
        struct md_cooperative_response out={.sequence=q.sequence,.outcome=MD_COOPERATIVE_DECLINED,.error=-ESTALE,.fd=-1};
        if (q.sequence==owner.sequence+1) {
            owner.sequence=q.sequence; out=execute(&owner,&q);
        }
        if (lost_response) {
            assert(out.outcome==MD_COOPERATIVE_COMPLETED && !out.error && out.fd>=0);
            /* Queue the real FD but lose the shared receipt: disconnect must
             * release unreceived kernel rights without replaying O_EXCL. */
            assert(md_fs_send_fds(delivery[0],&q.sequence,sizeof(q.sequence),&out.fd,1)==sizeof(q.sequence));
            assert(!close(out.fd));
            md_cooperative_close(channel); break;
        }
        if (q.sequence==1) {
            assert(!kill(actor,SIGUSR1));
            /* EVENT_WAIT: acknowledge signal-handler reentry before publishing
             * the receipt. Timeout fails the test, not a settling delay. */
            struct pollfd event={.fd=ack[0],.events=POLLIN};
            assert(poll(&event,1,5000)==1 && (event.revents&POLLIN));
            char value; assert(read(ack[0],&value,1)==1 && value==1);
        }
        int published=0;
        int reply=md_cooperative_reply(channel,&out,delivery[0],&published);
        if (out.fd>=0) assert(!close(out.fd));
        assert(!reply);
        if (owner.read_window && owner.window.owner && (owner.window.count>=32 || (uint64_t)clock_ns()>=owner.window.deadline))
            release_read(&owner);
    }
    release_read(&owner);
    assert(!getrusage(RUSAGE_SELF,&after));
    int status; assert(waitpid(child,&status,0)==child && status==0);
    if (lost_response) {
        /* The original actor has exited. Verify persistence under a fresh
         * actor, not by reading the vanished process's creation mask. */
        owner_close(&owner); owner_open(&owner,store,getpid());
        struct md_cooperative_request q=packet(SYS_openat,"/bench/lost-response",NULL,
            O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);
        checked(invoke_engine,&owner,&q,-EEXIST);
        q=packet(SYS_unlinkat,"/bench/lost-response",NULL,0,0);
        checked(invoke_engine,&owner,&q,0);
    } else printf("COOPERATIVE_WORKER {\"invocationCpuSeconds\":%.9f,\"completed\":%llu,\"readLeases\":%llu}\n",
        cpu(&after)-cpu(&before),(unsigned long long)owner.completed,(unsigned long long)owner.leases);
    owner_close(&owner);
    assert(fd_count()==descriptors);
    close(delivery[0]);
    close(ack[0]);
    assert(!munmap(channel,sizeof(*channel)));
}
static void read_window_contract(const char *store) {
    struct owner owner; owner_open(&owner,store,getpid()); owner.read_window=1;
    struct md_cooperative_request q=packet(SYS_openat,"/bench/read-visible",NULL,O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    struct md_cooperative_response out=checked(invoke_engine,&owner,&q,0);
    int fd=out.fd; assert(fd>=0);
    q=packet(SYS_newfstatat,"/bench/read-visible",NULL,0,0);
    for (unsigned i=0;i<64;++i) {
        assert(!ftruncate(fd,(off_t)i*17));
        out=checked(invoke_engine,&owner,&q,0);
        assert(out.info.size==(int64_t)i*17);
    }
    q=packet(SYS_unlinkat,"/bench/read-visible",NULL,0,0);
    checked(invoke_engine,&owner,&q,0); assert(!close(fd));
    q=packet(SYS_newfstatat,"/bench/from-writer",NULL,0,0);
    checked(invoke_engine,&owner,&q,-ENOENT);
    assert(owner.window.owner && owner.fs.store->locked);
    struct md_cooperative_channel *channel=channel_new();
    int ack[2]; assert(!pipe2(ack,O_CLOEXEC));
    fflush(NULL);
    pid_t writer=fork(); assert(writer>=0);
    if (!writer) {
        close(ack[0]);
        assert(write(ack[1],"w",1)==1); close(ack[1]);
        /* Never use the inherited SQLite connection in this child. */
        struct md_inode_store *other; assert(!md_inode_store_open(store,0,&other));
        struct md_identity id=md_identity_new(0,0); other->identity=&id;
        assert(!md_inode_mkdir(other,-1,"/bench/from-writer",0755));
        md_inode_store_close(other); md_identity_release(&id);
        md_cooperative_close(channel); _exit(0);
    }
    close(ack[1]);
    struct pollfd event={.fd=ack[0],.events=POLLIN};
    /* EVENT_WAIT: writer has started; timeout fails the fixture. The receiver
     * must release its store scope before parking or that writer cannot finish. */
    assert(poll(&event,1,5000)==1 && (event.revents&POLLIN));
    char value; assert(read(ack[0],&value,1)==1 && value=='w'); close(ack[0]);
    struct md_cooperative_request incoming;
    assert(!md_cooperative_receive(channel,&incoming,release_read,&owner));
    assert(!owner.window.owner && !owner.fs.store->locked);
    int status; assert(waitpid(writer,&status,0)==writer && status==0);
    out=checked(invoke_engine,&owner,&q,0);
    assert(S_ISDIR(out.info.mode));
    q=packet(SYS_unlinkat,"/bench/from-writer",NULL,AT_REMOVEDIR,0);
    checked(invoke_engine,&owner,&q,0);
    assert(!owner.window.owner && !owner.fs.store->locked);
    /* The count bound does not depend on clock precision or scheduler timing. */
    q=packet(SYS_newfstatat,"/bench/marker",NULL,0,0);
    checked(invoke_engine,&owner,&q,0);
    uint64_t leases=owner.leases; owner.window.count=32;
    checked(invoke_engine,&owner,&q,0); assert(owner.leases==leases+1);
    leases=owner.leases; owner.window.deadline=0;
    checked(invoke_engine,&owner,&q,0); assert(owner.leases==leases+1);
    q=packet(SYS_mkdirat,"/bench/private-read",NULL,0,0700);
    checked(invoke_engine,&owner,&q,0);
    q=packet(SYS_newfstatat,"/bench/private-read/.",NULL,0,0);
    checked(invoke_engine,&owner,&q,0);
    leases=owner.leases;
    /* Force the same scope despite scheduling delays in the test. Credentials
     * must still be captured and checked for each request, not for the window. */
    owner.window.deadline=INT64_MAX; owner.window.count=0;
    md_identity_release(&owner.identity); owner.identity=md_identity_new(1000,1000);
    assert(!md_task_registry_publish(owner.fs.tasks,owner.actor,owner.actor,&owner.identity,&owner.resources));
    checked(invoke_engine,&owner,&q,-EACCES);
    assert(owner.leases==leases && owner.window.owner);
    md_identity_release(&owner.identity); owner.identity=md_identity_new(0,0);
    assert(!md_task_registry_publish(owner.fs.tasks,owner.actor,owner.actor,&owner.identity,&owner.resources));
    checked(invoke_engine,&owner,&q,0);
    assert(owner.leases==leases && owner.window.owner);
    q=packet(SYS_unlinkat,"/bench/private-read",NULL,AT_REMOVEDIR,0);
    checked(invoke_engine,&owner,&q,0);
    q=packet(SYS_newfstatat,"/bench/marker",NULL,0,0);
    checked(invoke_engine,&owner,&q,0);
    assert(owner.window.owner);
    md_task_registry_forget(owner.fs.tasks,owner.actor);
    out=execute(&owner,&q);
    assert(out.outcome==MD_COOPERATIVE_DECLINED && out.error && !owner.window.owner && !owner.fs.store->locked);
    owner_close(&owner); assert(!munmap(channel,sizeof(*channel)));
    puts("PASS cooperative read window: fresh native IO/credentials, release before park/mutation, foreign writer freshness, count/time bounds and failed admission/teardown");
}
static void correctness(const char *store) {
    struct owner owner; owner_open(&owner,store,getpid());
    struct md_cooperative_request q=packet(SYS_mkdirat,"/bench/denied",NULL,0,0700);
    owner.enabled=0;
    struct md_cooperative_response out=execute(&owner,&q);
    assert(out.outcome==MD_COOPERATIVE_DECLINED && out.error==-EAGAIN && !owner.completed);
    owner.enabled=1;
    q=packet(SYS_newfstatat,"/bench/denied",NULL,0,0);
    checked(invoke_engine,&owner,&q,-ENOENT);
    md_identity_release(&owner.identity); owner.identity=md_identity_new(1000,1000);
    assert(!md_task_registry_publish(owner.fs.tasks,owner.actor,owner.actor,&owner.identity,&owner.resources));
    q=packet(SYS_mkdirat,"/bench/denied",NULL,0,0700);
    checked(invoke_engine,&owner,&q,-EACCES);
    md_identity_release(&owner.identity); owner.identity=md_identity_new(0,0);
    assert(!md_task_registry_publish(owner.fs.tasks,owner.actor,owner.actor,&owner.identity,&owner.resources));
    checked(invoke_engine,&owner,&q,0);
    q=packet(SYS_unlinkat,"/bench/denied",NULL,AT_REMOVEDIR,0);
    checked(invoke_engine,&owner,&q,0);
    struct md_inode_statistics statistics={0};
    md_inode_measure(owner.fs.store,&statistics);
    char bytes[4096]; memset(bytes,42,sizeof(bytes));
    file_cycle(invoke_engine,&owner,"/bench",0,bytes);
    md_inode_measure(owner.fs.store,NULL);
    assert(!statistics.write_admissions && !statistics.sync_object.calls && !statistics.sync_directory.calls);
    puts("PASS cooperative: ordinary file cycle uses native leaves without catalogue writes or sync barriers");
    struct md_fs_request fifo={.actor=getpid(),.operation=MD_FS_MKNOD,.directory={-1,-1},
        .path={"/bench/deferred-fifo",NULL},.mode=S_IFIFO|0600};
    struct md_fs_result made;
    md_fs_execute(&owner.fs,&fifo,&made,NULL); assert(!made.error && made.fd==-1);
    q=packet(SYS_openat,"/bench/deferred-fifo",NULL,O_RDONLY|O_CLOEXEC,0);
    checked(invoke_engine,&owner,&q,-EOPNOTSUPP);
    unsigned descriptors=fd_count();
    owner.tracked_files=1;
    owner.custody=md_fd_loan_new(owner.resources.files); assert(owner.custody);
    for (unsigned i=0;i<64;++i) {
        out=checked(invoke_engine,&owner,&q,-EOPNOTSUPP); assert(out.fd==-1);
    }
    assert(fd_count()==descriptors && !md_fd_origins_has_loans(owner.resources.files));
    q=packet(SYS_unlinkat,"/bench/deferred-fifo",NULL,0,0);
    checked(invoke_engine,&owner,&q,0);
    puts("PASS cooperative deferred open refusal: pin/control FD balance and no published origin");
    owner_close(&owner);
    read_window_contract(store);
    run_channel(store,1,0,1,0);
    run_channel(store,1,0,1,1);
    run_channel(store,1,0,1,2);
    run_channel(store,1,0,1,3);
    puts("PASS cooperative: captured requests, shared filesystem policy, refusal before mutation, lost receipt without replay");
}
int main(int argc,char **argv) {
    assert(argc>=3 && argc<=5);
    alarm(120);
    unsigned count=argc>=4 ? (unsigned)strtoul(argv[3],NULL,10) : 2048;
    assert(count && count<=1000000);
    int kind=argc==5 && !strcmp(argv[4],"metadata") ? 1 : argc==5 && !strcmp(argv[4],"files") ? 2
        : argc==5 && !strcmp(argv[4],"opens") ? 3 : 0;
    assert(argc<5 || kind || !strcmp(argv[4],"directories"));
    if (!strcmp(argv[1],"prepare")) prepare(argv[2],argv[0]);
    else if (!strcmp(argv[1],"guest-root")) {
        struct owner owner; owner_open(&owner,argv[2],getpid());
        owner.fs.store->identity=&owner.identity;
        struct md_fs_request q={.operation=MD_FS_CHOWN,.directory={MD_INODE_ROOT,-1},
            .path={"/",NULL},.attributes={.uid=0,.gid=0}};
        assert(!md_inode_metadata(owner.fs.store,&q));
        q.operation=MD_FS_CHMOD; q.mode=0755;
        assert(!md_inode_metadata(owner.fs.store,&q));
        owner.fs.store->identity=NULL; owner_close(&owner);
    }
    else if (!strcmp(argv[1],"native-prepare")) {
        assert(!mkdir(argv[2],0755));
        char marker[PATH_MAX];
        assert(snprintf(marker,sizeof(marker),"%s/marker",argv[2])<(int)sizeof(marker));
        int fd=open(marker,O_CREAT|O_EXCL|O_WRONLY,0644); assert(fd>=0);
        assert(write(fd,"marker",6)==6 && !close(fd));
    }
    else if (!strcmp(argv[1],"test")) {
        endpoint_wake_contract();
        correctness(argv[2]); run_channel(argv[2],1,0,0,0); run_channel(argv[2],1,0,0,1);
        run_channel(argv[2],1,0,0,2);
        run_channel(argv[2],1,0,0,3);
        run_channel(argv[2],16,3,0,5);
        run_channel(argv[2],16,3,0,6);
        for (int tracked=0;tracked<=1;++tracked) {
            run_shared_files(argv[2],1,3,1,tracked);
            run_shared_files(argv[2],16,3,0,tracked);
        }
        run_shared_files(argv[2],1,3,2,1);
        run_shared_files(argv[2],1,3,3,1);
        puts("PASS cooperative shared files: pre-publication loss, SIGKILL before consumption, exit with retained FD and exact retirement");
        for (int park=0;park<=1;++park) {
            for (int lost=0;lost<=3;++lost) run_sidecar(argv[2],16,3,lost,park);
            run_sidecar(argv[2],16,2,0,park);
        }
        puts("PASS cooperative FD sidecar: private engine, filtered recvmsg, real FD origins and exact death retirement");
        for (int reopen=0;reopen<=1;++reopen) {
            for (int lost=0;lost<=3;++lost) run_pipeline(argv[2],16,3,lost,reopen);
            run_pipeline(argv[2],16,2,0,reopen);
        }
        puts("PASS cooperative FD pipeline: private tables, direct helper completion, origin retirement in its owning table and death cleanup");
    }
    else if (!strcmp(argv[1],"test-pidfd")) {
        completion_queue_contract();
        for (int variant=2;variant<=8;++variant) {
            for (int lost=0;lost<=3;++lost) run_pipeline(argv[2],16,3,lost,variant);
            run_pipeline(argv[2],16,2,0,variant);
        }
        for (int variant=5;variant<=8;++variant) run_pipeline(argv[2],16,3,4,variant);
        for (int variant=7;variant<=8;++variant) {
            run_pipeline(argv[2],16,3,5,variant);
            run_pipeline(argv[2],16,3,6,variant);
        }
        puts("PASS cooperative queued close: EPERM retains origin; exit after queued close retires exactly once");
        puts("PASS cooperative guest plan: native open denial returns EPERM, no replay, origin/pin balance");
        puts("PASS cooperative self-pidfd: shared OFD offset, sockets, pipes, CLOEXEC, filtered guest and exact death cleanup");
    }
    else if (!strcmp(argv[1],"cooperative-shared-files") || !strcmp(argv[1],"cooperative-shared-tracked"))
        run_shared_files(argv[2],count,kind,0,!strcmp(argv[1],"cooperative-shared-tracked"));
    else if (!strcmp(argv[1],"cooperative-fd-executor")) run_channel(argv[2],count,kind,0,5);
    else if (!strcmp(argv[1],"cooperative-fd-executor-parked")) run_channel(argv[2],count,kind,0,6);
    else if (!strcmp(argv[1],"cooperative-fd-sidecar") || !strcmp(argv[1],"cooperative-fd-sidecar-parked"))
        run_sidecar(argv[2],count,kind,0,!strcmp(argv[1],"cooperative-fd-sidecar-parked"));
    else if (!strcmp(argv[1],"cooperative-fd-pipeline") || !strcmp(argv[1],"cooperative-fd-reopen")
            || !strcmp(argv[1],"cooperative-fd-pidfd") || !strcmp(argv[1],"cooperative-fd-local-close")
            || !strcmp(argv[1],"cooperative-fd-plan") || !strcmp(argv[1],"cooperative-guest-plan")
            || !strcmp(argv[1],"cooperative-guest-pin") || !strcmp(argv[1],"cooperative-guest-queued")
            || !strcmp(argv[1],"cooperative-guest-window"))
        run_pipeline(argv[2],count,kind,0,!strcmp(argv[1],"cooperative-guest-window") ? 8
            : !strcmp(argv[1],"cooperative-guest-queued") ? 7 : !strcmp(argv[1],"cooperative-guest-pin") ? 6
            : !strcmp(argv[1],"cooperative-guest-plan") ? 5 : !strcmp(argv[1],"cooperative-fd-plan") ? 4 : !strcmp(argv[1],"cooperative-fd-local-close") ? 3
            : !strcmp(argv[1],"cooperative-fd-pidfd") ? 2 : !strcmp(argv[1],"cooperative-fd-reopen"));
    else if (!strcmp(argv[1],"cooperative") || !strcmp(argv[1],"cooperative-bounded")
            || !strcmp(argv[1],"cooperative-adaptive") || !strcmp(argv[1],"cooperative-leased") || !strcmp(argv[1],"cooperative-leased-recheck"))
        run_channel(argv[2],count,kind,0,!strcmp(argv[1],"cooperative-leased-recheck") ? 4 : !strcmp(argv[1],"cooperative-leased") ? 3 : !strcmp(argv[1],"cooperative-adaptive") ? 2
            : !strcmp(argv[1],"cooperative-bounded"));
    else if (!strcmp(argv[1],"engine") || !strcmp(argv[1],"engine-profile") || !strcmp(argv[1],"engine-read-lease")) {
        struct owner owner; owner_open(&owner,argv[2],getpid());
        owner.profiling=!strcmp(argv[1],"engine-profile");
        if (owner.profiling) {
            owner.fs.statistics=&owner.operations; md_inode_measure(owner.fs.store,&owner.storage);
        }
        /* Lower-bound experiment only: other namespace writers are blocked for
         * this entire read workload. Each call still reads native attributes
         * and revalidates directories; this is not a production admission mode. */
        if (!strcmp(argv[1],"engine-read-lease")) {
            assert(kind==1);
            assert(!md_execution_window_admit(&owner.window,&owner,acquire_scope,release_scope,0,UINT_MAX,UINT64_MAX));
        }
        workload(argv[1],"/bench",count,kind,invoke_engine,&owner);
        release_read(&owner);
        if (owner.profiling) profile_report(&owner);
        owner_close(&owner);
    } else if (!strcmp(argv[1],"syscalls-entry")) {
        struct direct_client client={.api=(void *)getauxval(MD_AT_COOPERATIVE)};
        assert(client.api && client.api->version==MD_ENTRY_VERSION);
        workload("syscalls-entry",argv[2],count,kind,invoke_direct,&client);
        printf("COOPERATIVE_ENTRY completed=%u declined=%u\n",client.completed,client.declined);
        if (kind==1) assert(client.completed>=count);
    } else {
        assert(!strcmp(argv[1],"syscalls")); workload("syscalls",argv[2],count,kind,invoke_native,NULL);
    }
    return 0;
}

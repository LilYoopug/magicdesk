#define _GNU_SOURCE
#include "ipc_origins.h"
#include "ipc_capsule.h"
#include "fd_receipt.h"
#include "fs_worker.h"
#include "fs_engine.h"
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>

enum { PREPARE, RECEIVE };
struct md_ipc_origins {
    struct md_fs_worker *worker;
    struct md_ipc_capsules *capsules; /* worker-owned until join */
    struct md_ipc_origin_request *requests;
    char launch[33];
    unsigned count;
};
struct md_ipc_origin_request {
    struct md_fs_work work;
    struct md_ipc_origin_request *next, **previous;
    struct md_ipc_origins *service;
    struct md_fd_message *message;
    struct md_received_fds *source, *result;
    void (*complete)(struct md_ipc_origin_request *, int, void *);
    void *context;
    int kind, submitted, error;
    enum md_ipc_ancillary_transport transport;
    struct md_fs_context task;
    struct md_ipc_send_options options;
    struct md_ipc_send_address destination;
    atomic_int cancelled;
};
static void dispose(struct md_ipc_origin_request *r) {
    *r->previous=r->next;
    if (r->next) r->next->previous=r->previous;
    --r->service->count;
    md_fd_message_release(r->message);
    md_received_fds_release(r->source);
    md_fs_context_end(&r->task);
    if (r->destination.anchor>=0) close(r->destination.anchor);
    md_received_fds_release(r->result); free(r);
}
int md_ipc_origins_new(struct md_fs_worker *worker, const char *launch, struct md_ipc_origins **out) {
    if (!worker || !launch || strlen(launch)!=32 || strspn(launch,"0123456789abcdef")!=32
            || !out || *out) return -EINVAL;
    struct md_ipc_origins *s=calloc(1,sizeof(*s));
    if (!s) return -ENOMEM;
    s->worker=worker; memcpy(s->launch,launch,sizeof(s->launch)); *out=s; return 0;
}
void md_ipc_origins_destroy(struct md_ipc_origins *s) {
    if (!s) return;
    while (s->requests) dispose(s->requests);
    md_ipc_capsules_free(s->capsules); free(s);
}
static int prepare(struct md_ipc_origin_request *r, const struct md_ipc_binding *binding) {
    struct md_received_fds *result=NULL;
    int error=md_received_fds_reserve(&result,2);
    if (!error) {
        int fd=fcntl(r->source->fds[0],F_DUPFD_CLOEXEC,0);
        if (fd<0) error=-errno;
        else result->fds[result->count++]=fd;
    }
    int carrier=-1;
    if (!error) error=md_ipc_capsules_publish(r->service->capsules,binding,r->service->launch,
        r->message,r->source->fds+1,r->source->count-1,&carrier);
    if (!error) { result->fds[result->count++]=carrier; r->result=result; }
    else md_received_fds_release(result);
    return error;
}
static int address(struct md_ipc_origin_request *r) {
    const struct md_ipc_send_options *o=&r->options;
    r->destination.address=o->address; r->destination.length=o->length;
    if (!o->addressed || o->length<offsetof(struct sockaddr_un,sun_path)
            || o->address.ss_family!=AF_UNIX) return 0;
    if (o->length>sizeof(struct sockaddr_un)) return -EINVAL;
    const struct sockaddr_un *a=(const void *)&o->address;
    if (o->length==offsetof(struct sockaddr_un,sun_path) || !a->sun_path[0]) return 0;
    int family=0; socklen_t size=sizeof(family);
    if (getsockopt(r->source->fds[0],SOL_SOCKET,SO_DOMAIN,&family,&size)) return -errno;
    if (family!=AF_UNIX) return 0;
    char path[sizeof(a->sun_path)+1], resolved[PATH_MAX];
    size=o->length - offsetof(struct sockaddr_un,sun_path);
    memcpy(path,a->sun_path,size); path[size]=0;
    struct md_fs_anchor *cwd=r->task.task.cwd;
    struct md_fs_request q={.operation=MD_FS_SOCKET_ADDRESS,.flags=MD_FS_SOCKET_PIN,.actor=r->task.actor,.peer=r->task.peer,
        .directory={cwd ? md_fs_anchor_fd(cwd) : AT_FDCWD,-1},.origin={cwd,NULL},.path={path,NULL}};
    struct md_fs_result result;
    struct md_fs_output output={.data=resolved,.capacity=sizeof(resolved)};
    md_fs_context_execute(&r->task,&q,&result,&output);
    if (result.error) return result.error;
    if (result.host_path) {
        result.fd=open(resolved,O_PATH|O_CLOEXEC);
        if (result.fd<0) return -errno;
    }
    if (result.fd>=0) { r->destination.anchor=result.fd; return 0; }
    if (result.size<2 || result.size>sizeof(a->sun_path) || resolved[result.size-1]) return -EPROTO;
    struct sockaddr_un *to=(void *)&r->destination.address;
    memset(to,0,sizeof(*to)); to->sun_family=AF_UNIX;
    memcpy(to->sun_path+1,resolved,result.size-1);
    r->destination.length=offsetof(struct sockaddr_un,sun_path)+result.size;
    return 0;
}
static int credentials(struct md_ipc_origin_request *r, struct md_ipc_credentials *authority) {
    if (!r->options.credentials) return 0;
    struct md_fs_request q={.operation=MD_FS_IPC,.flags=MD_IPC_MESSAGE_CREATE,
        .actor=r->task.actor,.peer=r->task.peer,.directory={r->source->fds[0],-1},
        .offset=r->options.claimed.pid,
        .attributes={.uid=r->options.claimed.uid,.gid=r->options.claimed.gid}};
    struct md_fs_result result;
    md_ipc_credentials_execute(authority,&r->task.task.identity,&q,&result,NULL);
    if (result.error) return result.error;
    if (result.fd<0) return -EPROTO;
    int error=0;
    unsigned count=r->result ? r->result->count : r->source->count;
    if (count>=MD_FD_RECEIPT_MAX+1) error=-EINVAL;
    if (!error) error=md_received_fds_reserve(&r->result,count+1);
    if (!error && !r->result->count) {
        for (unsigned i=0;i<r->source->count;++i) {
            int fd=fcntl(r->source->fds[i],F_DUPFD_CLOEXEC,0);
            if (fd<0) { error=-errno; break; }
            r->result->fds[r->result->count++]=fd;
        }
    }
    if (!error) {
        r->result->fds[r->result->count++]=result.fd;
        r->destination.credentials=1;
    } else close(result.fd);
    return error;
}
static void run(struct md_fs_work *work, struct md_filesystem *fs, int error) {
    struct md_ipc_origin_request *r=(struct md_ipc_origin_request *)work;
    struct md_ipc_origins *s=r->service;
    r->task.filesystem=fs;
    if (!error && atomic_load_explicit(&r->cancelled,memory_order_relaxed)) error=-ECANCELED;
    struct md_ipc_credentials *authority=NULL; struct md_ipc_binding binding={0};
    if (!error) error=md_fs_ipc_authority(fs,&authority);
    if (!error) error=md_ipc_credentials_bind(authority,r->source->fds[0],&binding);
    if (r->kind==PREPARE && (error==-ENODATA || error==-ENOTSUP
            || error==-EAFNOSUPPORT || error==-EPROTOTYPE)) error=0;
    if (!error && r->kind==PREPARE) error=address(r);
    /* A datagram destination can override a connected peer. It must not carry
     * that peer's capsule or identity capability to a different receiver. */
    int bound=binding.scope!=NULL;
    if (!error && r->options.addressed && r->options.length && bound) {
        int type=0; socklen_t length=sizeof(type);
        if (getsockopt(r->source->fds[0],SOL_SOCKET,SO_TYPE,&type,&length)) error=-errno;
        if (!error && type==SOCK_DGRAM) {
            struct sockaddr_storage peer={0}; length=sizeof(peer);
            if (r->destination.anchor>=0) {
                /* A retained inode has no authenticated connection identity.
                 * Do not leak capabilities or silently downgrade a framed peer. */
                if (binding.transport==MD_IPC_TRANSPORT_ORIGINS_V1) error=-EOPNOTSUPP;
                bound=0;
            } else if (getpeername(r->source->fds[0],(void *)&peer,&length)
                    || length!=r->destination.length || memcmp(&peer,&r->destination.address,length)) bound=0;
        }
    }
    r->transport=bound ? binding.transport : MD_IPC_TRANSPORT_NATIVE;
    int framed=r->transport==MD_IPC_TRANSPORT_ORIGINS_V1;
    if (!error && r->kind==RECEIVE && !framed) error=-ENOTSUP;
    if (!error && framed && !s->capsules) error=md_ipc_capsules_new(&binding,&s->capsules);
    if (!error && atomic_load_explicit(&r->cancelled,memory_order_relaxed)) error=-ECANCELED;
    if (!error && framed) {
        if (r->kind==RECEIVE) error=md_ipc_capsules_receive(s->capsules,&binding,r->source->fds[1],&r->result);
        else if (r->source->count>1) error=prepare(r,&binding);
    }
    if (!error && r->kind==PREPARE && bound) error=credentials(r,authority);
    md_ipc_binding_release(&binding); r->error=error;
}
static int completed(struct md_fs_work *work) {
    struct md_ipc_origin_request *r=(struct md_ipc_origin_request *)work;
    r->submitted=0;
    /* Shared custody/reference mutations stay on the event-loop owner. The
     * worker only borrows them; cancellation cannot release a running input. */
    md_fd_message_release(r->message); r->message=NULL;
    if (!r->error && r->kind==PREPARE && !r->result) {
        r->result=r->source; r->source=NULL;
    }
    md_received_fds_release(r->source); r->source=NULL;
    if (atomic_load_explicit(&r->cancelled,memory_order_relaxed)) dispose(r);
    else r->complete(r,r->error,r->context);
    return 0;
}
static int begin(struct md_ipc_origins *s, int kind, struct md_fd_message *message,
        struct md_received_fds *source,
        struct md_fs_context *task, const struct md_ipc_send_options *options,
        void (*complete)(struct md_ipc_origin_request *, int, void *), void *context,
        struct md_ipc_origin_request **out) {
    if (!s || !source || !complete || !out || *out || source->count<1
            || source->count>MD_FD_RECEIPT_MAX+1
            || (kind==RECEIVE && source->count!=2)
            || (kind==PREPARE && source->count==1 && !options)
            || (kind==PREPARE && (source->count>1 ? !message || md_fd_message_count(message)!=source->count-1 : message!=NULL))
            || (options && (!task || options->length>sizeof(options->address)))) return -EINVAL;
    for (unsigned i=0;i<source->count;++i) if (source->fds[i]<0) return -EBADF;
    if (s->count>=16) return -EBUSY;
    struct md_ipc_origin_request *r=calloc(1,sizeof(*r));
    if (!r) return -ENOMEM;
    *r=(struct md_ipc_origin_request){.work={.run=run,.complete=completed},
        .service=s,.kind=kind,.complete=complete,.context=context,.submitted=1,
        .source=md_received_fds_retain(source),.message=md_fd_message_retain(message),
        .destination={.anchor=-1}};
    if (task) r->task=*task;
    if (options) r->options=*options;
    atomic_init(&r->cancelled,0);
    int error=md_fs_worker_submit(s->worker,&r->work);
    if (error) {
        md_received_fds_release(r->source); md_fd_message_release(r->message); free(r); return error;
    }
    r->next=s->requests; r->previous=&s->requests;
    if (r->next) r->next->previous=&r->next;
    s->requests=r; ++s->count; *out=r; return 0;
}
int md_ipc_origins_prepare(struct md_ipc_origins *s, struct md_fd_message *message,
        struct md_received_fds *source,
        void (*complete)(struct md_ipc_origin_request *, int, void *), void *context,
        struct md_ipc_origin_request **out) {
    return begin(s,PREPARE,message,source,NULL,NULL,complete,context,out);
}
int md_ipc_origins_send(struct md_ipc_origins *s, struct md_fd_message *message,
        struct md_received_fds *source, struct md_fs_context *task, const struct md_ipc_send_options *options,
        void (*complete)(struct md_ipc_origin_request *, int, void *), void *context,
        struct md_ipc_origin_request **out) {
    if (!task || !options) return -EINVAL;
    int error=begin(s,PREPARE,message,source,task,options,complete,context,out);
    if (!error) *task=(struct md_fs_context){0};
    return error;
}
int md_ipc_origins_receive(struct md_ipc_origins *s, struct md_received_fds *source,
        void (*complete)(struct md_ipc_origin_request *, int, void *), void *context,
        struct md_ipc_origin_request **out) {
    return begin(s,RECEIVE,NULL,source,NULL,NULL,complete,context,out);
}
int md_ipc_origins_take_send(struct md_ipc_origin_request **owner, struct md_received_fds **out,
        enum md_ipc_ancillary_transport *transport, struct md_ipc_send_address *destination) {
    if (!owner || !*owner || !out || *out) return -EINVAL;
    struct md_ipc_origin_request *r=*owner;
    if (r->submitted) return -EAGAIN;
    if (!destination && (r->options.addressed || r->options.credentials)) return -EINVAL;
    int error=r->error;
    if (!error) {
        *out=r->result; r->result=NULL; if (transport) *transport=r->transport;
        if (destination) { *destination=r->destination; r->destination.anchor=-1; }
    }
    *owner=NULL; dispose(r); return error;
}
int md_ipc_origins_take(struct md_ipc_origin_request **owner, struct md_received_fds **out,
        enum md_ipc_ancillary_transport *transport) {
    return md_ipc_origins_take_send(owner,out,transport,NULL);
}
void md_ipc_origins_cancel(struct md_ipc_origin_request **owner) {
    if (!owner || !*owner) return;
    struct md_ipc_origin_request *r=*owner; *owner=NULL;
    atomic_store_explicit(&r->cancelled,1,memory_order_relaxed);
    if (!r->submitted) dispose(r);
}

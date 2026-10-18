#define _GNU_SOURCE
#include "fuse_session.h"
#include <errno.h>
#include <limits.h>
#include <stdatomic.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct md_fuse_session {
    atomic_uint references;
    pthread_mutex_t lock;
    struct md_fuse_connection *connection;
    struct md_fuse_request *init;
    struct md_user_namespace *user_namespace;
    struct md_fuse_options options;
    atomic_uint max_write;
    atomic_uint flags;
    atomic_uint minor;
    atomic_int ready;
};
int md_fuse_session_new(struct md_fuse_connection *connection,const struct md_fuse_options *options,
        const struct md_identity *id,uint32_t pid,struct md_resource_wakeup *wake,struct md_fuse_session **out) {
    *out=NULL;
    if (!connection || !options || !id) return -EINVAL;
    struct md_fuse_session *s=calloc(1,sizeof(*s)); if (!s) return -ENOMEM;
    int initialized=pthread_mutex_init(&s->lock,NULL);
    if (initialized) { free(s); return -initialized; }
    atomic_init(&s->ready,0); atomic_init(&s->max_write,0); atomic_init(&s->flags,0); atomic_init(&s->minor,0);
    atomic_init(&s->references,1); s->connection=md_fuse_connection_retain(connection);
    s->options=*options; s->user_namespace=md_user_namespace_retain(id->user_namespace);
    s->options.uid=md_user_namespace_into(id->user_namespace,0,options->uid);
    s->options.gid=md_user_namespace_into(id->user_namespace,1,options->gid);
    int error=(s->options.uid==UINT32_MAX || s->options.gid==UINT32_MAX) ? -EINVAL : 0;
    struct fuse_in_header header={.opcode=FUSE_INIT,.pid=pid,
        .uid=md_identity_visible_id(id,0,id->uid.fs),.gid=md_identity_visible_id(id,1,id->gid.fs)};
    /* The pre-INIT_EXT input is exactly four u32 words, even with newer NDK headers. */
    const uint32_t init[]={7,MD_FUSE_PROTOCOL_MINOR,0,FUSE_ATOMIC_O_TRUNC|FUSE_SPLICE_READ|FUSE_SPLICE_WRITE|FUSE_SPLICE_MOVE};
    if (!error) error=md_fuse_connection_claim(connection);
    if (!error) {
        error=md_fuse_request_submit(connection,&header,init,sizeof(init),
            sizeof(struct fuse_init_out),0,wake,&s->init);
        if (error) md_fuse_connection_abort(connection,error);
    }
    if (error) {
        md_user_namespace_release(s->user_namespace); md_fuse_connection_release(s->connection);
        pthread_mutex_destroy(&s->lock); free(s);
    } else *out=s;
    return error;
}
struct md_fuse_session *md_fuse_session_retain(struct md_fuse_session *s) {
    if (s) atomic_fetch_add_explicit(&s->references,1,memory_order_relaxed); return s;
}
void md_fuse_session_abort(struct md_fuse_session *s,int error) {
    if (s) md_fuse_connection_abort(s->connection,error);
}
void md_fuse_session_release(struct md_fuse_session *s) {
    if (!s || atomic_fetch_sub_explicit(&s->references,1,memory_order_acq_rel)!=1) return;
    md_fuse_connection_abort(s->connection,-ECONNABORTED);
    md_fuse_request_release(s->init); md_fuse_connection_release(s->connection);
    md_user_namespace_release(s->user_namespace); pthread_mutex_destroy(&s->lock); free(s);
}
int md_fuse_session_ready(struct md_fuse_session *s) {
    int error=md_fuse_connection_error(s->connection);
    if (error) return error;
    int ready=atomic_load_explicit(&s->ready,memory_order_acquire);
    if (ready) return ready;
    pthread_mutex_lock(&s->lock);
    ready=atomic_load_explicit(&s->ready,memory_order_relaxed);
    if (ready) { pthread_mutex_unlock(&s->lock); return ready; }
    struct fuse_init_out result={0};
    long size=md_fuse_request_result(s->init,&result,sizeof(result));
    if (size==-EINPROGRESS) { pthread_mutex_unlock(&s->lock); return 0; }
    if (size<0) error=(int)size;
    /* Both sides advertise their ceiling; a newer daemon speaks our lower
     * offered minor, it is not an incompatible protocol response. */
    else if (size<24 || result.major!=7 || result.minor<12
            || !result.max_write) error=-EPROTO;
    else {
        atomic_store_explicit(&s->max_write,result.max_write<MD_FUSE_IO_SIZE ? result.max_write : MD_FUSE_IO_SIZE,memory_order_relaxed);
        atomic_store_explicit(&s->flags,result.flags&FUSE_ATOMIC_O_TRUNC,memory_order_relaxed);
        atomic_store_explicit(&s->minor,result.minor<MD_FUSE_PROTOCOL_MINOR ? result.minor : MD_FUSE_PROTOCOL_MINOR,memory_order_relaxed);
        ready=1;
    }
    md_fuse_request_release(s->init); s->init=NULL;
    if (error) { ready=error; md_fuse_connection_abort(s->connection,error); }
    atomic_store_explicit(&s->ready,ready,memory_order_release);
    pthread_mutex_unlock(&s->lock);
    return ready;
}
uint32_t md_fuse_session_read_size(const struct md_fuse_session *s) { return s->options.max_read; }
uint32_t md_fuse_session_write_size(const struct md_fuse_session *s) { return atomic_load_explicit(&s->max_write,memory_order_relaxed); }
int md_fuse_session_atomic_truncate(const struct md_fuse_session *s) {
    return !!(atomic_load_explicit(&s->flags,memory_order_relaxed)&FUSE_ATOMIC_O_TRUNC);
}
unsigned md_fuse_session_minor(const struct md_fuse_session *s) {
    return atomic_load_explicit(&s->minor,memory_order_relaxed);
}
const struct md_fuse_options *md_fuse_session_options(const struct md_fuse_session *s) { return &s->options; }
int md_fuse_session_access(const struct md_fuse_session *s,const struct md_identity *id) {
    if (!id || !md_user_namespace_contains(s->user_namespace,id->user_namespace)) return -EACCES;
    if (!s->options.allow_other && (id->uid.real!=s->options.uid || id->uid.effective!=s->options.uid
            || id->uid.saved!=s->options.uid || id->gid.real!=s->options.gid
            || id->gid.effective!=s->options.gid || id->gid.saved!=s->options.gid)) return -EACCES;
    return 0;
}
int md_fuse_session_request(struct md_fuse_session *s,const struct md_identity *id,uint32_t pid,
        uint32_t operation,uint64_t node,const void *data,size_t size,size_t capacity,int no_reply,
        struct md_resource_wakeup *wake,struct md_fuse_request **out) {
    *out=NULL;
    int ready=md_fuse_session_ready(s);
    if (ready<=0) return ready ? ready : -EAGAIN;
    int access=md_fuse_session_access(s,id);
    if (access) return access;
    struct fuse_in_header header={.opcode=operation,.nodeid=node,.pid=pid,
        .uid=md_user_namespace_from(s->user_namespace,0,id->uid.fs),
        .gid=md_user_namespace_from(s->user_namespace,1,id->gid.fs)};
    if (header.uid==UINT32_MAX || header.gid==UINT32_MAX) return -EOVERFLOW;
    return md_fuse_request_submit(s->connection,&header,data,size,capacity,no_reply,wake,out);
}

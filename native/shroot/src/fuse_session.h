#ifndef MD_FUSE_SESSION_H
#define MD_FUSE_SESSION_H
#include "fuse_transport.h"
#include "guest_identity.h"
#include "fuse_options.h"
struct md_fuse_session;
/* Negotiation deliberately offers no unimplemented cache, locking,
 * writeback or passthrough semantics. The wire baseline is Linux 5.15. */
enum { MD_FUSE_PROTOCOL_MINOR=31 };
int md_fuse_session_new(struct md_fuse_connection *,const struct md_fuse_options *,
    const struct md_identity *,uint32_t pid,struct md_resource_wakeup *,struct md_fuse_session **);
struct md_fuse_session *md_fuse_session_retain(struct md_fuse_session *);
void md_fuse_session_release(struct md_fuse_session *);
void md_fuse_session_abort(struct md_fuse_session *,int);
/* 0 while INIT is pending, 1 when negotiated, negative errno after failure. */
int md_fuse_session_ready(struct md_fuse_session *);
uint32_t md_fuse_session_read_size(const struct md_fuse_session *);
uint32_t md_fuse_session_write_size(const struct md_fuse_session *);
int md_fuse_session_atomic_truncate(const struct md_fuse_session *);
unsigned md_fuse_session_minor(const struct md_fuse_session *);
const struct md_fuse_options *md_fuse_session_options(const struct md_fuse_session *);
int md_fuse_session_access(const struct md_fuse_session *,const struct md_identity *);
int md_fuse_session_request(struct md_fuse_session *,const struct md_identity *,uint32_t pid,
    uint32_t operation,uint64_t node,const void *,size_t,size_t,int,
    struct md_resource_wakeup *,struct md_fuse_request **);
#endif

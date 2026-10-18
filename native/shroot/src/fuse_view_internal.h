#ifndef MD_FUSE_VIEW_INTERNAL_H
#define MD_FUSE_VIEW_INTERNAL_H
#include "fuse_view.h"
#include "fs_mount_internal.h"
#include <pthread.h>
#include <stdatomic.h>

/* One mount owns nodes and their private carriers. Files retain this owner; mutable
 * node metadata and mapping generations are protected by its lock. */
enum { NODE_BUCKETS=1024, NODE_LIMIT=65536 };
struct fuse_node {
    struct fuse_node *id_next,*fd_next;
    uint64_t id,generation,lookups,changes;
    mode_t type;
    char carrier_name[32];
    struct stat carrier,attributes;
};
struct fuse_name {
    struct fuse_name *next;
    struct fuse_node *parent,*node;
    char name[];
};
struct fuse_view {
    atomic_uint references;
    pthread_mutex_t lock;
    struct md_fuse_session *session;
    struct md_fuse_connection *notifications;
    struct md_user_namespace *user_namespace;
    struct md_pid_namespace *pid_namespace;
    dev_t device;
    int root;
    unsigned count;
    struct fuse_node *by_id[NODE_BUCKETS],*by_fd[NODE_BUCKETS],*root_node;
    struct fuse_name *names;
};
void *md_fuse_view_retain(void *);
void md_fuse_view_release(void *);
int md_fuse_view_attributes(struct fuse_view *,const struct fuse_attr *,struct stat *);
uint32_t md_fuse_view_pid(struct fuse_view *,pid_t);
int md_fuse_node_open(struct fuse_view *,struct fuse_node *,int flags);
void md_fuse_file_release_remote(struct fuse_view *,uint64_t,int,const struct md_identity *,uint64_t,unsigned);
void md_fuse_file_release_handle(struct fuse_view *,struct fuse_node *,const struct md_identity *,uint64_t,unsigned);
/* Takes the remote open handle on both success and failure. */
int md_fuse_file_publish(struct fuse_view *,struct fuse_node *,struct md_fs_anchor *,
    const struct md_identity *,unsigned,const struct fuse_open_out *,struct md_fs_result *,const struct md_fs_output *);
#endif

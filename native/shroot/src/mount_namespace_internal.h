#ifndef MD_MOUNT_NAMESPACE_INTERNAL_H
#define MD_MOUNT_NAMESPACE_INTERNAL_H
#include "mount_namespace.h"
#include "mount_instance.h"
#include <pthread.h>
#include <stdatomic.h>

struct md_mount_namespace {
    atomic_uint refs;
    atomic_int managed_paths;
    uint64_t inode;
    struct md_user_namespace *owner;
    unsigned shm_id;
    struct md_view_mount base;
    struct md_view_mount *root;
    struct md_fs_mounts *tree;
    struct md_mount_identity *native_ids;
    struct md_native_mounts *native_mounts;
    struct md_mount_graph *graph;
    struct md_mount_family *family;
    struct md_mount_namespace *family_next;
    pthread_mutex_t tables_lock;
    struct md_mount_table_file *tables;
    /* Weak membership: each FS context retains the view, not vice versa.
     * Fork publication and root relocation share this short lifecycle lock. */
    pthread_mutex_t domains_lock;
    struct md_guest_domain *domains;
};
#endif

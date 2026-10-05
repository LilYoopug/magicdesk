#include "fs_mount_internal.h"
#include <stdlib.h>
#include <unistd.h>

struct md_mount_namespace *md_mount_namespace_new(void) {
    struct md_mount_namespace *n=calloc(1,sizeof(*n));
    if (n) atomic_init(&n->refs,1);
    return n;
}
struct md_mount_namespace *md_mount_namespace_retain(struct md_mount_namespace *n) {
    if (n) atomic_fetch_add_explicit(&n->refs,1,memory_order_relaxed);
    return n;
}
void md_mount_namespace_release(struct md_mount_namespace *n) {
    if (!n || atomic_fetch_sub_explicit(&n->refs,1,memory_order_acq_rel)!=1) return;
    struct md_fs_mounts *m=n->tree;
    if (m) {
        for (unsigned i=0;i<MD_VIEW_BUCKETS;++i) {
            struct md_view_object *p=m->table[i];
            while (p) { struct md_view_object *next=p->next; close(p->fd); free(p); p=next; }
        }
        for (unsigned i=0;i<m->count;++i) {
            if (m->mounts[i].source>=0) close(m->mounts[i].source);
            if (m->mounts[i].target>=0) close(m->mounts[i].target);
        }
        free(m);
    }
    free(n->native_ids); free(n);
}
int md_mount_namespace_attached(const struct md_mount_namespace *n) {
    return n && n->tree && n->tree->count;
}

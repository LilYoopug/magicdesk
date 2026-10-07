#include "inode_internal.h"
#include <stdlib.h>
#include <unistd.h>

struct md_inode_lifetime *mdi_lifetime_new(int root, const struct stat *st) {
    struct md_inode_lifetime *p=calloc(1,sizeof(*p));
    if (!p) return NULL;
    atomic_init(&p->refs,1);
    p->root=root; p->device=st->st_dev; p->inode=st->st_ino;
    for (unsigned i=0;i<MDI_SOURCES;++i) p->sources[i]=p->source_leases[i]=-1;
    return p;
}
struct md_inode_lifetime *md_inode_store_lifetime(const struct md_inode_store *s) {
    return s ? s->lifetime : NULL;
}
struct md_inode_lifetime *md_inode_lifetime_retain(struct md_inode_lifetime *p) {
    if (p) atomic_fetch_add_explicit(&p->refs,1,memory_order_relaxed);
    return p;
}
void md_inode_lifetime_release(struct md_inode_lifetime *p) {
    if (!p || atomic_fetch_sub_explicit(&p->refs,1,memory_order_acq_rel)!=1) return;
    for (unsigned i=1;i<MDI_SOURCES;++i) {
        if (p->sources[i]>=0) close(p->sources[i]);
        if (p->source_leases[i]>=0) close(p->source_leases[i]);
    }
    close(p->root); free(p);
}
int md_inode_lifetime_same(const struct md_inode_lifetime *a, const struct md_inode_lifetime *b) {
    return a==b || (a && b && a->device==b->device && a->inode==b->inode);
}

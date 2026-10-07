#include "received_fds.h"
#include "fs_anchor.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

int md_received_fds_reserve(struct md_received_fds **owner, unsigned needed) {
    if (!owner || !needed || needed>253U*1024+1) return -EINVAL;
    struct md_received_fds *p=*owner;
    int fresh=!p;
    if (p && (p->references!=1 || p->origins)) return -EBUSY;
    if (p && p->capacity>=needed) return 0;
    unsigned capacity=needed*2;
    p=realloc(p,sizeof(*p)+capacity*sizeof(int));
    if (!p) return -ENOMEM;
    if (fresh) { p->references=1; p->count=0; p->origins=NULL; }
    p->capacity=capacity; *owner=p; return 0;
}
int md_received_fds_annotate(struct md_received_fds *p, struct md_fs_anchor *const *origins,
        unsigned count) {
    if (!p || !origins || !count || count!=p->count) return -EINVAL;
    if (p->references!=1 || p->origins) return -EBUSY;
    unsigned known=0;
    for (unsigned i=0;i<count;++i) known+=origins[i]!=NULL;
    if (!known) return 0;
    struct md_fs_anchor **next=calloc(count,sizeof(*next));
    if (!next) return -ENOMEM;
    for (unsigned i=0;i<count;++i) next[i]=md_fs_anchor_retain(origins[i]);
    p->origins=next;
    return 0;
}
int md_received_fds_select(const struct md_received_fds *p, const int *indices, unsigned count,
        int *fds, struct md_fs_anchor **origins) {
    if (!p || !indices || !fds || !count || count>253) return -EINVAL;
    for (unsigned i=0;i<count;++i) {
        if (indices[i]<0 || (unsigned)indices[i]>=p->count) return -EINVAL;
        if (!origins && p->origins && p->origins[indices[i]]) return -EOPNOTSUPP;
    }
    for (unsigned i=0;i<count;++i) {
        fds[i]=p->fds[indices[i]];
        if (origins) origins[i]=p->origins ? p->origins[indices[i]] : NULL;
    }
    return 0;
}
struct md_received_fds *md_received_fds_retain(struct md_received_fds *p) {
    if (p) ++p->references;
    return p;
}
void md_received_fds_release(struct md_received_fds *p) {
    if (!p || --p->references) return;
    for (unsigned i=0;i<p->count;++i) {
        close(p->fds[i]);
        if (p->origins) md_fs_anchor_release(p->origins[i]);
    }
    free(p->origins);
    free(p);
}

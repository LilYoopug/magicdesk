#include "received_fds.h"
#include "fd_object.h"
#include "socket_control.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int md_received_fds_reserve(struct md_received_fds **owner, unsigned needed) {
    if (!owner || !needed || needed>MD_SOCKET_RECEIVED_FDS*1024U+1) return -EINVAL;
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
int md_received_fds_annotate(struct md_received_fds *p, struct md_fd_object *const *origins,
        unsigned count) {
    if (!p || !origins || !count || count!=p->count) return -EINVAL;
    if (p->references!=1 || p->origins) return -EBUSY;
    unsigned known=0;
    for (unsigned i=0;i<count;++i) known+=origins[i]!=NULL;
    if (!known) return 0;
    struct md_fd_object **next=calloc(p->capacity,sizeof(*next));
    if (!next) return -ENOMEM;
    for (unsigned i=0;i<count;++i) next[i]=md_fd_object_retain(origins[i]);
    p->origins=next;
    return 0;
}
int md_received_fds_join(struct md_received_fds **owner,struct md_received_fds **tail) {
    if (!owner || !tail || owner==tail || !*tail || *owner==*tail) return -EINVAL;
    struct md_received_fds *a=*owner,*b=*tail;
    if ((a && a->references!=1) || b->references!=1) return -EBUSY;
    if (!a) { *owner=b; *tail=NULL; return 0; }
    unsigned count=a->count+b->count;
    if (count<a->count || count>MD_SOCKET_RECEIVED_FDS*1024U+1) return -EOVERFLOW;
    unsigned capacity=count>a->capacity ? count*2 : a->capacity;
    struct md_fd_object **origins=a->origins;
    int replace=(a->origins || b->origins) && (!a->origins || capacity!=a->capacity);
    if (replace) {
        origins=calloc(capacity,sizeof(*origins));
        if (!origins) return -ENOMEM;
        if (a->origins) memcpy(origins,a->origins,a->count*sizeof(*origins));
    }
    /* Prepare annotations before realloc: a failed growth leaves both input
     * vectors and every retained authority unchanged. Neither FD is duplicated. */
    if (capacity!=a->capacity) {
        struct md_received_fds *grown=realloc(a,sizeof(*a)+capacity*sizeof(int));
        if (!grown) { if (replace) free(origins); return -ENOMEM; }
        a=grown; a->capacity=capacity;
    }
    if (replace) { free(a->origins); a->origins=origins; }
    if (b->origins) memcpy(origins+a->count,b->origins,b->count*sizeof(*origins));
    memcpy(a->fds+a->count,b->fds,b->count*sizeof(int));
    a->count=count;
    free(b->origins); free(b);
    *owner=a; *tail=NULL; return 0;
}
int md_received_fds_select(const struct md_received_fds *p, const int *indices, unsigned count,
        int *fds, struct md_fd_object **origins) {
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
        if (p->origins) md_fd_object_release(p->origins[i]);
    }
    free(p->origins);
    free(p);
}

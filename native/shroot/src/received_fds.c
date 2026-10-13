#include "received_fds.h"
#include "fs_anchor.h"
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
    struct md_fd_object **next=calloc(count,sizeof(*next));
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
    struct md_received_fds *next=malloc(sizeof(*next)+count*sizeof(int));
    if (!next) return -ENOMEM;
    *next=(struct md_received_fds){.references=1,.count=count,.capacity=count};
    if (a->origins || b->origins) {
        next->origins=calloc(count,sizeof(*next->origins));
        if (!next->origins) { free(next); return -ENOMEM; }
        if (a->origins) memcpy(next->origins,a->origins,a->count*sizeof(*a->origins));
        if (b->origins) memcpy(next->origins+a->count,b->origins,b->count*sizeof(*b->origins));
    }
    memcpy(next->fds,a->fds,a->count*sizeof(int));
    memcpy(next->fds+a->count,b->fds,b->count*sizeof(int));
    free(a->origins); free(a); free(b->origins); free(b);
    *owner=next; *tail=NULL; return 0;
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

#include "received_fds.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

int md_received_fds_reserve(struct md_received_fds **owner, unsigned needed) {
    if (!owner || !needed || needed>253U*1024+1) return -EINVAL;
    struct md_received_fds *p=*owner;
    int fresh=!p;
    if (p && p->references!=1) return -EBUSY;
    if (p && p->capacity>=needed) return 0;
    unsigned capacity=needed*2;
    p=realloc(p,sizeof(*p)+capacity*sizeof(int));
    if (!p) return -ENOMEM;
    if (fresh) { p->references=1; p->count=0; }
    p->capacity=capacity; *owner=p; return 0;
}
struct md_received_fds *md_received_fds_retain(struct md_received_fds *p) {
    if (p) ++p->references;
    return p;
}
void md_received_fds_release(struct md_received_fds *p) {
    if (!p || --p->references) return;
    for (unsigned i=0;i<p->count;++i) close(p->fds[i]);
    free(p);
}

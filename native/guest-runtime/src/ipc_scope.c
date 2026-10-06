#include "ipc_scope.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

void md_ipc_scope_release(struct md_ipc_scope *s) {
    if (!s || atomic_fetch_sub_explicit(&s->refs,1,memory_order_acq_rel)!=1) return;
    if (s->lease>=0) close(s->lease);
    if (s->root>=0) close(s->root);
    free(s);
}
void md_ipc_binding_release(struct md_ipc_binding *b) {
    if (!b) return;
    md_ipc_scope_release(b->scope); *b=(struct md_ipc_binding){0};
}
int md_ipc_binding_copy(struct md_ipc_binding *out, const struct md_ipc_binding *source) {
    if (!out || out->scope || !source || !source->scope || source->connection.side>1) return -EINVAL;
    atomic_fetch_add_explicit(&source->scope->refs,1,memory_order_relaxed);
    *out=*source; return 0;
}
int md_ipc_binding_same_scope(const struct md_ipc_binding *a, const struct md_ipc_binding *b) {
    return a && b && a->scope && b->scope && a->scope->device==b->scope->device
        && a->scope->inode==b->scope->inode;
}

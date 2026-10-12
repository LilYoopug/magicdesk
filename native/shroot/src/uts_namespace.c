#include "uts_namespace.h"
#include "namespace_identity.h"
#include "control_event.h"
#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

struct md_uts_namespace {
    atomic_uint references;
    uint64_t inode;
    struct utsname names;
    struct md_user_namespace *owner;
    struct md_control_event *events[2];
};
struct md_uts_namespace *md_uts_namespace_new(void) {
    struct md_uts_namespace *n=calloc(1,sizeof(*n));
    if (!n) return NULL;
    if (uname(&n->names)) { free(n); return NULL; }
    int error=md_namespace_identity_new(&n->inode);
    if (error) { free(n); errno=-error; return NULL; }
    atomic_init(&n->references,1);
    for (unsigned i=0;i<2;++i) {
        n->events[i]=md_control_event_new();
        if (!n->events[i]) { int saved=errno; md_uts_namespace_release(n); errno=saved; return NULL; }
    }
    return n;
}
struct md_uts_namespace *md_uts_namespace_retain(struct md_uts_namespace *n) {
    if (n) atomic_fetch_add_explicit(&n->references,1,memory_order_relaxed);
    return n;
}
struct md_uts_namespace *md_uts_namespace_copy(const struct md_uts_namespace *n, struct md_user_namespace *owner) {
    if (!n) return NULL;
    struct md_uts_namespace *copy=malloc(sizeof(*copy));
    if (copy) {
        int error=md_namespace_identity_new(&copy->inode);
        if (error) { free(copy); errno=-error; return NULL; }
        atomic_init(&copy->references,1); copy->owner=md_user_namespace_retain(owner);
        copy->names=n->names;
        for (unsigned i=0;i<2;++i) copy->events[i]=md_control_event_retain(n->events[i]);
    }
    return copy;
}
void md_uts_namespace_release(struct md_uts_namespace *n) {
    if (n && atomic_fetch_sub_explicit(&n->references,1,memory_order_acq_rel)==1) {
        for (unsigned i=0;i<2;++i) md_control_event_release(n->events[i]);
        md_user_namespace_release(n->owner); free(n);
    }
}
struct md_control_event *md_uts_namespace_event(const struct md_uts_namespace *n,int domain) {
    return n ? n->events[!!domain] : NULL;
}
const struct md_user_namespace *md_uts_namespace_owner(const struct md_uts_namespace *n) { return n->owner; }
uint64_t md_uts_namespace_inode(const struct md_uts_namespace *n) { return n->inode; }
void md_uts_namespace_read(const struct md_uts_namespace *n, struct utsname *names) {
    *names=n->names;
}
int md_uts_namespace_set(struct md_uts_namespace *n, int domain, const void *name, size_t size) {
    if (!n || size>=sizeof(n->names.nodename)) return -EINVAL;
    char *target=domain ? n->names.domainname : n->names.nodename;
    if (size) memcpy(target,name,size);
    memset(target+size,0,sizeof(n->names.nodename)-size);
    return md_control_event_publish(n->events[!!domain]);
}

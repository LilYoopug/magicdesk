#include "uts_namespace.h"
#include "namespace_identity.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct md_uts_namespace { unsigned references; uint64_t inode; struct utsname names; struct md_user_namespace *owner; };
struct md_uts_namespace *md_uts_namespace_new(void) {
    struct md_uts_namespace *n=calloc(1,sizeof(*n));
    if (!n) return NULL;
    if (uname(&n->names)) { free(n); return NULL; }
    int error=md_namespace_identity_new(&n->inode);
    if (error) { free(n); errno=-error; return NULL; }
    n->references=1;
    return n;
}
struct md_uts_namespace *md_uts_namespace_retain(struct md_uts_namespace *n) {
    if (n) ++n->references;
    return n;
}
struct md_uts_namespace *md_uts_namespace_copy(const struct md_uts_namespace *n, struct md_user_namespace *owner) {
    if (!n) return NULL;
    struct md_uts_namespace *copy=malloc(sizeof(*copy));
    if (copy) {
        *copy=*n;
        int error=md_namespace_identity_new(&copy->inode);
        if (error) { free(copy); errno=-error; return NULL; }
        copy->references=1; copy->owner=md_user_namespace_retain(owner);
    }
    return copy;
}
void md_uts_namespace_release(struct md_uts_namespace *n) {
    if (n && !--n->references) { md_user_namespace_release(n->owner); free(n); }
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
    return 0;
}

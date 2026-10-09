#include "inode_internal.h"
#include "temporary_directory.h"
#include <errno.h>
#include <unistd.h>

int md_inode_store_transient(int parent, struct md_user_namespace *namespace, struct md_inode_store **out) {
    if (!out) return -EINVAL;
    *out=NULL;
    int root=md_temporary_directory_new(parent);
    if (root<0) return root;
    struct stat st;
    int r=fstat(root,&st) ? -errno : 0;
    struct md_inode_lifetime *owner=r ? NULL : mdi_lifetime_new(root,&st);
    if (!r && !owner) r=-ENOMEM;
    if (!owner) { md_temporary_directory_release(root); return r; }
    owner->temporary=1;
    owner->owner=md_user_namespace_retain(namespace);
    r=md_inode_store_initialize(owner,out);
    md_inode_lifetime_release(owner);
    return r;
}

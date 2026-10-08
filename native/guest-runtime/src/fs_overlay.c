#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "fs_storage.h"
#include "inode_internal.h"
#include "inode_overlay.h"
#include "inode_view.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { MAX_LAYERS=64 };
struct options { char *lower[MAX_LAYERS],*upper,*work; unsigned count; int user_xattr; };
static int parse(char *text, struct options *out) {
    *out=(struct options){0};
    char *options=text, *entry;
    while ((entry=strsep(&options,","))) {
        if (!*entry) return -EINVAL;
        if (!strcmp(entry,"userxattr")) { out->user_xattr=1; continue; }
        if (!strncmp(entry,"upperdir=",9) || !strncmp(entry,"workdir=",8)) {
            int upper=entry[0]=='u'; char **target=upper ? &out->upper : &out->work;
            char *value=entry+(upper ? 9 : 8);
            if (*target || !*value) return -EINVAL;
            if (strchr(value,'\\')) return -EOPNOTSUPP;
            *target=value; continue;
        }
        if (strncmp(entry,"lowerdir=",9)) return -EOPNOTSUPP;
        if (out->count || !entry[9]) return -EINVAL;
        char *layers=entry+9;
        while (layers) {
            if (out->count==MAX_LAYERS) return -E2BIG;
            char *next=strchr(layers,':');
            if (next) *next++=0;
            if (!*layers) return -EINVAL;
            if (strchr(layers,'\\')) return -EOPNOTSUPP;
            out->lower[out->count++]=layers; layers=next;
        }
    }
    return out->count && !!out->upper==!!out->work ? 0 : -EINVAL;
}
static int disjoint(struct md_inode_store *source,int lower,struct md_inode_store *upper,int upperfd,int workfd) {
    if (!upper || !md_inode_lifetime_same(source->lifetime,upper->lifetime)) return 0;
    int r=mdi_begin(source,0);
    if (r) return r;
    struct mdi_node a,b,c;
    r=mdi_fd(source,lower,&a);
    if (!r) r=mdi_fd(source,upperfd,&b);
    if (!r) r=mdi_fd(source,workfd,&c);
    if (!r) {
        int related=mdi_ancestor(source,a.id,b.id);
        if (!related) related=mdi_ancestor(source,b.id,a.id);
        if (!related) related=mdi_ancestor(source,a.id,c.id);
        if (!related) related=mdi_ancestor(source,c.id,a.id);
        if (related) r=related<0 ? related : -EINVAL;
    }
    return mdi_finish(source,r);
}
int md_fs_mount_overlay(struct md_filesystem *fs, const struct md_fs_request *q,
        struct md_mount_source *out) {
    if (q->flags&~MD_FS_MOUNT_FLAGS) return -EOPNOTSUPP;
    if (!q->value || !q->value_size) return -EINVAL;
    char *data=strdup(q->value);
    if (!data) return -ENOMEM;
    struct options options;
    int r=parse(data,&options);
    struct md_inode_store *index=NULL;
    struct md_view_location upper={.fd=-1,.parent=-1},work={.fd=-1,.parent=-1};
    struct md_fs_storage_scope writable={0};
    if (!r && options.upper) {
        r=md_view_walk(fs,AT_FDCWD,NULL,options.upper,1,0,0,&upper);
        if (!r) r=md_view_walk(fs,AT_FDCWD,NULL,options.work,1,0,0,&work);
        if (!r && (!md_view_inode(upper.mount) || !md_view_inode(work.mount)
                || upper.view!=fs->mounts || work.view!=fs->mounts)) r=-EOPNOTSUPP;
        if (!r && (md_view_readonly(upper.mount) || md_view_readonly(work.mount))) r=-EROFS;
        if (!r) r=md_fs_storage_enter(fs,upper.mount,&writable);
        struct md_inode_store *workstore=NULL;
        if (!r) r=md_fs_storage_get(fs,work.mount,&workstore);
        if (!r && !md_inode_lifetime_same(writable.store->lifetime,workstore->lifetime)) r=-EXDEV;
        if (!r) r=md_inode_view_create(writable.store,MD_FILESYSTEM_OVERLAY,&index);
    } else if (!r) {
        int parent=md_fs_private_mounts_parent(fs->store);
        if (parent<0) r=parent;
        else {
            r=md_inode_store_transient(parent,fs->store->identity->user_namespace,&index);
            close(parent);
        }
    }
    for (unsigned i=options.count; !r && i>0; --i) {
        struct md_view_location from={.fd=-1,.parent=-1};
        r=md_view_walk(fs,AT_FDCWD,NULL,options.lower[i-1],1,0,0,&from);
        if (!r && (!md_view_inode(from.mount) || from.view!=fs->mounts)) r=-EOPNOTSUPP;
        struct md_fs_storage_scope scope={0};
        if (!r) r=md_fs_storage_enter(fs,from.mount,&scope);
        if (!r) r=disjoint(scope.store,from.fd,writable.store,upper.fd,work.fd);
        if (!r) r=md_inode_overlay_layer(index,scope.store,from.fd,options.user_xattr);
        md_fs_storage_leave(&scope); md_view_location_close(&from);
    }
    int root=-1;
    if (!r && options.upper) {
        r=md_inode_overlay_prepare_upper(index,writable.store,upper.fd,work.fd,options.user_xattr);
        if (!r) r=md_inode_overlay_activate(index);
    } else if (!r) {
        index->lifetime->filesystem_kind=MD_FILESYSTEM_OVERLAY;
        r=md_inode_store_seal(index);
    }
    if (!r) r=md_inode_overlay_stash(index,fs->store->identity);
    if (!r) {
        root=md_inode_open(index,-1,"/",O_PATH|O_DIRECTORY|O_CLOEXEC,0);
        if (root<0) r=root;
    }
    if (!r) {
        *out=(struct md_mount_source){.fd=root,.backing=MD_MOUNT_INODE,
            .storage=md_inode_lifetime_retain(index->lifetime),
            .policy=md_fs_mount_flags(q->flags|(options.upper ? 0 : MS_RDONLY))};
        root=-1;
    }
    if (root>=0) close(root);
    md_inode_store_close(index);
    md_fs_storage_leave(&writable); md_view_location_close(&upper); md_view_location_close(&work);
    free(data); return r;
}

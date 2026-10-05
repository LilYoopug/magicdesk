#define _GNU_SOURCE
#include "fs_engine.h"
#include "image_catalogue.h"
#include "inode_watch.h"
#include "fs_mount_internal.h"
#include "task_registry.h"
#include "ipc_credentials.h"
#include "inode_internal.h"
#include "linux_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static void change_root(struct md_filesystem *fs, struct md_guest_domain *context,
        const struct md_fs_request *q, struct md_fs_result *out) {
    *out = (struct md_fs_result){.fd = -1};
    if (!context) { out->error = -ENOTSUP; return; }
    if (q->origin[0] && q->origin[0]->view!=fs->mounts && q->directory[0]!=MD_INODE_ROOT
            && (!q->path[0] || q->path[0][0]!='/')) { out->error=-ENOTSUP; return; }
    if (!md_identity_may_chroot(fs->store->identity)) { out->error = -EPERM; return; }
    struct md_fs_request open = *q;
    open.operation = MD_FS_OPEN; open.flags = O_PATH | O_DIRECTORY | O_CLOEXEC;
    struct md_fs_anchor *origin=NULL;
    struct md_fs_output output={.origin=&origin};
    if (md_mount_namespace_attached(fs->mounts) || open.origin[0]) md_fs_mounts_execute(fs, &open, out, &output);
    else md_fs_inode_execute(fs, &open, out, &output);
    if (out->error) return;
    int fd = out->fd; out->fd = -1;
    struct md_fs_location root;
    int error = md_fs_root_capture(fs,fd,origin,&root);
    if (!error) error = md_domain_set_root(context, &root);
    md_fs_anchor_release(origin); close(fd); out->error = error == -EXDEV ? -ENOTSUP : error;
}

void md_fs_stat_info(const struct stat *s, struct md_fs_info *out) {
    *out = (struct md_fs_info){.device = s->st_dev, .inode = s->st_ino, .links = s->st_nlink,
        .rdev = s->st_rdev, .size = s->st_size, .blocks = s->st_blocks, .mode = s->st_mode,
        .uid = s->st_uid, .gid = s->st_gid, .block_size = (uint32_t)s->st_blksize,
        .access_seconds = s->st_atim.tv_sec, .modify_seconds = s->st_mtim.tv_sec,
        .change_seconds = s->st_ctim.tv_sec, .access_nanos = (uint32_t)s->st_atim.tv_nsec,
        .modify_nanos = (uint32_t)s->st_mtim.tv_nsec, .change_nanos = (uint32_t)s->st_ctim.tv_nsec};
}
int md_fs_context_begin(struct md_filesystem *fs, int actor, int peer, struct md_fs_context *context) {
    *context=(struct md_fs_context){0};
    if (!fs || !fs->store) return -EINVAL;
    if (fs->tasks) {
        int error=md_task_registry_read(fs->tasks,actor,peer,&context->task);
        if (error) return error;
        context->authenticated=context->has_identity=1;
    } else if (fs->store->identity) {
        context->task.identity=md_identity_copy(fs->store->identity);
        context->has_identity=1;
    }
    context->filesystem=fs; context->actor=actor; context->peer=peer;
    return 0;
}
void md_fs_context_end(struct md_fs_context *context) {
    md_task_snapshot_release(&context->task);
    *context=(struct md_fs_context){0};
}
void md_fs_execute(struct md_filesystem *fs,
        const struct md_fs_request *q, struct md_fs_result *out, const struct md_fs_output *output) {
    struct md_fs_context context;
    int error=md_fs_context_begin(fs,q->actor,q->peer,&context);
    if (error) {
        if (output && output->origin) *output->origin=NULL;
        *out=(struct md_fs_result){.fd=-1,.error=error}; return;
    }
    md_fs_context_execute(&context,q,out,output);
    md_fs_context_end(&context);
}
void md_fs_context_execute(struct md_fs_context *context,
        const struct md_fs_request *q, struct md_fs_result *out, const struct md_fs_output *output) {
    struct md_filesystem *fs=context->filesystem;
    if (output && output->origin) *output->origin=NULL;
    if (!fs || context->actor!=q->actor || context->peer!=q->peer) {
        *out=(struct md_fs_result){.fd=-1,.error=fs ? -EPERM : -EINVAL}; return;
    }
    if (output && output->origin) {
        if (q->operation!=MD_FS_OPEN && q->operation!=MD_FS_CREATE && q->operation!=MD_FS_REOPEN
                && q->operation!=MD_FS_OPEN_OBJECT && q->operation!=MD_FS_OPEN_IMAGE) {
            *out=(struct md_fs_result){.fd=-1,.error=-EINVAL}; return;
        }
    }
    const struct md_task_snapshot *task=&context->task;
    struct md_identity identity=task->identity;
    const struct md_identity *previous = fs->store->identity;
    if (q->operation == MD_FS_IPC) {
        if (!fs->ipc && fs->ipc_store) {
            int error = md_ipc_credentials_open(fs->ipc_store, &fs->ipc);
            if (error) {
                *out = (struct md_fs_result){.fd=-1,.error=error};
                return;
            }
        }
        md_ipc_credentials_execute(fs->ipc, &identity, q, out, output);
        return;
    }
    if (context->authenticated && !task->mounts) {
        *out=(struct md_fs_result){.fd=-1,.error=-ENOTSUP};
        return;
    }
    if (context->has_identity && q->operation == MD_FS_ACCESS && !(q->flags & MD_AT_EACCESS)) {
        identity.uid.fs = identity.uid.real; identity.gid.fs = identity.gid.real;
        identity.caps.effective = identity.uid.real ? 0 : identity.caps.permitted;
    }
    fs->store->identity = context->has_identity ? &identity : NULL;
    unsigned previous_mask=fs->store->creation_mask;
    const char *previous_root=fs->store->root_id;
    struct md_view_object *previous_native_root=fs->native_root;
    struct md_mount_namespace *previous_mounts=fs->mounts;
    if (context->authenticated) fs->mounts=task->mounts;
    int root_error=context->authenticated ? md_fs_root_select(fs,&task->root) : 0;
    struct md_inode_boundary boundary={.path=output ? output->data : NULL,.capacity=output ? output->capacity : 0};
    struct md_inode_boundary *previous_boundary=fs->store->boundary;
    fs->store->boundary=&boundary;
    fs->store->creation_mask=q->attributes.creation_mask;
    if (root_error) *out=(struct md_fs_result){.fd=-1,.error=root_error};
    else if (q->operation == MD_FS_CHROOT) change_root(fs, task->fs, q, out);
    else if (md_mount_namespace_attached(fs->mounts) || q->origin[0] || q->origin[1]) md_fs_mounts_execute(fs, q, out, output);
    else md_fs_inode_execute(fs, q, out, output);
    fs->store->boundary=previous_boundary;
    if (out->error==-EREMOTE) {
        if (q->operation==MD_FS_CHROOT) out->error=-ENOTSUP;
        else if (q->operation==MD_FS_LINK || q->operation==MD_FS_RENAME) out->error=-EXDEV;
        else if (boundary.path && boundary.capacity) {
            out->error=0; out->host_path=1; out->size=strlen(boundary.path)+1;
        }
    }
    fs->store->creation_mask=previous_mask;
    fs->store->root_id=previous_root;
    fs->native_root=previous_native_root;
    if (context->authenticated) fs->mounts=previous_mounts;
    fs->store->identity = previous;
}
void md_fs_inode_execute(struct md_filesystem *fs,
        const struct md_fs_request *q, struct md_fs_result *out, const struct md_fs_output *output) {
    struct md_inode_store *s = fs->store;
    struct md_image_catalogue *images = fs->images;
    *out = (struct md_fs_result){.fd = -1};
    void *data = output ? output->data : NULL;
    size_t capacity = output ? output->capacity : 0;
    const char *a = q->path[0] ? q->path[0] : "", *b = q->path[1] ? q->path[1] : "";
    int first = q->directory[0], second = q->directory[1];
    int r = -ENOTSUP; struct stat st;
    switch (q->operation) {
    case MD_FS_GETACL: case MD_FS_SETACL: case MD_FS_REMOVEACL:
        md_inode_acl(s,q,out); return;
    case MD_FS_LISTATTR:
        r=md_inode_attributes(s,first,data,capacity);
        if(r>=0) { out->size=(size_t)r; r=0; }
        break;
    case MD_FS_GETCAP: case MD_FS_SETCAP: case MD_FS_REMOVECAP:
        r = md_inode_capability(s, q, data, capacity);
        if (r >= 0) { out->size = (size_t)r; r = 0; }
        break;
    case MD_FS_CHMOD: case MD_FS_CHOWN: case MD_FS_ACCESS: case MD_FS_UTIMENS:
        r = md_inode_metadata(s, q); break;
    case MD_FS_XATTR_OPEN: r = md_inode_xattr_open(s, first, a, (int)q->mode); goto opened;
    case MD_FS_REOPEN: r = md_catalogue_reopen(images, s, first, (int)q->flags, (int)q->mode, &out->open_completion); goto opened;
    case MD_FS_WATCH_CREATE: r = md_inode_watch_create(s, (int)q->flags); goto opened;
    case MD_FS_WATCH_ADD:
        r = md_inode_watch_add(s, first, second, q->flags);
        if (r >= 0) { out->position = r; r = 0; }
        break;
    case MD_FS_WATCH_REMOVE: r = md_inode_watch_remove(s, first, (int)q->flags); break;
    case MD_FS_WATCH_CONTAINS:
        out->position = md_inode_watch_contains(s, first); r = 0; break;
    case MD_FS_WATCH_BYTES:
        r = (int)md_inode_watch_bytes(s, first);
        if (r >= 0) { out->position = r; r = 0; }
        break;
    case MD_FS_WATCH_READ:
        r = (int)md_inode_watch_read(s, first, data, q->capacity < capacity ? q->capacity : capacity,
            output ? output->deliver : NULL, output ? output->context : NULL);
        if (r >= 0) { out->size = (size_t)r; r = 0; }
        break;
    case MD_FS_OPEN_IMAGE: {
        if (!data || capacity < sizeof(struct md_image_identity)) { r = -ERANGE; break; }
        struct md_image_identity *identity = data;
        r = md_catalogue_open_image(images, s, first, a, (int)q->flags, identity);
        if (r >= 0) out->size = offsetof(struct md_image_identity, path) + strlen(identity->path) + 1;
        goto opened;
    }
    case MD_FS_OBJECT_ID:
        if (!data || capacity < 33) { r = -ERANGE; break; }
        r = md_catalogue_object_id(images, s, first, data);
        if (!r) out->size = 33;
        break;
    case MD_FS_OPEN_OBJECT: r = md_catalogue_open_object(images, s, a, (int)q->flags); goto opened;
    case MD_FS_SOCKET_BIND: r = md_inode_socket_bind(s, first, a, q->mode, second); break;
    case MD_FS_SOCKET_ADDRESS: case MD_FS_SOCKET_NAME:
        r = q->operation == MD_FS_SOCKET_ADDRESS
            ? md_inode_socket_address(s, first, a, data, capacity)
            : md_inode_socket_name(s, a, data, capacity);
        if (!r) out->size = strlen(data) + 1;
        break;
    case MD_FS_CREATE: r = md_inode_create(s, first, a, q->mode); goto opened;
    case MD_FS_OPEN: r = md_catalogue_open(images, s, first, a, (int)q->flags, q->mode, q->resolve, &out->open_completion); goto opened;
    case MD_FS_MKDIR: r = md_inode_mkdir(s, first, a, q->mode); break;
    case MD_FS_MKFIFO: r = md_inode_mkfifo(s, first, a, q->mode); break;
    case MD_FS_SYMLINK: r = md_inode_symlink(s, b, first, a); break;
    case MD_FS_LINK: r = md_inode_link(s, first, a, second, b, (int)q->flags); break;
    case MD_FS_UNLINK: r = md_inode_unlink(s, first, a, (int)q->flags); break;
    case MD_FS_RENAME: r = md_inode_rename(s, first, a, second, b, q->flags); break;
    case MD_FS_STAT: case MD_FS_FSTAT: {
        if (q->mode & ~MD_FS_STAT_MOUNT) { r=-EINVAL; break; }
        char path[PATH_MAX];
        char *previous=s->stat_path;
        if (q->mode & MD_FS_STAT_MOUNT) { path[0]=0; s->stat_path=path; }
        r = q->operation == MD_FS_STAT ? md_catalogue_stat(images, s, first, a, (int)q->flags, &st)
            : md_catalogue_fstat(images, s, first, &st);
        s->stat_path=previous;
        if (!r) md_fs_stat_info(&st, &out->info);
        if (!r && (q->mode & MD_FS_STAT_MOUNT) && *path)
            r=md_fs_base_mount(fs,!strncmp(path,"/dev/shm",8) && (!path[8] || path[8]=='/'),
                &out->info.mount_id);
        break;
    }
    case MD_FS_PATH:
        r = md_catalogue_path(images, s, first, data, capacity);
        if (!r) out->size = strlen(data) + 1;
        break;
    case MD_FS_REALPATH:
        r = md_inode_realpath(s, first, a, data, capacity);
        if (!r) out->size = strlen(data) + 1;
        break;
    case MD_FS_TEMPORARY: r = md_inode_temporary(s); goto opened;
    case MD_FS_MOUNT_TABLE: r = md_fs_mount_table(fs,q->flags); goto opened;
    case MD_FS_NATIVE_MOUNT:
        r=md_fs_native_mount(fs,(uint64_t)q->offset,&out->info.mount_id); break;
    case MD_FS_READLINK:
        r = (int)md_inode_readlink(s, first, a, data, capacity);
        if (r >= 0) { out->size = (size_t)r; r = 0; }
        break;
    case MD_FS_GETDENTS:
        r = (int)md_inode_getdents_deliver(s, first, data, q->capacity < capacity ? q->capacity : capacity,
            output ? output->deliver : NULL, output ? output->context : NULL);
        if (r >= 0) { out->size = (size_t)r; r = 0; }
        break;
    case MD_FS_SEEKDIR: {
        int64_t position = md_inode_seekdir(s, first, q->offset, (int)q->flags);
        if (position < 0) r = (int)position;
        else { out->position = position; r = 0; }
        break;
    }
    }
    out->error = r;
    return;
opened:
    if (r < 0) out->error = r;
    else {
        out->fd = r;
        md_view_capture(fs,fs->mounts,NULL,out,output);
    }
}

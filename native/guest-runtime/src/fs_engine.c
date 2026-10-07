#define _GNU_SOURCE
#include "fs_engine.h"
#include "image_catalogue.h"
#include "inode_watch.h"
#include "fs_mount_internal.h"
#include "mount_graph.h"
#include "fs_storage.h"
#include "task_registry.h"
#include "ipc_credentials.h"
#include "inode_internal.h"
#include "linux_abi.h"
#include "task_status.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <unistd.h>

void md_fs_view_execute(struct md_filesystem *fs, const struct md_fs_request *q,
        struct md_fs_result *out, const struct md_fs_output *output) {
    if (md_mount_namespace_attached(fs->mounts) || q->origin[0] || q->origin[1])
        md_fs_mounts_execute(fs,q,out,output);
    else md_fs_inode_execute(fs,q,out,output);
}
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
    md_fs_view_execute(fs,&open,out,&output);
    if (out->error) return;
    int fd = out->fd; out->fd = -1;
    struct md_fs_location root;
    int error = md_fs_root_capture(fs,fd,origin,&root);
    if (!error) error = md_domain_set_root(context, &root);
    md_fs_anchor_release(origin); close(fd); out->error = error == -EXDEV ? -ENOTSUP : error;
}
static int watch_add(struct md_filesystem *fs, int instance, int object,
        const struct md_fs_anchor *origin, unsigned flags) {
    struct md_view_mount *mount=origin ? origin->mount : NULL;
    if (origin) {
        int r=md_view_anchor_check(fs,object,origin);
        if (r) return r;
    } else {
        struct md_view_object *entry=NULL;
        int r=md_view_identity(fs,object,&entry);
        if (r && r!=-EXDEV) return r;
        if (!r) mount=entry->mount;
    }
    if (!md_view_inode(mount)) return md_inode_watch_add(fs->store,instance,object,flags);
    struct md_fs_storage_scope scope;
    int r=md_fs_storage_enter(fs,mount,&scope);
    if (!r) {
        r=md_inode_watch_add_from(fs->store,scope.store,instance,object,flags);
        md_fs_storage_leave(&scope);
    }
    return r;
}
static void watch_path(struct md_filesystem *fs, const struct md_fs_request *q,
        struct md_fs_result *out, const struct md_fs_output *output) {
    struct md_fs_request open=*q;
    open.operation=MD_FS_OPEN; open.flags=O_PATH|O_CLOEXEC|(q->flags&IN_DONT_FOLLOW ? O_NOFOLLOW : 0);
    open.directory[1]=-1; open.origin[1]=NULL;
    struct md_fs_anchor *origin=NULL;
    struct md_fs_output capture=output ? *output : (struct md_fs_output){0};
    capture.origin=fs->mounts ? &origin : NULL;
    md_fs_view_execute(fs,&open,out,&capture);
    if (out->error) { md_fs_anchor_release(origin); return; }
    int fd=out->fd; out->fd=-1;
    int wd=watch_add(fs,q->directory[1],fd,origin,q->flags);
    close(fd);
    md_fs_anchor_release(origin);
    if (wd<0) out->error=wd; else out->position=wd;
}
static void task_path(struct md_filesystem *fs, const struct md_fs_request *q,
        struct md_fs_result *out, const struct md_fs_output *output) {
    int directory=q->mode==MD_FS_TASK_CHDIR || q->mode==MD_FS_TASK_FCHDIR;
    struct md_fs_request open=*q;
    open.operation=MD_FS_OPEN; open.mode=0; open.offset=0;
    open.flags=O_PATH|O_CLOEXEC|(directory ? O_DIRECTORY : 0);
    if (!q->path[0] || !*q->path[0]) {
        open.operation=MD_FS_REOPEN; open.mode=MD_FS_REOPEN_NATIVE;
    }
    struct md_fs_anchor *origin=NULL;
    struct md_fs_output capture=output ? *output : (struct md_fs_output){0};
    capture.origin=fs->mounts || (output && output->origin) ? &origin : NULL;
    md_fs_view_execute(fs,&open,out,&capture);
    if (out->error) return;
    int fd=out->fd; out->fd=-1;
    struct md_fs_request selected={.operation=MD_FS_ACCESS,.directory={fd,-1},
        .origin={origin,NULL},.mode=directory ? X_OK : W_OK,.flags=MD_AT_EACCESS};
    md_fs_view_execute(fs,&selected,out,NULL);
    if (out->error==-EXDEV)
        out->error=syscall(SYS_faccessat2,fd,"",selected.mode,AT_EMPTY_PATH|MD_AT_EACCESS) ? -errno : 0;
    if (!out->error && !directory) {
        struct stat st;
        if (fstat(fd,&st)) out->error=-errno;
        else if (!S_ISREG(st.st_mode)) out->error=S_ISDIR(st.st_mode) ? -EISDIR : -EINVAL;
        if (!out->error) {
            selected.operation=MD_FS_REOPEN; selected.mode=MD_FS_REOPEN_NATIVE; selected.flags=O_WRONLY|O_CLOEXEC;
            md_fs_view_execute(fs,&selected,out,output);
        }
    } else if (!out->error) {
        out->fd=fd; fd=-1;
        if (output && output->origin) { *output->origin=origin; origin=NULL; }
    }
    if (fd>=0) close(fd);
    md_fs_anchor_release(origin);
}

void md_fs_stat_info(const struct stat *s, struct md_fs_info *out) {
    *out = (struct md_fs_info){.device = s->st_dev, .inode = s->st_ino, .links = s->st_nlink,
        .rdev = s->st_rdev, .size = s->st_size, .blocks = s->st_blocks, .mode = s->st_mode,
        .uid = s->st_uid, .gid = s->st_gid, .block_size = (uint32_t)s->st_blksize,
        .access_seconds = s->st_atim.tv_sec, .modify_seconds = s->st_mtim.tv_sec,
        .change_seconds = s->st_ctim.tv_sec, .access_nanos = (uint32_t)s->st_atim.tv_nsec,
        .modify_nanos = (uint32_t)s->st_mtim.tv_nsec, .change_nanos = (uint32_t)s->st_ctim.tv_nsec};
}
void md_fs_statfs_result(int fd, struct md_fs_result *out, const struct md_fs_output *output) {
    if (!output || !output->data || output->capacity<sizeof(struct md_fs_statfs)) {
        out->error=-ERANGE; return;
    }
    struct statfs native;
    if (fstatfs(fd,&native)) { out->error=-errno; return; }
    struct md_fs_statfs value={.type=native.f_type,.block_size=native.f_bsize,
        .blocks=native.f_blocks,.free_blocks=native.f_bfree,.available_blocks=native.f_bavail,
        .files=native.f_files,.free_files=native.f_ffree,.name_length=native.f_namelen,
        .fragment_size=native.f_frsize,.flags=native.f_flags};
    _Static_assert(sizeof(value.fsid)==sizeof(native.f_fsid),"statfs filesystem identity");
    memcpy(value.fsid,&native.f_fsid,sizeof(value.fsid));
    memcpy(output->data,&value,sizeof(value)); out->size=sizeof(value);
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
void md_fs_context_capture_result(struct md_fs_context *context, struct md_fs_result *result,
        struct md_fs_anchor **origin) {
    struct md_fs_output output={.origin=origin};
    md_view_capture(context->filesystem,context->authenticated ? context->task.mounts
        : context->filesystem->mounts,NULL,result,&output);
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
int md_fs_ipc_authority(struct md_filesystem *fs, struct md_ipc_credentials **out) {
    if (!fs || !out) return -EINVAL;
    if (!fs->ipc) {
        if (!fs->ipc_store) return -ENOTSUP;
        int error=md_ipc_credentials_open(fs->ipc_store,MD_IPC_TRANSPORT_ORIGINS_V1,&fs->ipc);
        if (error) return error;
    }
    *out=fs->ipc; return 0;
}
static void context_execute(struct md_fs_context *context,
        const struct md_fs_request *q, struct md_fs_result *out, const struct md_fs_output *output) {
    struct md_filesystem *fs=context->filesystem;
    if (output && output->origin) *output->origin=NULL;
    if (!fs || context->actor!=q->actor || context->peer!=q->peer) {
        *out=(struct md_fs_result){.fd=-1,.error=fs ? -EPERM : -EINVAL}; return;
    }
    if (output && output->origin) {
        if (!md_fs_operation_has_origin(q->operation)) {
            *out=(struct md_fs_result){.fd=-1,.error=-EINVAL}; return;
        }
    }
    if (q->operation==MD_FS_UMASK) {
        long mask=md_task_umask(context->actor);
        *out=(struct md_fs_result){.fd=-1,.error=mask<0 ? (int)mask : 0,
            .position=mask<0 ? 0 : mask};
        return;
    }
    const struct md_task_snapshot *task=&context->task;
    struct md_identity identity=task->identity;
    const struct md_identity *previous = fs->store->identity;
    if (q->operation == MD_FS_IPC || q->operation==MD_FS_IPC_PEER) {
        struct md_ipc_credentials *ipc=NULL;
        int error=md_fs_ipc_authority(fs,&ipc);
        if (error) *out=(struct md_fs_result){.fd=-1,.error=error};
        else md_ipc_credentials_execute(ipc, &identity, q, out, output);
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
    int root_error=md_mount_graph_sync(fs->mounts);
    for (unsigned i=0;!root_error && i<2;++i)
        if (q->origin[i] && q->origin[i]->view!=fs->mounts)
            root_error=md_mount_graph_sync(q->origin[i]->view);
    if (!root_error && context->authenticated) root_error=md_fs_root_select(fs,&task->root);
    struct md_inode_boundary boundary={.path=output ? output->data : NULL,.capacity=output ? output->capacity : 0};
    struct md_inode_boundary *previous_boundary=fs->store->boundary;
    fs->store->boundary=&boundary;
    fs->store->creation_mask=q->attributes.creation_mask;
    if (root_error) *out=(struct md_fs_result){.fd=-1,.error=root_error};
    else if (q->operation == MD_FS_CHROOT) change_root(fs, task->fs, q, out);
    else if (q->operation==MD_FS_MOUNT)
        *out=(struct md_fs_result){.fd=-1,.error=md_fs_mount_change(fs,task->fs,q)};
    else if (q->operation == MD_FS_WATCH_PATH) watch_path(fs,q,out,output);
    else if (q->operation == MD_FS_WATCH_ADD) {
        int wd=watch_add(fs,q->directory[0],q->directory[1],q->origin[1],q->flags);
        *out=(struct md_fs_result){.fd=-1,.error=wd<0 ? wd : 0,.position=wd<0 ? 0 : wd};
    }
    else if (q->operation == MD_FS_TASK_PATH) task_path(fs,q,out,output);
    else if (q->operation==MD_FS_XATTR || q->operation==MD_FS_FXATTR) md_fs_xattr(fs,q,out,output);
    else md_fs_view_execute(fs,q,out,output);
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
static void object_execute(struct md_fs_context *context, const struct md_fs_request *q,
        struct md_fs_result *out, const struct md_fs_output *output) {
    struct md_fs_request captured=*q;
    struct md_fs_anchor *origins[2]={NULL,NULL};
    int descriptors[2]={-1,-1};
    int error=context->filesystem ? md_fs_request_validate(q) : -EINVAL;
    for (unsigned i=0;i<2 && !error;++i) if (q->object[i]) {
        struct md_fs_request open={.actor=q->actor,.peer=q->peer,.operation=MD_FS_OPEN_OBJECT,
            .directory={-1,-1},.path={q->object[i],NULL},.flags=O_PATH|O_CLOEXEC};
        struct md_fs_output source={.origin=(context->authenticated ? context->task.mounts
            : context->filesystem->mounts) ? &origins[i] : NULL};
        struct md_fs_result result;
        context_execute(context,&open,&result,&source);
        descriptors[i]=result.fd;
        error=result.error;
        if (!error && (result.fd<0 || result.open_completion.kind || result.host_path)) error=-EPROTO;
        captured.directory[i]=result.fd; captured.origin[i]=origins[i]; captured.object[i]=NULL;
    }
    if (!error) context_execute(context,&captured,out,output);
    else {
        if (output && output->origin) *output->origin=NULL;
        *out=(struct md_fs_result){.fd=-1,.error=error};
    }
    for (unsigned i=0;i<2;++i) {
        md_fs_anchor_release(origins[i]);
        if (descriptors[i]>=0) close(descriptors[i]);
    }
}
void md_fs_context_execute(struct md_fs_context *context,
        const struct md_fs_request *q, struct md_fs_result *out, const struct md_fs_output *output) {
    if (q->capture[0].path || q->capture[1].path) {
        *out=(struct md_fs_result){.fd=-1,.error=-EINVAL}; return;
    }
    struct md_filesystem *fs=context->filesystem;
    struct md_cost *cost=fs && fs->statistics && q->operation<=MD_FS_LAST
        ? &fs->statistics->operation[q->operation] : NULL;
    int64_t begin=md_cost_begin(cost);
    if (q->object[0] || q->object[1]) object_execute(context,q,out,output);
    else context_execute(context,q,out,output);
    md_cost_end(cost,begin);
}
static void inode_execute(struct md_filesystem *fs,
        const struct md_fs_request *q, struct md_fs_result *out, const struct md_fs_output *output) {
    struct md_inode_store *s = fs->selected_store ? fs->selected_store : fs->store;
    struct md_image_catalogue *images = s==fs->store ? fs->images : NULL;
    *out = (struct md_fs_result){.fd = -1};
    void *data = output ? output->data : NULL;
    size_t capacity = output ? output->capacity : 0;
    const char *a = q->path[0] ? q->path[0] : "", *b = q->path[1] ? q->path[1] : "";
    int first = q->directory[0], second = q->directory[1];
    int r = -ENOTSUP; struct stat st;
    switch (q->operation) {
    case MD_FS_GETACL: case MD_FS_SETACL: case MD_FS_REMOVEACL:
        md_inode_acl(s,q,out,output); return;
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
    case MD_FS_REOPEN:
        r=md_catalogue_reopen(images,s,first,(int)q->flags,!!(q->mode&MD_FS_REOPEN_MUTABLE),&out->open_completion);
        if (r==-EXDEV && (q->mode&MD_FS_REOPEN_NATIVE))
            r=md_reopen_file(first,(int)q->flags,&out->open_completion);
        goto opened;
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
        r = output && output->reserve_watch
            ? (int)md_inode_watch_reserve(s, first, data, q->capacity < capacity ? q->capacity : capacity)
            : (int)md_inode_watch_read(s, first, data, q->capacity < capacity ? q->capacity : capacity,
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
    case MD_FS_MKNOD:
        if ((q->mode&S_IFMT)==S_IFIFO) r=md_inode_mkfifo(s,first,a,q->mode&07777);
        else {
            r=md_inode_create(s,first,a,q->mode&07777);
            if (r>=0) { close(r); r=0; }
        }
        break;
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
        if (!r && (q->mode & MD_FS_STAT_MOUNT) && fs->inode_mount)
            out->info.mount_id=fs->inode_mount->id;
        else if (!r && (q->mode & MD_FS_STAT_MOUNT) && *path)
            r=md_fs_base_mount(fs,!strncmp(path,"/dev/shm",8) && (!path[8] || path[8]=='/'),
                &out->info.mount_id);
        break;
    }
    case MD_FS_STATFS: {
        int fd=*a ? md_inode_open(s,first,a,O_PATH|O_CLOEXEC,0) : first;
        if (fd<0) out->error=fd;
        else { md_fs_statfs_result(fd,out,output); if (*a) close(fd); }
        return;
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
    case MD_FS_MOUNT_TABLE: r = md_fs_mount_table(fs,q->mode,q->flags); goto opened;
    case MD_FS_NATIVE_MOUNT:
        r=md_fs_native_mount(fs,(uint64_t)q->offset,&out->info.mount_id); break;
    case MD_FS_READLINK:
        r = (int)md_inode_readlink(s, first, a, data, capacity);
        if (r >= 0) { out->size = (size_t)r; r = 0; }
        break;
    case MD_FS_GETDENTS:
        r = output && output->directory_position
            ? (int)md_inode_getdents_prepare(s,first,data,q->capacity < capacity ? q->capacity : capacity,output->directory_position)
            : (int)md_inode_getdents_deliver(s, first, data, q->capacity < capacity ? q->capacity : capacity,
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
        md_view_capture(fs,fs->mounts,fs->inode_mount,out,output);
    }
}
void md_fs_inode_execute(struct md_filesystem *fs, const struct md_fs_request *q,
        struct md_fs_result *out, const struct md_fs_output *output) {
    struct md_inode_store *store=fs->selected_store ? fs->selected_store : fs->store;
    int readonly=store->readonly;
    if (fs->mounts && (fs->inode_mount ? md_view_readonly(fs->inode_mount)
            : (md_mount_policy_flags(&fs->mounts->base.policy)&MD_MOUNT_READONLY))) store->readonly=1;
    inode_execute(fs,q,out,output);
    store->readonly=readonly;
}

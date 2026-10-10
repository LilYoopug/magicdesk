#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include "fs_storage.h"
#include "procfs_view.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void md_view_location_close(struct md_view_location *p) {
    if (p->parent >= 0) close(p->parent);
    if (p->fd >= 0) close(p->fd);
    p->parent = p->fd = -1;
}
static int duplicate(int fd) { int copy = fcntl(fd, F_DUPFD_CLOEXEC, 3); return copy < 0 ? -errno : copy; }
int md_view_descriptor(struct md_filesystem *fs, int fd, const struct md_fs_anchor *origin,
        struct md_view_location *out) {
    *out=(struct md_view_location){.parent=-1,.fd=-1};
    int r=origin ? md_view_anchor_check(fs,fd,origin) : 0;
    if (r) return r;
    struct md_mount_namespace *view=origin ? origin->view : fs->mounts;
    struct md_view_mount *mount=origin ? origin->mount : view ? &view->base : NULL;
    if (!origin) {
        struct md_view_object *object=NULL;
        r=md_view_identity(fs,fd,&object);
        if (!r) mount=object->mount;
        else if (r==-EXDEV) {
            char id[33];
            r=md_inode_object_id(fs->store,fd,id);
        }
    }
    if (r) return r;
    out->fd=duplicate(fd);
    if (out->fd<0) { r=out->fd; out->fd=-1; return r; }
    out->view=view; out->mount=mount;
    return 0;
}
int md_view_task_path(struct md_filesystem *fs, int fd, const char *name, const char *tail,
        uint64_t resolve, int native_devices) {
    struct md_inode_boundary *boundary=fs->store->boundary;
    if (!boundary || !boundary->path) return 0;
    char path[PATH_MAX];
    int r=md_view_fdpath(fd,path,sizeof(path));
    if (r) return r;
    int proc=!strncmp(path,"/proc",5) && (!path[5] || path[5]=='/');
    int device=native_devices && !strncmp(path,"/dev",4) && (!path[4] || path[4]=='/');
    if (!proc && !device) return 0;
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    if (!S_ISDIR(st.st_mode)) return -ENOTDIR;
    if (resolve&(RESOLVE_BENEATH|RESOLVE_IN_ROOT|RESOLVE_NO_XDEV)) return -EXDEV;
    if (resolve&(RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS)) return -ENOTSUP;
    int n=snprintf(boundary->path,boundary->capacity,"%s/%s%s",path,name,tail);
    return n<0 || (size_t)n>=boundary->capacity ? -ENAMETOOLONG : -EREMOTE;
}
static int component(struct md_filesystem *fs, struct md_mount_namespace *view,
        struct md_view_mount *mount, int fd, const char *name, int provider_source) {
    if (mount && mount->provider) return md_provider_tree_step(mount->provider,fd,name);
    if (md_view_inode(mount)) {
        struct md_fs_storage_scope scope;
        int r=md_fs_storage_enter(fs,mount,&scope);
        if (r) return r;
        if (provider_source && scope.store==fs->store) scope.store->boundary=scope.boundary;
        if (view!=fs->mounts) scope.store->root_id=NULL;
        int next=md_inode_open(scope.store,fd,name,O_PATH|O_NOFOLLOW|O_CLOEXEC,0);
        md_fs_storage_leave(&scope);
        return next;
    }
    int next = openat(fd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    return next < 0 ? -errno : next;
}
static int enter(struct md_mount_namespace *view, int *fd, struct md_view_mount **mount, uint64_t resolve) {
    struct md_fs_mounts *tree = view ? view->tree : NULL;
    if (!tree) return 0;
    struct stat st;
    if (fstat(*fd, &st)) return -errno;
    for (unsigned i = 0; i <= tree->count; ++i) {
        struct md_view_mount *m = i ? &tree->mounts[i-1] : &view->base;
        if (m->source<0) continue;
        if (m->detached || m->parent != *mount || !md_view_same(&st, &m->guest)) continue;
        if (resolve & RESOLVE_NO_XDEV) return -EXDEV;
        int copy = duplicate(m->source);
        if (copy < 0) return copy;
        close(*fd); *fd = copy; *mount = m;
        return enter(view,fd,mount,resolve);
    }
    return 0;
}
static int parent(struct md_filesystem *fs, struct md_mount_namespace *view,
        struct md_view_mount **mount, int fd, uint64_t resolve) {
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    /* A stack can contain several mounted roots at the same dentry. Leave all
     * of them before taking one directory step; never use a source's parent. */
    while (*mount && md_view_same(&st,&(*mount)->native)) {
        if (view && *mount==view->root) return duplicate(fd);
        if (fs->native_root && view==fs->mounts && *mount==fs->native_root->mount
                && md_view_same(&st,&fs->native_root->identity)) return duplicate(fd);
        if ((*mount)->detached) return duplicate(fd);
        if (resolve&RESOLVE_NO_XDEV) return -EXDEV;
        fd=(*mount)->target; st=(*mount)->guest; *mount=(*mount)->parent;
    }
    return component(fs,view,*mount,fd,"..",0);
}
int md_view_walk(struct md_filesystem *fs, int base, const struct md_fs_anchor *origin,
        const char *path, int follow, int missing,
        uint64_t resolve, struct md_view_location *out) {
    *out = (struct md_view_location){.parent=-1,.fd=-1};
    if (!path || !*path) return -ENOENT;
    if (resolve & ~(RESOLVE_BENEATH | RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV | RESOLVE_CACHED | MD_VIEW_TASK_PATH | MD_VIEW_PROVIDER_SOURCE | MD_VIEW_MOUNT_TARGET)) return -EINVAL;
    if ((resolve & (RESOLVE_BENEATH | RESOLVE_IN_ROOT)) == (RESOLVE_BENEATH | RESOLVE_IN_ROOT)) return -EINVAL;
    if (resolve & RESOLVE_CACHED) return -EAGAIN;
    if (path[0] == '/' && (resolve & RESOLVE_BENEATH)) return -EXDEV;
    if (strlen(path) >= PATH_MAX) return -ENAMETOOLONG;
    char todo[PATH_MAX]; strcpy(todo, path);
    int from_root = base == MD_INODE_ROOT || (path[0] == '/' && !(resolve & RESOLVE_IN_ROOT));
    /* A native proc descriptor predates or bypasses logical mounts. Its kernel
     * inode cannot select one of several proc mounts with different PID views.
     * Logical opens retain an origin; only those enter a mounted proc view. */
    if (!from_root && !origin && (resolve&MD_VIEW_TASK_PATH)) {
        int native=md_view_task_path(fs,base,path,"",resolve,0);
        if (native) return native;
    }
    int r = !from_root && origin ? md_view_anchor_check(fs,base,origin) : 0;
    if (r) return r;
    int fd = from_root ? md_view_root_fd(fs) : duplicate(base);
    if (fd < 0) return fd;
    struct md_mount_namespace *view = !from_root && origin ? origin->view : fs->mounts;
    struct md_view_mount *mount = view ? &view->base : NULL;
    if (from_root) mount=md_view_root_mount(fs);
    else if (origin) mount=origin->mount;
    else {
        struct md_view_object *object = NULL;
        r = md_view_identity(fs, fd, &object);
        if (!r) mount=object->mount;
        if (r == -EXDEV) r = 0;
    }
    if (!r && from_root && !fs->native_root) r = enter(view, &fd, &mount, resolve);
    int boundary_fd = !r ? duplicate(fd) : -1;
    struct md_view_mount *boundary_mount = mount;
    struct md_mount_namespace *boundary_view = view;
    if (!r && boundary_fd < 0) r = boundary_fd;
    struct stat boundary;
    if (!r && fstat(boundary_fd, &boundary)) r = -errno;
    unsigned links = 0;
    while (!r) {
        struct stat current;
        if (fstat(fd, &current)) { r = -errno; break; }
        if (!S_ISDIR(current.st_mode)) { r = -ENOTDIR; break; }
        char *start = todo; while (*start == '/') ++start;
        if (!*start) { out->parent = duplicate(fd); out->fd = fd; fd = -1; out->view = view; out->mount = mount; strcpy(out->name, "."); r = out->parent < 0 ? out->parent : 0; break; }
        char *end = start; while (*end && *end != '/') ++end;
        size_t length = (size_t)(end-start);
        if (length > NAME_MAX) { r = -ENAMETOOLONG; break; }
        char name[NAME_MAX+1]; memcpy(name, start, length); name[length] = 0;
        int trailing = *end == '/';
        memmove(todo, end, strlen(end)+1);
        char *rest = todo; while (*rest == '/') ++rest;
        int last = !*rest, next = -1;
        struct md_view_mount *next_mount = mount;
        if (!strcmp(name, "..") && (resolve & (RESOLVE_BENEATH | RESOLVE_IN_ROOT)) && view == boundary_view && mount == boundary_mount && md_view_same(&current, &boundary)) {
            if (resolve & RESOLVE_BENEATH) { r = -EXDEV; break; }
            next = duplicate(fd);
        } else if (!strcmp(name,"..") && fs->native_root && view==fs->mounts && mount==fs->native_root->mount
                && md_view_same(&current,&fs->native_root->identity)) {
            next = duplicate(fd);
        } else if (!strcmp(name, "..") && mount && md_view_same(&current, &mount->native)) {
            next = parent(fs,view,&next_mount,fd,resolve);
        } else if (md_view_inode(mount)) {
            /* The component walker must retain the unconsumed suffix when a
             * logical path crosses into a task-owned host filesystem. */
            struct md_inode_boundary *boundary=fs->store->boundary;
            const char *previous_suffix=boundary ? boundary->suffix : NULL;
            if (boundary) boundary->suffix=todo;
            next = component(fs, view, mount, fd, name,!!(resolve&MD_VIEW_PROVIDER_SOURCE));
            if (boundary) boundary->suffix=previous_suffix;
            int placement=last && (resolve&MD_VIEW_MOUNT_TARGET);
            if (next==-EREMOTE && view && (view->tree || placement)) {
                /* An explicit mount covers the initial filesystem's implicit
                 * proc/dev provider. Resolve only its covered dentry here;
                 * an ordinary root bind must retain the provider fallback. */
                fs->store->boundary=NULL;
                int covered=component(fs,view,mount,fd,name,0);
                fs->store->boundary=boundary;
                if (covered>=0) {
                    int entered=enter(view,&covered,&next_mount,resolve);
                    if (entered) { close(covered); next=entered; }
                    else if (next_mount!=mount || placement) next=covered;
                    else close(covered);
                }
            }
            /* Entering an admitted native mount root is not an escape or a
             * magic-link traversal. Delegating an unresolved suffix would be;
             * retain the stricter failure until its walker owns that scope. */
            if (next==-EREMOTE && ((resolve&RESOLVE_NO_XDEV)
                    || ((!boundary || (!boundary->mount_root && !boundary->native_directory))
                        && (resolve&(RESOLVE_IN_ROOT|RESOLVE_BENEATH))))) next=-EXDEV;
            if (next==-EREMOTE && (!boundary || (!boundary->mount_root && !boundary->native_directory))
                    && (resolve&(RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS))) next=-ENOTSUP;
        }
        else {
            if (mount && mount->backing==MD_MOUNT_PROC)
                next=md_procfs_step(fs,mount,fd,name,todo,!last || follow>0 || (trailing && follow==0));
            else if (mount && mount->backing==MD_MOUNT_DEVPTS)
                next=md_devpts_step(mount->devpts,fd,name);
            else {
                next=(resolve&MD_VIEW_TASK_PATH) ? md_view_task_path(fs,fd,name,todo,resolve,0) : 0;
                if (!next) next=component(fs,view,mount,fd,name,0);
            }
        }
        if (next == -ENOENT && last && missing && (!trailing || missing > 1)) {
            out->parent = fd; fd = -1; out->view = view; out->mount = mount; strcpy(out->name, name); break;
        }
        if (next < 0) { r = next; break; }
        struct stat st;
        if (fstat(next, &st)) { r = -errno; close(next); break; }
        if (S_ISLNK(st.st_mode) && (!last || follow > 0 || (trailing && follow == 0))) {
            if (++links > 40 || (resolve & RESOLVE_NO_SYMLINKS)) { close(next); r = -ELOOP; break; }
            char target[PATH_MAX];
            ssize_t n = readlinkat(next, "", target, sizeof(target)); close(next);
            if (n < 0) { r = -errno; break; }
            size_t rest_size = strlen(todo);
            if (!n) { r = -ENOENT; break; }
            if ((size_t)n + rest_size >= sizeof(target)) { r = -ENAMETOOLONG; break; }
            memcpy(target+n, todo, rest_size+1); strcpy(todo, target);
            if (target[0] == '/') {
                if (resolve & RESOLVE_BENEATH) { r = -EXDEV; break; }
                struct md_mount_namespace *root_view = resolve & RESOLVE_IN_ROOT ? boundary_view : fs->mounts;
                struct md_view_mount *root_mount = resolve & RESOLVE_IN_ROOT ? boundary_mount
                    : md_view_root_mount(fs);
                if ((resolve & RESOLVE_NO_XDEV) && (view!=root_view || mount!=root_mount)) { r=-EXDEV; break; }
                close(fd);
                fd = resolve & RESOLVE_IN_ROOT ? duplicate(boundary_fd) : md_view_root_fd(fs);
                view=root_view; mount=root_mount;
                if (fd < 0) r = fd;
                else if (!(resolve&RESOLVE_IN_ROOT) && !fs->native_root) r=enter(view,&fd,&mount,resolve);
            }
            continue;
        }
        if (strcmp(name,".")) r = enter(view, &next, &next_mount, resolve);
        if (!r && (!last || trailing) && !S_ISDIR(st.st_mode)) r = -ENOTDIR;
        if (r) { close(next); break; }
        if (last) {
            out->boundary = next_mount != mount;
            /* A mount root is materialized by its source FD, never its covered dentry. */
            if (out->boundary || !strcmp(name, "..")) {
                close(fd); fd = duplicate(next); strcpy(name, ".");
                if (fd < 0) { r = fd; close(next); break; }
            }
            out->parent = fd; fd = -1; out->fd = next; out->view = view; out->mount = next_mount; strcpy(out->name, name); break;
        }
        close(fd); fd = next; mount = next_mount;
    }
    if (fd >= 0) close(fd);
    if (boundary_fd >= 0) close(boundary_fd);
    if (r) md_view_location_close(out);
    return r;
}

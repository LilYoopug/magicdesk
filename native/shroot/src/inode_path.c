#define _GNU_SOURCE
#include "inode_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

int mdi_host_boundary(struct md_inode_store *s, const char *parent, const char *name, const char *tail, uint64_t resolve) {
    if (!s->boundary || strcmp(mdi_root(s),s->lifetime->scope)
            || strcmp(parent,s->lifetime->scope)) return 0;
    if (strcmp(name,"proc") && strcmp(name,"dev")) return 0;
    const char *suffix=s->boundary->suffix ? s->boundary->suffix : "";
    const char *next=*tail ? tail : suffix; while (*next=='/') ++next;
    if (!strcmp(name,"dev") && !strncmp(next,"shm",3) && (!next[3] || next[3]=='/')) return 0;
    s->boundary->mount_root=!*next;
    s->boundary->native_directory=!strcmp(name,"dev");
    if ((resolve&RESOLVE_NO_XDEV) || (*next && !s->boundary->native_directory
            && (resolve&(RESOLVE_IN_ROOT|RESOLVE_BENEATH)))) return -EXDEV;
    if (*next && !s->boundary->native_directory && (resolve&(RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS))) return -ENOTSUP;
    if (!s->boundary->path) return -EREMOTE;
    int n=snprintf(s->boundary->path,s->boundary->capacity,"/%s%s%s",name,tail,suffix);
    return n<0 || (size_t)n>=s->boundary->capacity ? -ENAMETOOLONG : -EREMOTE;
}

int mdi_walk(struct md_inode_store *s, int dirfd, const char *path,
        enum mdi_follow follow, int missing, struct mdi_location *out) {
    return mdi_walk_resolved(s, dirfd, path, follow, missing, 0, out);
}
int mdi_walk_resolved(struct md_inode_store *s, int dirfd, const char *path,
        enum mdi_follow follow, int missing, uint64_t resolve, struct mdi_location *out) {
    if (resolve & ~(RESOLVE_BENEATH | RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS |
            RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV | RESOLVE_CACHED)) return -EINVAL;
    if ((resolve & (RESOLVE_BENEATH | RESOLVE_IN_ROOT)) == (RESOLVE_BENEATH | RESOLVE_IN_ROOT))
        return -EINVAL;
    /* The metadata service performs IO; it cannot promise a cache-only walk. */
    if (resolve & RESOLVE_CACHED) return -EAGAIN;
    if (!path) return -EFAULT;
    if (!*path) return -ENOENT;
    if (*path == '/' && (resolve & RESOLVE_BENEATH)) return -EXDEV;
    size_t length = strnlen(path, PATH_MAX);
    if (length == PATH_MAX) return -ENAMETOOLONG;
    char todo[PATH_MAX]; memcpy(todo, path, length+1);
    struct mdi_node current;
    int r = (path[0] == '/' && !(resolve & RESOLVE_IN_ROOT)) || dirfd == MD_INODE_ROOT
        ? mdi_node(s, mdi_root(s), &current) : mdi_fd(s, dirfd, &current);
    if (r) return r;
    if (current.kind != S_IFDIR) return -ENOTDIR;
    struct mdi_node boundary = current;
    unsigned links = 0;
    memset(out, 0, sizeof(*out));
    for (;;) {
        char *start = todo; while (*start == '/') ++start;
        if (!*start) {
            out->node = out->parent = current;
            out->exists = out->special = 1;
            out->trailing = 1;
            return 0;
        }
        if ((r = mdi_access(s, &current, X_OK))) return r;
        char *end = start; while (*end && *end != '/') ++end;
        size_t size = (size_t)(end-start);
        if (size > NAME_MAX) return -ENAMETOOLONG;
        char name[NAME_MAX+1]; memcpy(name, start, size); name[size] = 0;
        int slash = *end == '/';
        memmove(todo, end, strlen(end)+1);
        char *rest = todo; while (*rest == '/') ++rest;
        int last = !*rest;
        r=mdi_host_boundary(s,current.id,name,todo,resolve);
        if (r) return r;
        struct mdi_node next;
        int special = !strcmp(name, ".") || !strcmp(name, "..");
        if (!strcmp(name, ".")) { next = current; r = 0; }
        else if (!strcmp(name, "..")) {
            if ((resolve & (RESOLVE_BENEATH | RESOLVE_IN_ROOT)) && !strcmp(current.id, boundary.id)) {
                if (resolve & RESOLVE_BENEATH) return -EXDEV;
                next = current; r = 0;
            } else if (!strcmp(current.id, mdi_root(s))) { next = current; r = 0; }
            else r = mdi_node(s, current.parent, &next);
        }
        else r = mdi_lookup(s, current.id, name, &next);
        if (r == -ENOENT && last && missing && !special) {
            out->parent = current; strcpy(out->name, name);
            out->trailing = slash;
            return 0;
        }
        if (r) return r;
        if (next.kind == S_IFLNK && (!last || follow == MDI_FOLLOW
                || (follow == MDI_NOFOLLOW && slash))) {
            if (resolve & RESOLVE_NO_SYMLINKS) return -ELOOP;
            if (++links > 40) return -ELOOP;
            char target[PATH_MAX];
            ssize_t n = readlinkat(s->objects, next.backing, target, sizeof(target));
            if (n < 0) return -errno;
            size_t rest_length = strlen(todo);
            if (!n) return -ENOENT;
            if ((size_t)n + rest_length >= sizeof(target)) return -ENAMETOOLONG;
            memcpy(target+n, todo, rest_length+1);
            strcpy(todo, target);
            if (target[0] == '/') {
                if (resolve & RESOLVE_BENEATH) return -EXDEV;
                if (resolve & RESOLVE_IN_ROOT) current = boundary;
                else if ((r = mdi_node(s, mdi_root(s), &current))) return r;
            }
            continue;
        }
        if ((!last || (slash && follow != MDI_ENTRY)) && next.kind != S_IFDIR) return -ENOTDIR;
        if (last) {
            out->parent = current; out->node = next; strcpy(out->name, name);
            out->exists = 1; out->special = special; out->trailing = slash;
            return 0;
        }
        current = next;
    }
}

int mdi_ancestor(struct md_inode_store *s, const char *ancestor, const char *child) {
    sqlite3_stmt *q = NULL;
    /* UNION (not UNION ALL) terminates even for a corrupt parent cycle. */
    int r = mdi_prepare(s, "WITH RECURSIVE chain(object,parent) AS ("
        "SELECT object,parent FROM objects WHERE object=?1 UNION "
        "SELECT o.object,o.parent FROM objects o JOIN chain c ON o.object=c.parent) "
        "SELECT EXISTS(SELECT 1 FROM chain WHERE object=?2)", &q);
    if (!r) r = mdi_bind_id(q, 1, child);
    if (!r) r = mdi_bind_id(q, 2, ancestor);
    if (!r) {
        int rc = mdi_step(s, q);
        r = rc == SQLITE_ROW ? sqlite3_column_int(q, 0) : mdi_sql_failure(rc);
    }
    sqlite3_finalize(q);
    return r;
}

static int path_name(struct md_inode_store *s, const struct mdi_node *node, struct mdi_path_name *name) {
    int directory=node->kind==S_IFDIR;
    struct mdi_cache_key key={.query=directory ? MDI_DIRECTORY_NAME : MDI_FILE_PATH,
        .id=node->id,.name=directory ? node->parent : NULL};
    if (mdi_cache_name_get(s,&key,name)) return 0;
    sqlite3_stmt *q=NULL;
    int r=mdi_query_acquire(s,key.query,&q);
    if (!r) r=mdi_bind_id(q,1,directory ? node->parent : node->id);
    if (!r && directory) r=mdi_bind_id(q,2,node->id);
    if (!r) {
        int rc=mdi_step(s,q);
        if (rc!=SQLITE_ROW) r=rc==SQLITE_DONE ? (directory ? -ENOENT : -ENOTSUP) : mdi_sql_failure(rc);
        else {
            int column=directory ? 0 : 1;
            int length=sqlite3_column_bytes(q,column);
            if (length<1 || length>NAME_MAX || (!directory && sqlite3_column_bytes(q,0)!=32)) r=-EIO;
            else {
                memcpy(name->parent,directory ? (const void *)node->parent : sqlite3_column_text(q,0),32);
                name->parent[32]=0;
                memcpy(name->name,sqlite3_column_blob(q,column),length); name->name[length]=0;
                name->ambiguous=directory ? 0 : sqlite3_column_int(q,2);
                if (memchr(name->name,0,length) || mdi_name_valid(name->name)) r=-EIO;
            }
        }
    }
    r=mdi_query_release(q,r);
    if (!r) mdi_cache_name_put(s,&key,name);
    return r;
}
static int directory_path(struct md_inode_store *s, struct mdi_node node, char *out, size_t size) {
    int r = node.kind == S_IFDIR ? 0 : -ENOTDIR;
    char path[PATH_MAX] = "";
    while (!r && strcmp(node.id, mdi_root(s))) {
        if (!strcmp(node.id, s->lifetime->scope)) return -ENOENT;
        struct mdi_path_name name;
        r=path_name(s,&node,&name);
        if (!r) {
            size_t n=strlen(name.name), old=strlen(path);
            if (old+n+1>=sizeof(path)) r=-ENAMETOOLONG;
            else {
                memmove(path+n+1,path,old+1); path[0]='/';
                memcpy(path+1,name.name,n);
            }
        }
        if (!r) r = mdi_node(s, node.parent, &node);
    }
    if (!r) {
        if (!*path) strcpy(path, "/");
        if (strlen(path) >= size) r = -ERANGE;
        else strcpy(out, path);
    }
    return r;
}
int md_inode_path(struct md_inode_store *s, int dirfd, char *out, size_t size) {
    if (!out) return -EFAULT;
    if (!size) return -ERANGE;
    int r = mdi_begin(s, 0);
    if (r) return r;
    struct mdi_node node;
    r = dirfd == MD_INODE_ROOT ? mdi_node(s, mdi_root(s), &node) : mdi_fd(s, dirfd, &node);
    if (!r) r = mdi_node_path(s, &node, out, size);
    return mdi_finish(s, r);
}
int mdi_node_path(struct md_inode_store *s, const struct mdi_node *source, char *out, size_t size) {
    struct mdi_node node = *source;
    int r = 0;
    if (node.kind == S_IFDIR) r = directory_path(s, node, out, size);
    else if (!r) {
        /* An inode which has ever had aliases cannot identify the dentry of an
         * arbitrary inherited FD. Keep that uncertainty even after unlinking an
         * alias; choosing the remaining name would misidentify old descriptors. */
        struct mdi_location location = {.node = node};
        struct mdi_path_name name;
        r=path_name(s,&node,&name);
        if (!r && name.ambiguous) r=-ENOTSUP;
        if (!r) { strcpy(location.name,name.name); r=mdi_node(s,name.parent,&location.parent); }
        if (!r) r = mdi_location_path(s, &location, out, size);
        if (!r && !node.links) {
            size_t length = strlen(out);
            if (length + sizeof(" (deleted)") > size) r = -ERANGE;
            else memcpy(out + length, " (deleted)", sizeof(" (deleted)"));
        }
    }
    return r;
}
int md_inode_realpath(struct md_inode_store *s, int base, const char *path, char *out, size_t size) {
    if (!out) return -EFAULT;
    if (!size) return -ERANGE;
    int r = mdi_begin(s, 0);
    if (r) return r;
    struct mdi_location location;
    r = mdi_walk(s, base, path, MDI_FOLLOW, 0, &location);
    if (!r) r = mdi_location_path(s, &location, out, size);
    return mdi_finish(s, r);
}
int mdi_location_path(struct md_inode_store *s, const struct mdi_location *location, char *out, size_t size) {
    if (!out) return -EFAULT;
    if (!size) return -ERANGE;
    if (location->node.kind == S_IFDIR) return directory_path(s, location->node, out, size);
    int r = directory_path(s, location->parent, out, size);
    if (!r) {
        size_t n = strlen(out), name = strlen(location->name);
        if (n == 1) n = 0;
        if (n + 1 + name >= size) r = -ERANGE;
        else { out[n++] = '/'; memcpy(out + n, location->name, name + 1); }
    }
    return r;
}

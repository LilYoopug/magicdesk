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
    const char *next=tail; while (*next=='/') ++next;
    if (!strcmp(name,"dev") && !strncmp(next,"shm",3) && (!next[3] || next[3]=='/')) return 0;
    s->boundary->mount_root=!*next;
    s->boundary->native_directory=!strcmp(name,"dev");
    if ((resolve&RESOLVE_NO_XDEV) || (*next && !s->boundary->native_directory
            && (resolve&(RESOLVE_IN_ROOT|RESOLVE_BENEATH)))) return -EXDEV;
    if (!s->boundary->path) return -EREMOTE;
    int n=snprintf(s->boundary->path,s->boundary->capacity,"/%s%s",name,tail);
    return n<0 || (size_t)n>=s->boundary->capacity ? -ENAMETOOLONG : -EREMOTE;
}

int mdi_path_step(struct md_inode_store *s, const struct mdi_node *current,
        const char *name, const char *tail, uint64_t resolve, struct mdi_node *next,struct stat *attributes,struct mdi_path_pin *pin) {
    int r=mdi_access(s,current,X_OK);
    if (!r) r=mdi_host_boundary(s,current->id,name,tail,resolve);
    if (r) return r;
    if (!strcmp(name,".") || (!strcmp(name,"..") && !strcmp(current->id,mdi_root(s)))) {
        *next=*current;
    } else if (!strcmp(name,"..")) {
        r=mdi_node(s,current->parent,next);
    } else {
        r=mdi_lookup(s,current,name,next,attributes,pin);
        if (r) return r;
        if (s->mount_boundary && md_inode_mount_contains(s->mount_boundary,next->device,next->inode)) return -EXDEV;
        return 0;
    }
    if (!r && s->mount_boundary && md_inode_mount_contains(s->mount_boundary,next->device,next->inode)) return -EXDEV;
    return !r && attributes ? mdi_stat(s,next,attributes) : r;
}
static int walk(struct md_inode_store *,int,const char *,enum mdi_follow,int,uint64_t,
        struct mdi_location *,struct stat *,struct mdi_path_pin *);
int mdi_walk(struct md_inode_store *s, int dirfd, const char *path,
        enum mdi_follow follow, int missing, struct mdi_location *out) {
    return mdi_walk_resolved(s, dirfd, path, follow, missing, 0, out);
}
int mdi_walk_resolved(struct md_inode_store *s, int dirfd, const char *path,
        enum mdi_follow follow, int missing, uint64_t resolve, struct mdi_location *out) {
    return walk(s,dirfd,path,follow,missing,resolve,out,NULL,NULL);
}
int mdi_walk_pinned(struct md_inode_store *s,int dirfd,const char *path,
        enum mdi_follow follow,int missing,uint64_t resolve,struct mdi_location *out,struct mdi_path_pin *pin) {
    *pin=(struct mdi_path_pin){.fd=-1};
    int r=walk(s,dirfd,path,follow,missing,resolve,out,NULL,pin);
    if (r && pin->fd>=0) { close(pin->fd); pin->fd=-1; }
    return r;
}
int mdi_walk_stat(struct md_inode_store *s,int dirfd,const char *path,
        enum mdi_follow follow,struct mdi_location *out,struct stat *attributes) {
    return walk(s,dirfd,path,follow,0,0,out,attributes,NULL);
}
static int walk(struct md_inode_store *s,int dirfd,const char *path,
        enum mdi_follow follow,int missing,uint64_t resolve,struct mdi_location *out,struct stat *attributes,struct mdi_path_pin *pin) {
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
    char todo[PATH_MAX];
    const char *cursor=path;
    struct mdi_node current;
    int r = (path[0] == '/' && !(resolve & RESOLVE_IN_ROOT)) || dirfd == MD_INODE_ROOT
        ? mdi_node(s, mdi_root(s), &current) : mdi_fd(s, dirfd, &current);
    if (r==-EXDEV) {
        struct stat native;
        if (fstat(dirfd,&native)) return -errno;
        if (!S_ISDIR(native.st_mode)) return -ENOTDIR;
    }
    if (r) return r;
    if (((path[0]=='/' && !(resolve&RESOLVE_IN_ROOT)) || dirfd==MD_INODE_ROOT) && s->mount_boundary
            && md_inode_mount_contains(s->mount_boundary,current.device,current.inode)) return -EXDEV;
    if (current.kind != S_IFDIR) return -ENOTDIR;
    struct mdi_node boundary = current;
    struct mdi_path_prefix prefix;
    prefix.count=1;
    prefix.nodes[0]=current;
    int remember=!resolve && !current.native && !current.descriptor;
    size_t prefix_length=0;
    if (remember) {
        r=mdi_path_prefix_get(s,path,&prefix,&prefix_length);
        if (r) return r;
        current=prefix.nodes[prefix.count-1];
        cursor=path+prefix_length;
    }
    unsigned links = 0;
    memset(out, 0, sizeof(*out));
    for (;;) {
        const char *start = cursor; while (*start == '/') ++start;
        if (!*start) {
            out->node = out->parent = current;
            out->exists = out->special = 1;
            out->trailing = 1;
            return attributes ? mdi_stat(s,&current,attributes) : 0;
        }
        const char *end = start; while (*end && *end != '/') ++end;
        size_t size = (size_t)(end-start);
        if (size > NAME_MAX) return -ENAMETOOLONG;
        char name[NAME_MAX+1]; memcpy(name, start, size); name[size] = 0;
        int slash = *end == '/';
        cursor=end;
        const char *rest = cursor; while (*rest == '/') ++rest;
        int last = !*rest;
        struct mdi_node next;
        int special = !strcmp(name, ".") || !strcmp(name, "..");
        if (remember && (last || special)) {
            mdi_path_prefix_put(s,path,prefix_length,&prefix);
            remember=0;
        }
        if (!strcmp(name,"..") && (resolve&(RESOLVE_BENEATH|RESOLVE_IN_ROOT))
                && !strcmp(current.id,boundary.id)) {
            r=mdi_access(s,&current,X_OK);
            if (!r && (resolve&RESOLVE_BENEATH)) r=-EXDEV;
            next=current;
            if (!r && last && attributes) r=mdi_stat(s,&next,attributes);
        } else r=mdi_path_step(s,&current,name,cursor,resolve,&next,last ? attributes : NULL,last ? pin : NULL);
        /* Preserve the first unresolved component for dependency-driven import.
         * Ordinary callers still accept only an absent terminal component. */
        if (r == -ENOENT && !special) {
            out->parent = current; strcpy(out->name, name);
            out->trailing = slash;
            return last && missing ? 0 : r;
        }
        if (r) return r;
        if (next.kind == S_IFLNK && (!last || follow == MDI_FOLLOW
                || (follow == MDI_NOFOLLOW && slash))) {
            if (remember) mdi_path_prefix_put(s,path,prefix_length,&prefix);
            remember=0;
            if (resolve & RESOLVE_NO_SYMLINKS) return -ELOOP;
            if (++links > 40) return -ELOOP;
            char target[PATH_MAX];
            ssize_t n = readlinkat(s->objects, next.backing, target, sizeof(target));
            if (n < 0) return -errno;
            size_t rest_length = strlen(cursor);
            if (!n) return -ENOENT;
            if ((size_t)n + rest_length >= sizeof(target)) return -ENAMETOOLONG;
            memcpy(target+n, cursor, rest_length+1);
            strcpy(todo, target);
            cursor=todo;
            if (target[0] == '/') {
                if (resolve & RESOLVE_BENEATH) return -EXDEV;
                if (resolve & RESOLVE_IN_ROOT) current = boundary;
                else if ((r = mdi_node(s, mdi_root(s), &current))) return r;
                if (s->mount_boundary && md_inode_mount_contains(s->mount_boundary,current.device,current.inode)) return -EXDEV;
            }
            continue;
        }
        if ((!last || (slash && follow != MDI_ENTRY)) && next.kind != S_IFDIR) return -ENOTDIR;
        if (last) {
            out->parent = current; out->node = next; strcpy(out->name, name);
            out->exists = 1; out->special = special; out->trailing = slash;
            return 0;
        }
        if (remember) {
            if (next.native || next.descriptor || prefix.count==MDI_PATH_PREFIX_DEPTH) {
                mdi_path_prefix_put(s,path,prefix_length,&prefix); remember=0;
            } else {
                prefix.nodes[prefix.count++]=next;
                prefix_length=(size_t)(end-path);
            }
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
    if (node->native) {
        strcpy(name->parent,node->parent);
        strcpy(name->name,strchr(node->backing,'/')+1);
        name->ambiguous=0; return 0;
    }
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
int md_inode_contains(struct md_inode_store *s,int root,int object) {
    int r=mdi_begin(s,0);
    if (r) return r;
    struct mdi_node parent,child;
    r=root==MD_INODE_ROOT ? mdi_node(s,mdi_root(s),&parent) : mdi_fd(s,root,&parent);
    if (!r) r=mdi_fd(s,object,&child);
    if (r==-EXDEV) r=0;
    else if (!r) {
        if (!strcmp(parent.id,child.id)) r=1;
        else if (parent.kind!=S_IFDIR) r=0;
        else if (child.kind==S_IFDIR) r=mdi_ancestor(s,parent.id,child.id);
        else {
            struct mdi_path_name name;
            r=path_name(s,&child,&name);
            if (!r) r=name.ambiguous ? -ENOTSUP : mdi_ancestor(s,parent.id,name.parent);
        }
    }
    int error=mdi_finish(s,r<0 ? r : 0);
    return error ? error : r;
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
int mdi_dentry_capture(struct md_inode_store *s,const struct mdi_location *loc,uint64_t *id) {
    *id=0;
    if (loc->node.native || loc->node.kind==S_IFDIR) return 0;
    const struct mdi_cache_key key={.query=MDI_DENTRY_CAPTURE,.id=loc->parent.id,.name=loc->name};
    if (mdi_cache_number_get(s,&key,id)) return 0;
    sqlite3_stmt *q=NULL;
    int r=mdi_query_acquire(s,MDI_DENTRY_CAPTURE,&q);
    if (!r) r=mdi_bind_id(q,1,loc->parent.id);
    if (!r) r=mdi_bind_name(q,2,loc->name);
    if (!r) r=mdi_bind_id(q,3,loc->node.id);
    if (!r) {
        int next=mdi_step(s,q);
        if (next!=SQLITE_ROW) r=next==SQLITE_DONE ? -ESTALE : mdi_sql_failure(next);
        else *id=(uint64_t)sqlite3_column_int64(q,0);
    }
    r=mdi_query_release(q,r);
    if (!r) mdi_cache_number_put(s,&key,*id);
    return r;
}
int mdi_dentry_move(struct md_inode_store *s,uint64_t id,const char *parent,const char *name) {
    if (!id) return 0;
    /* Rename retains the old entry identity, not the newly allocated readdir
     * cookie. Unlink retains a tombstone until its inode's normal collection. */
    sqlite3_stmt *q=NULL;
    int r=mdi_prepare(s,"DELETE FROM dentry_paths WHERE cookie=(SELECT cookie FROM names "
        "WHERE parent=?1 AND name=?2)",&q);
    if (!r) r=mdi_bind_id(q,1,parent);
    if (!r) r=mdi_bind_name(q,2,name);
    if (!r) r=mdi_sql_error(mdi_step(s,q));
    sqlite3_finalize(q); q=NULL;
    if (!r) r=mdi_prepare(s,"UPDATE dentry_paths SET parent=?1,name=?2,"
        "cookie=(SELECT cookie FROM names WHERE parent=?1 AND name=?2) WHERE id=?3",&q);
    if (!r) r=mdi_bind_id(q,1,parent);
    if (!r) r=mdi_bind_name(q,2,name);
    if (!r) r=mdi_sql_error(sqlite3_bind_int64(q,3,(sqlite3_int64)id));
    if (!r) r=mdi_sql_error(mdi_step(s,q));
    if (!r && sqlite3_changes(s->db)!=1) r=-ESTALE;
    sqlite3_finalize(q); return r;
}
int md_inode_dentry_path(struct md_inode_store *s,int fd,uint64_t id,int native_birth,char *out,size_t size) {
    if (!out) return -EFAULT;
    if (!size) return -ERANGE;
    if (!id && !native_birth) return md_inode_path(s,fd,out,size);
    int r=mdi_begin(s,0);
    if (r) return r;
    struct mdi_node node={0};
    r=mdi_fd(s,fd,&node);
    if (!r && (node.native || node.kind==S_IFDIR)) return mdi_finish(s,mdi_node_path(s,&node,out,size));
    enum mdi_query slot=id ? MDI_DENTRY_PATH : MDI_DENTRY_BIRTH;
    sqlite3_stmt *q=NULL;
    if (!r) r=mdi_query_acquire(s,slot,&q);
    if (!r && id) r=mdi_sql_error(sqlite3_bind_int64(q,1,(sqlite3_int64)id));
    if (!r) r=mdi_bind_id(q,2,node.id);
    struct mdi_location loc={.node=node};
    int deleted=0;
    char parent[33];
    if (!r) {
        int next=mdi_step(s,q);
        if (next!=SQLITE_ROW) r=next==SQLITE_DONE ? -ESTALE : mdi_sql_failure(next);
        else {
            const char *p=(const char *)sqlite3_column_text(q,0);
            int length=sqlite3_column_bytes(q,1);
            if (!p || strlen(p)!=32 || length<1 || length>NAME_MAX) r=-EIO;
            else {
                memcpy(parent,p,33); memcpy(loc.name,sqlite3_column_blob(q,1),(size_t)length);
                loc.name[length]=0; deleted=sqlite3_column_int(q,2);
            }
        }
    }
    r=mdi_query_release(q,r);
    if (!r) r=mdi_node(s,parent,&loc.parent);
    if (!r) r=mdi_location_path(s,&loc,out,size);
    if (!r && deleted) {
        size_t length=strlen(out);
        if (length+sizeof(" (deleted)")>size) r=-ERANGE;
        else memcpy(out+length," (deleted)",sizeof(" (deleted)"));
    }
    return mdi_finish(s,r);
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

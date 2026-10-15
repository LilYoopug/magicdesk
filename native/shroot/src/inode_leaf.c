#define _GNU_SOURCE
#include "inode_internal.h"
#include "inode_leaf.h"
#include "inode_native.h"
#include "inode_publication.h"
#include "inode_xattr.h"
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void mdi_leaf_admit(struct md_inode_store *s) {
    s->native_files=0;
    if (s->readonly) return;
    int fd=openat(s->objects,".",O_TMPFILE|O_RDWR|O_CLOEXEC,0600);
    if (fd<0) return;
    struct stat st;
    int r=mdi_native_metadata(fd,1,1,0);
    if (!r) r=mdi_native_stat(fd,&st);
    s->native_files=!r && st.st_uid==1 && st.st_gid==1 && !(st.st_mode&07777);
    close(fd);
}
int mdi_leaf_create(struct md_inode_store *s,const struct mdi_node *parent,const char *name,int flags,mode_t mode) {
    if (!s->native_files || !s->identity || s->overlay || parent->mode<0 || !parent->attached || parent->source
            || (parent->acl_mask&MD_ACL_DEFAULT)) return -EOPNOTSUPP;
    uint32_t uid=s->identity->uid.fs,gid=s->identity->gid.fs;
    if (parent->mode&S_ISGID) gid=parent->gid;
    if ((mode&S_ISGID) && !md_identity_file_capable(s->identity,parent->uid,parent->gid,CAP_FSETID)
            && !md_identity_in_group(s->identity,gid)) mode&=~S_ISGID;
    mode&=~s->creation_mask;
    flags&=~(O_CREAT|O_EXCL|O_TRUNC|O_NOFOLLOW|O_NOCTTY);
    if (mdi_native_eligible(uid,gid,mode))
        return mdi_native_create_in(s->objects,parent->backing,name,flags,uid,gid,mode);
    char stage[33],target[NAME_MAX+34];
    int r=mdi_name_valid(name);
    if (!r) r=mdi_random_id(stage);
    if (r) return r;
    int fd=mdi_native_prepare(s->objects,stage,flags,uid,gid,mode);
    if (fd<0) return fd;
    snprintf(target,sizeof(target),"%s/%s",parent->backing,name);
    /* Only unpublished native births move out of the backing root. The watch
     * owner uses this exact kernel move cookie to publish CREATE then OPEN. */
    if (renameat2(s->objects,stage,s->objects,target,RENAME_NOREPLACE)) r=-errno;
    if (r) { close(fd); unlinkat(s->objects,stage,0); }
    return r ? r : fd;
}

void mdi_leaf_id(const struct stat *st,char out[33]) {
    snprintf(out,33,"%016" PRIx64 "%016" PRIx64,(uint64_t)st->st_dev,(uint64_t)st->st_ino);
}
static int leaf(struct md_inode_store *s,const struct mdi_node *parent,const char *name,
        int descriptor,const struct stat *physical,struct mdi_node *out) {
    if (!S_ISREG(physical->st_mode) || physical->st_nlink>1) return -EXDEV;
    struct mdi_node node={.native=1,.descriptor=descriptor<0 ? 0 : descriptor+1,
        .kind=S_IFREG,.device=physical->st_dev,.inode=physical->st_ino,
        .logical_device=physical->st_dev,.logical_inode=physical->st_ino,
        .links=physical->st_nlink,.attached=!!physical->st_nlink};
    mdi_leaf_id(physical,node.id);
    strcpy(node.parent,parent->id); strcpy(node.scope,parent->scope);
    int n=snprintf(node.backing,sizeof(node.backing),"%s/%s",parent->backing,name);
    if (n<0 || (size_t)n>=sizeof(node.backing)) return -ENAMETOOLONG;
    struct stat logical=*physical;
    if (physical->st_mode&S_ISVTX) {
        int fd=descriptor>=0 ? descriptor : mdi_backing_open(s,&node,O_PATH);
        if (fd<0) return fd;
        int r=mdi_native_info(fd,&logical,&node.acl_mask);
        if (descriptor<0) close(fd);
        if (r) return r;
        if (logical.st_dev!=physical->st_dev || logical.st_ino!=physical->st_ino) return -ESTALE;
    } else {
        if (!mdi_native_eligible(0,0,physical->st_mode&07777)) return -EIO;
        logical.st_uid=logical.st_gid=0;
    }
    node.mode=logical.st_mode&07777; node.uid=logical.st_uid; node.gid=logical.st_gid;
    *out=node; return 0;
}
int mdi_leaf_lookup(struct md_inode_store *s,const char *id,const char *name,struct mdi_node *out) {
    struct mdi_node parent;
    int r=mdi_node(s,id,&parent);
    if (r) return r;
    if (parent.kind!=S_IFDIR || parent.source || !parent.attached) return -ENOENT;
    char path[NAME_MAX+34];
    int n=snprintf(path,sizeof(path),"%s/%s",parent.backing,name);
    if (n<0 || (size_t)n>=sizeof(path)) return -ENAMETOOLONG;
    struct stat st;
    if (fstatat(s->objects,path,&st,AT_SYMLINK_NOFOLLOW)) return -errno;
    return leaf(s,&parent,name,-1,&st,out);
}
static int fdpath(int fd,char *out,size_t size) {
    char proc[64]; snprintf(proc,sizeof(proc),"/proc/self/fd/%d",fd);
    ssize_t n=readlink(proc,out,size);
    if (n<0) return -errno;
    if ((size_t)n>=size) return -ENAMETOOLONG;
    out[n]=0; return 0;
}
int mdi_leaf_descriptor(struct md_inode_store *s,int fd,const struct stat *st,struct mdi_node *out) {
    if (!S_ISREG(st->st_mode) || st->st_nlink>1) return -EXDEV;
    char path[PATH_MAX],root[PATH_MAX];
    int r=fdpath(fd,path,sizeof(path));
    if (!r) r=fdpath(s->objects,root,sizeof(root));
    if (r) return r;
    size_t length=strlen(root);
    if (strncmp(path,root,length) || path[length]!='/') return -EXDEV;
    char *parent=path+length+1,*name=strchr(parent,'/');
    if (!name || name-parent!=32) return -EXDEV;
    *name++=0;
    if (strspn(parent,"0123456789abcdef")!=32 || strchr(name,'/')) return -EXDEV;
    /* The kernel appends this suffix only after final unlink. A real filename
     * ending in the same bytes is left untouched while it still has a link. */
    size_t size=strlen(name);
    const char suffix[]=" (deleted)";
    if (!st->st_nlink && size>=sizeof(suffix)-1 && !strcmp(name+size-(sizeof(suffix)-1),suffix))
        name[size-(sizeof(suffix)-1)]=0;
    if (mdi_name_valid(name)) return -EXDEV;
    struct mdi_node directory;
    r=mdi_node(s,parent,&directory);
    if (r) return r==-ENOENT ? -EXDEV : r;
    if (directory.kind!=S_IFDIR || directory.source || strcmp(directory.scope,s->lifetime->scope)
            || strcmp(directory.backing,parent)) return -EXDEV;
    struct stat actual;
    r=mdi_backing_stat(s,&directory,&actual);
    if (r) return r;
    if (st->st_nlink) {
        char selected[NAME_MAX+34]; snprintf(selected,sizeof(selected),"%s/%s",parent,name);
        if (fstatat(s->objects,selected,&actual,AT_SYMLINK_NOFOLLOW)) return -errno;
        if (st->st_dev!=actual.st_dev || st->st_ino!=actual.st_ino) return -ESTALE;
    }
    return leaf(s,&directory,name,fd,st,out);
}
int mdi_leaf_promote(struct md_inode_store *s,struct mdi_node *node) {
    if (!node->native) return 0;
    if (!node->attached) return -ENOENT;
    struct mdi_node parent;
    int r=mdi_node(s,node->parent,&parent);
    struct stat st;
    if (!r) r=mdi_backing_stat(s,node,&st);
    if (!r) r=mdi_publication_promote(s,&parent,strchr(node->backing,'/')+1,&st,node);
    return r;
}
ssize_t mdi_leaf_attribute(struct md_inode_store *s,const struct mdi_node *node,int cap,void *out,size_t size) {
    int fd=mdi_backing_open(s,node,O_PATH);
    if (fd<0) return fd;
    ssize_t r=mdi_native_attribute(fd,cap,out,size);
    close(fd); return r;
}
int mdi_leaf_attribute_set(struct md_inode_store *s,const struct mdi_node *node,int cap,
        const void *value,size_t size,mode_t mode) {
    int fd=mdi_backing_open(s,node,O_PATH);
    if (fd<0) return fd;
    int r=mdi_native_attribute_set(fd,cap,value,size,mode);
    close(fd); return r;
}
int mdi_leaf_import_attributes(struct md_inode_store *s,const struct mdi_node *node,int fd) {
    for (int cap=0;cap<2;++cap) {
        ssize_t size=mdi_native_attribute(fd,cap,NULL,0);
        if (size==-ENODATA) continue;
        if (size<0) return (int)size;
        void *value=malloc((size_t)size);
        if (!value) return -ENOMEM;
        ssize_t n=mdi_native_attribute(fd,cap,value,(size_t)size);
        int r=n!=size ? (n<0 ? (int)n : -ESTALE) : cap ? mdi_file_capability(s,node,value,(size_t)size)
            : mdi_acl_store(s,node,MD_ACL_ACCESS,value,(size_t)size);
        free(value); if (r) return r;
    }
    struct mdi_node native=*node; native.native=1; native.descriptor=fd+1;
    return mdi_overlay_attributes_copy(s,node,s,&native);
}
int mdi_leaf_list(struct md_inode_store *s,const struct mdi_node *parent,int (*visit)(const char *,void *),void *context) {
    /* Real-permission directories never allocate native guest leaves. They may
     * be mode 000, and removing an empty one must not require read access. */
    if (parent->mode<0) return 0;
    int fd=mdi_backing_open(s,parent,O_RDONLY|O_DIRECTORY);
    if (fd<0) return fd;
    DIR *dir=fdopendir(fd);
    if (!dir) { int r=-errno; close(fd); return r; }
    int r=0;
    while (!r) {
        errno=0; struct dirent *entry=readdir(dir);
        if (!entry) { if (errno) r=-errno; break; }
        if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        int regular=entry->d_type==DT_REG;
        if (entry->d_type==DT_UNKNOWN) {
            struct stat st;
            if (fstatat(fd,entry->d_name,&st,AT_SYMLINK_NOFOLLOW)) { r=-errno; break; }
            regular=S_ISREG(st.st_mode);
        }
        if (!regular || mdi_name_valid(entry->d_name)) { r=-EIO; break; }
        r=visit(entry->d_name,context);
    }
    closedir(dir); return r;
}
struct materialize { struct md_inode_store *store; const struct mdi_node *parent; };
static int promote_name(const char *name,void *data) {
    struct materialize *m=data;
    struct mdi_node node;
    int r=mdi_leaf_lookup(m->store,m->parent->id,name,&node);
    return r ? r : mdi_leaf_promote(m->store,&node);
}
int mdi_leaf_materialize(struct md_inode_store *s) {
    char after[33]="";
    int r=0;
    while (!r) {
        sqlite3_stmt *q=NULL;
        r=mdi_prepare(s,"SELECT object FROM objects WHERE kind=16384 AND scope=?1 AND object>?2 ORDER BY object LIMIT 1",&q);
        if (!r) r=mdi_bind_id(q,1,s->lifetime->scope);
        if (!r) r=mdi_bind_id(q,2,after);
        int found=0;
        if (!r) {
            int next=mdi_step(s,q);
            if (next==SQLITE_ROW && sqlite3_column_bytes(q,0)==32) { memcpy(after,sqlite3_column_text(q,0),33); found=1; }
            else if (next!=SQLITE_DONE) r=-EIO;
        }
        sqlite3_finalize(q);
        if (r || !found) break;
        struct mdi_node parent;
        r=mdi_node(s,after,&parent);
        struct materialize m={s,&parent};
        if (!r && parent.attached) r=mdi_leaf_list(s,&parent,promote_name,&m);
    }
    return r;
}

#define _GNU_SOURCE
#include "inode_internal.h"
#include "inode_leaf.h"
#include "inode_native.h"
#include "inode_publication.h"
#include "inode_xattr.h"
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>

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
static int birth_attributes(struct md_inode_store *s,const struct mdi_node *parent,const char *name,
        uint32_t *uid,uint32_t *gid,mode_t *mode) {
    if (!s->native_files || !s->identity || !parent->attached || parent->source)
        return -EOPNOTSUPP;
    int allowed=mdi_overlay_native_name(s,parent,name);
    if (allowed) return allowed;
    struct stat st={.st_mode=parent->mode,.st_uid=parent->uid,.st_gid=parent->gid};
    int r=parent->mode<0 ? mdi_stat(s,parent,&st) : 0;
    if (r) return r;
    *uid=s->identity->uid.fs; *gid=s->identity->gid.fs;
    if (st.st_mode&S_ISGID) *gid=st.st_gid;
    if ((*mode&S_ISGID) && !md_identity_file_capable(s->identity,st.st_uid,st.st_gid,CAP_FSETID)
            && !md_identity_in_group(s->identity,*gid)) *mode&=~S_ISGID;
    if (!(parent->acl_mask&MD_ACL_DEFAULT)) *mode&=~s->creation_mask;
    return 0;
}
static int prepare_backing(struct md_inode_store *s,const struct mdi_node *parent,const char *stage,
        int flags,uint32_t uid,uint32_t gid,mode_t mode) {
    int fd=mdi_native_eligible(uid,gid,mode)
        ? mdi_native_create(s->objects,stage,flags,uid,gid,mode)
        : mdi_native_prepare(s->objects,stage,flags,uid,gid,mode);
    if (fd<0) return fd;
    if (parent->acl_mask&MD_ACL_DEFAULT) {
        struct mdi_node node={.native=1,.descriptor=fd+1,.kind=S_IFREG,.mode=mode,.uid=uid,.gid=gid};
        int r=mdi_acl_inherit(s,parent,&node,mode);
        if (r) { close(fd); unlinkat(s->objects,stage,0); return r; }
    }
    return fd;
}
int mdi_leaf_create(struct md_inode_store *s,const struct mdi_node *parent,const char *name,int flags,mode_t mode) {
    if (parent->mode<0) return -EOPNOTSUPP;
    uint32_t uid,gid;
    int r=birth_attributes(s,parent,name,&uid,&gid,&mode);
    if (r) return r;
    flags&=~(O_CREAT|O_EXCL|O_TRUNC|O_NOFOLLOW|O_NOCTTY);
    if (!(parent->acl_mask&MD_ACL_DEFAULT) && mdi_native_eligible(uid,gid,mode))
        return mdi_native_create_in(s->objects,parent->backing,name,flags,uid,gid,mode);
    char stage[33],target[NAME_MAX+34];
    r=mdi_name_valid(name);
    if (!r) r=mdi_random_id(stage);
    if (r) return r;
    int fd=prepare_backing(s,parent,stage,flags,uid,gid,mode);
    if (fd<0) return fd;
    snprintf(target,sizeof(target),"%s/%s",parent->backing,name);
    /* Only unpublished native births move out of the backing root. The watch
     * owner uses this exact kernel move cookie to publish CREATE then OPEN. */
    if (renameat2(s->objects,stage,s->objects,target,RENAME_NOREPLACE)) r=-errno;
    if (r) { close(fd); unlinkat(s->objects,stage,0); }
    return r ? r : fd;
}

struct md_inode_birth {
    struct md_inode_store *store;
    char parent[33],backing[33],stage[33],name[NAME_MAX+1];
    int catalogue,synchronous;
};
int mdi_leaf_prepare_birth(struct md_inode_store *s,const struct mdi_node *parent,const char *name,
        int flags,mode_t mode,struct md_inode_birth **out) {
    if (!out || *out) return -EINVAL;
    uint32_t uid,gid;
    int r=birth_attributes(s,parent,name,&uid,&gid,&mode);
    if (!r) r=mdi_name_valid(name);
    if (r) return r;
    struct md_inode_birth *birth=calloc(1,sizeof(*birth));
    if (!birth) return -ENOMEM;
    birth->store=s;
    birth->catalogue=parent->mode<0;
    birth->synchronous=!!(flags&O_DSYNC);
    strcpy(birth->parent,parent->id); strcpy(birth->backing,parent->backing); strcpy(birth->name,name);
    r=mdi_random_id(birth->stage);
    flags&=~(O_CREAT|O_EXCL|O_TRUNC|O_NOFOLLOW|O_NOCTTY);
    int fd=r ? r : prepare_backing(s,parent,birth->stage,flags,uid,gid,mode);
    if (fd<0) { free(birth); return fd; }
    /* The real caller, not this metadata preparation, owns its data open and
     * descriptor capacity. Maintenance is excluded by the store's lifetime. */
    int pin=openat(s->objects,birth->stage,O_PATH|O_CLOEXEC|O_NOFOLLOW);
    r=pin<0 ? -errno : 0;
    if (!r && birth->catalogue) r=mdi_sync(s,fd);
    close(fd);
    if (r) { if (pin>=0) close(pin); unlinkat(s->objects,birth->stage,0); free(birth); return r; }
    *out=birth; return pin;
}
int md_inode_birth_discard(struct md_inode_birth **owner) {
    if (!owner || !*owner) return 0;
    struct md_inode_birth *birth=*owner;
    if (unlinkat(birth->store->objects,birth->stage,0) && errno!=ENOENT) return -errno;
    free(birth); *owner=NULL; return 0;
}
void md_inode_birth_forget(struct md_inode_birth **owner) {
    if (owner) { free(*owner); *owner=NULL; }
}
static int catalogue_birth(struct md_inode_birth **owner) {
    struct md_inode_birth *birth=*owner;
    struct md_inode_store *s=birth->store;
    char id[33];
    int r=mdi_random_id(id);
    int pin=r ? r : openat(s->objects,birth->stage,O_PATH|O_CLOEXEC|O_NOFOLLOW);
    if (pin<0 && !r) r=-errno;
    struct stat st;
    if (!r) r=mdi_native_stat(pin,&st);
    if (!r) r=mdi_write(s);
    /* Staging events never acquire a catalogue identity. Only the final move
     * publishes CREATE/OPEN; failure before commit leaves an owned orphan. */
    if (!r && renameat2(s->objects,birth->stage,s->objects,id,RENAME_NOREPLACE)) r=-errno;
    if (!r) strcpy(birth->stage,id);
    struct mdi_node node;
    if (!r) r=mdi_register_object(s,id,S_IFREG,st.st_mode&07777,st.st_uid,st.st_gid,&st,NULL,&node);
    if (!r) r=mdi_leaf_import_attributes(s,&node,pin);
    if (!r) r=mdi_add_name(s,birth->parent,birth->name,id);
    if (!r) r=mdi_event(s,birth->parent,&node,birth->name,IN_CREATE,NULL);
    if (!r) r=mdi_sync(s,s->objects);
    if (!r && birth->synchronous) s->sync_requested=1;
    if (pin>=0) close(pin);
    int committed=0;
    r=mdi_commit_owned(s,r,&committed);
    if (committed) { free(birth); *owner=NULL; }
    return r;
}
int md_inode_birth_commit(struct md_inode_birth **owner) {
    if (!owner || !*owner) return -EINVAL;
    struct md_inode_birth *birth=*owner;
    struct md_inode_store *s=birth->store;
    int r=mdi_begin(s,0);
    if (r) return r;
    struct mdi_node parent,entry;
    r=mdi_readonly(s) ? -EROFS : mdi_node(s,birth->parent,&parent);
    if (!r && (!parent.attached || parent.source || strcmp(parent.backing,birth->backing))) r=-ENOENT;
    if (!r) {
        int found=mdi_lookup(s,&parent,birth->name,&entry,NULL,NULL);
        r=found==-ENOENT ? 0 : found ? found : -EEXIST;
    }
    if (!r) r=mdi_overlay_native_name(s,&parent,birth->name);
    if (!r && birth->catalogue) return catalogue_birth(owner);
    char target[NAME_MAX+34];
    if (!r) {
        snprintf(target,sizeof(target),"%s/%s",birth->backing,birth->name);
        if (renameat2(s->objects,birth->stage,s->objects,target,RENAME_NOREPLACE)) r=-errno;
        else { free(birth); *owner=NULL; }
    }
    /* Consuming the owner records the accepted rename even if retirement fails.
     * The caller must not replay or discard a committed creation. */
    return mdi_finish(s,r);
}

int mdi_leaf_id(const struct stat *st,const char scope[33],char out[33]) {
    static const char hex[]="0123456789abcdef";
    const uint64_t values[]={(uint64_t)st->st_dev,(uint64_t)st->st_ino};
    for (unsigned part=0;part<2;++part) for (unsigned i=0;i<16;++i)
        out[part*16+i]=hex[(values[part]>>(60-4*i))&15];
    out[32]=0;
    if (!strcmp(scope,MDI_ROOT)) return 0;
    /* A backing can be visible in both upper and merged scopes. Preserve the
     * root identity and derive each view's stable identity before promotion. */
    for (unsigned i=0;i<32;++i) {
        const char *digit=strchr(hex,scope[i]);
        if (!scope[i] || !digit) return -EIO;
        out[i]=hex[(strchr(hex,out[i])-hex)^(digit-hex)];
    }
    return 0;
}
static int leaf(struct md_inode_store *s,const struct mdi_node *parent,
        const char *backing,int descriptor,const struct stat *physical,struct mdi_node *out,struct stat *attributes) {
    if (!S_ISREG(physical->st_mode) || physical->st_nlink>1) return -EXDEV;
    struct mdi_node node={.native=1,.descriptor=descriptor<0 ? 0 : descriptor+1,
        .kind=S_IFREG,.device=physical->st_dev,.inode=physical->st_ino,
        .logical_device=physical->st_dev,.logical_inode=physical->st_ino,
        .links=physical->st_nlink,.attached=!!physical->st_nlink};
    int id=mdi_leaf_id(physical,parent->scope,node.id);
    if (id) return id;
    strcpy(node.parent,parent->id); strcpy(node.scope,parent->scope);
    strcpy(node.backing,backing);
    struct stat logical=*physical;
    if (physical->st_mode&S_ISVTX) {
        int fd=descriptor>=0 ? descriptor : mdi_backing_open(s,&node,O_PATH);
        if (fd<0) return fd;
        int r=descriptor>=0 ? mdi_native_project(fd,&logical,&node.acl_mask)
            : mdi_native_info(fd,&logical,&node.acl_mask);
        if (descriptor<0) close(fd);
        if (r) return r;
        if (logical.st_dev!=physical->st_dev || logical.st_ino!=physical->st_ino) return -ESTALE;
    } else {
        if (!mdi_native_eligible(0,0,physical->st_mode&07777)) return -EIO;
        logical.st_uid=logical.st_gid=0;
    }
    node.mode=logical.st_mode&07777; node.uid=logical.st_uid; node.gid=logical.st_gid;
    /* Return this lookup's observation, not a second pathname lookup which can
     * select a different object. Nothing survives the enclosing operation. */
    if (attributes) { *attributes=logical; mdi_stat_project(&node,attributes); }
    *out=node; return 0;
}
int mdi_leaf_lookup(struct md_inode_store *s,const struct mdi_node *parent,const char *name,struct mdi_node *out,struct stat *attributes,struct mdi_path_pin *pin) {
    if (parent->kind!=S_IFDIR || parent->source || !parent->attached) return -ENOENT;
    char path[NAME_MAX+34];
    size_t prefix=strlen(parent->backing),length=strlen(name);
    if (prefix+length+1>=sizeof(path)) return -ENAMETOOLONG;
    memcpy(path,parent->backing,prefix); path[prefix]='/'; memcpy(path+prefix+1,name,length+1);
    struct stat st;
    if (pin) {
        int fd=openat(s->objects,path,O_PATH|O_NOFOLLOW|O_CLOEXEC);
        if (fd<0) return -errno;
        int r=fstat(fd,&st) ? -errno : leaf(s,parent,path,fd,&st,out,attributes);
        if (r) close(fd);
        else *pin=(struct mdi_path_pin){.fd=fd,.physical=st};
        return r;
    }
    if (fstatat(s->objects,path,&st,AT_SYMLINK_NOFOLLOW)) return -errno;
    return leaf(s,parent,path,-1,&st,out,attributes);
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
    if (!r && !strcmp(directory.scope,s->lifetime->scope) && !strcmp(directory.backing,parent))
        goto selected;
    if (r && r!=-ENOENT) return r;
    sqlite3_stmt *q=NULL;
    r=mdi_query_acquire(s,MDI_BACKING_OBJECT,&q);
    if (!r) r=mdi_bind_id(q,1,parent);
    if (!r) r=mdi_sql_error(sqlite3_bind_int(q,2,0));
    char id[33];
    if (!r) {
        int next=mdi_step(s,q);
        if (next==SQLITE_ROW && sqlite3_column_bytes(q,0)==32) memcpy(id,sqlite3_column_text(q,0),33);
        else r=next==SQLITE_DONE ? -ENOENT : -EIO;
    }
    r=mdi_query_release(q,r);
    if (!r) r=mdi_node(s,id,&directory);
    if (r) return r==-ENOENT ? -EXDEV : r;
selected:
    if (directory.kind!=S_IFDIR || directory.source || strcmp(directory.scope,s->lifetime->scope)
            || strcmp(directory.backing,parent)) return -EXDEV;
    struct stat actual;
    r=mdi_backing_stat(s,&directory,&actual);
    if (r) return r;
    char selected[NAME_MAX+34]; snprintf(selected,sizeof(selected),"%s/%s",parent,name);
    if (st->st_nlink) {
        if (fstatat(s->objects,selected,&actual,AT_SYMLINK_NOFOLLOW)) return -errno;
        if (st->st_dev!=actual.st_dev || st->st_ino!=actual.st_ino) return -ESTALE;
    }
    return leaf(s,&directory,selected,fd,st,out,NULL);
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
    int r=mdi_leaf_lookup(m->store,m->parent,name,&node,NULL,NULL);
    return r ? r : mdi_leaf_promote(m->store,&node);
}
int mdi_leaf_materialize_directory(struct md_inode_store *s,const struct mdi_node *parent) {
    struct materialize m={s,parent};
    return parent->attached ? mdi_leaf_list(s,parent,promote_name,&m) : 0;
}
int mdi_leaf_materialize_tree(struct md_inode_store *s,const struct mdi_node *root) {
    sqlite3_stmt *q=NULL;
    int r=mdi_prepare(s,"WITH RECURSIVE dirs(object) AS (SELECT ?1 UNION "
        "SELECT n.object FROM names n JOIN dirs d ON n.parent=d.object "
        "JOIN objects o ON o.object=n.object WHERE o.kind=16384) SELECT object FROM dirs",&q);
    if (!r) r=mdi_bind_id(q,1,root->id);
    char (*ids)[33]=NULL;
    size_t count=0,capacity=0;
    while (!r) {
        int next=mdi_step(s,q);
        if (next==SQLITE_DONE) break;
        if (next!=SQLITE_ROW) { r=mdi_sql_failure(next); break; }
        if (sqlite3_column_bytes(q,0)!=32) { r=-EIO; break; }
        if (count==capacity) {
            if (capacity>SIZE_MAX/2/sizeof(*ids)) { r=-ENOMEM; break; }
            size_t size=capacity ? capacity*2 : 16;
            void *grown=realloc(ids,size*sizeof(*ids));
            if (!grown) { r=-ENOMEM; break; }
            ids=grown; capacity=size;
        }
        memcpy(ids[count++],sqlite3_column_text(q,0),33);
    }
    sqlite3_finalize(q);
    /* Promotion temporarily commits its recovery journal. Snapshot directory
     * identities and close the cursor before crossing that transaction boundary. */
    for (size_t i=0;!r && i<count;++i) {
        struct mdi_node parent;
        r=mdi_node(s,ids[i],&parent);
        if (!r) r=mdi_leaf_materialize_directory(s,&parent);
    }
    free(ids); return r;
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
        if (!r) r=mdi_leaf_materialize_directory(s,&parent);
    }
    return r;
}

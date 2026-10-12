#define _GNU_SOURCE
#include "provider_tree.h"
#include "temporary_directory.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct md_provider_tree {
    atomic_uint references;
    int upper,lower;
    char **opaque;
    unsigned opaque_count;
    const struct md_provider_tree_ops *ops;
    void *context;
};
static int fdpath(int fd,char *out,size_t size) {
    char proc[64]; snprintf(proc,sizeof(proc),"/proc/self/fd/%d",fd);
    ssize_t n=readlink(proc,out,size);
    if (n<0) return -errno;
    if ((size_t)n>=size) return -ENAMETOOLONG;
    out[n]=0; return 0;
}
static int below(const char *path,const char *root) {
    size_t length=strlen(root);
    return !strncmp(path,root,length) && (!path[length] || path[length]=='/');
}
struct md_provider_tree *md_provider_tree_new(int parent,int lower,const char *const *opaque,
        unsigned count,const struct md_provider_tree_ops *ops,void *context) {
    if (count>32 || (count && !opaque)) { errno=EINVAL; return NULL; }
    struct md_provider_tree *tree=calloc(1,sizeof(*tree));
    if (!tree) return NULL;
    atomic_init(&tree->references,1); tree->upper=tree->lower=-1;
    if (lower>=0) { tree->lower=fcntl(lower,F_DUPFD_CLOEXEC,3); if (tree->lower<0) goto failed; }
    tree->upper=md_temporary_directory_new(parent);
    if (tree->upper<0) { errno=-tree->upper; tree->upper=-1; goto failed; }
    tree->opaque=calloc(count ? count : 1,sizeof(*tree->opaque));
    if (!tree->opaque) goto failed;
    for (unsigned i=0;i<count;++i) {
        if (!opaque[i] || opaque[i][0]!='/' || strstr(opaque[i],"..")) { errno=EINVAL; goto failed; }
        tree->opaque[i]=strdup(opaque[i]); if (!tree->opaque[i]) goto failed;
        tree->opaque_count++;
    }
    tree->ops=ops; tree->context=ops && ops->retain ? ops->retain(context) : context;
    return tree;
failed: {
    int error=errno; md_provider_tree_release(tree); errno=error; return NULL;
}}
struct md_provider_tree *md_provider_tree_retain(struct md_provider_tree *tree) {
    if (tree) atomic_fetch_add_explicit(&tree->references,1,memory_order_relaxed);
    return tree;
}
void md_provider_tree_release(struct md_provider_tree *tree) {
    if (!tree || atomic_fetch_sub_explicit(&tree->references,1,memory_order_acq_rel)!=1) return;
    if (tree->ops && tree->ops->release) tree->ops->release(tree->context);
    if (tree->lower>=0) close(tree->lower);
    if (tree->upper>=0) md_temporary_directory_release(tree->upper);
    for (unsigned i=0;i<tree->opaque_count;++i) free(tree->opaque[i]);
    free(tree->opaque); free(tree);
}
int md_provider_tree_root(struct md_provider_tree *tree) { return tree->upper; }
int md_provider_tree_private(struct md_provider_tree *tree,int fd) {
    if (fd<0) return 0;
    char path[PATH_MAX],root[PATH_MAX];
    int error=fdpath(fd,path,sizeof(path));
    if (!error) error=fdpath(tree->upper,root,sizeof(root));
    return error ? error : below(path,root);
}
unsigned long md_provider_tree_filesystem(struct md_provider_tree *tree) { return tree->ops ? tree->ops->filesystem : 0; }
int md_provider_tree_path(struct md_provider_tree *tree,int fd,char *out,size_t size) {
    char path[PATH_MAX],root[PATH_MAX]; int error=fdpath(fd,path,sizeof(path));
    if (error) return error;
    int roots[]={tree->upper,tree->lower};
    for (unsigned i=0;i<2;++i) {
        if (roots[i]<0) continue;
        error=fdpath(roots[i],root,sizeof(root)); if (error) return error;
        if (!below(path,root)) continue;
        const char *suffix=path+strlen(root); if (!*suffix) suffix="/";
        size_t length=strlen(suffix);
        if (length>=size) return -ENAMETOOLONG;
        memcpy(out,suffix,length+1); return 0;
    }
    return -EXDEV;
}
static int opaque(struct md_provider_tree *tree,const char *path) {
    for (unsigned i=0;i<tree->opaque_count;++i) if (below(path,tree->opaque[i])) return 1;
    return 0;
}
static const char *relative(const char *path) { return path[1] ? path+1 : "."; }
static int internal(const char *directory,const char *name) {
    return !strcmp(directory,"/") && !strcmp(name,MD_TEMPORARY_DIRECTORY_MARKER);
}
int md_provider_tree_step(struct md_provider_tree *tree,int directory,const char *name) {
    char path[PATH_MAX]; int error=md_provider_tree_path(tree,directory,path,sizeof(path));
    if (error) return error;
    if (internal(path,name)) return -ENOENT;
    if (!strcmp(name,"..")) {
        char *slash=strrchr(path,'/'); if (slash==path) path[1]=0; else *slash=0;
    } else if (strcmp(name,".")) {
        if (!*name || strchr(name,'/')) return -EINVAL;
        size_t length=strlen(path),n=strlen(name);
        if (length+n+2>sizeof(path)) return -ENAMETOOLONG;
        if (length>1) path[length++]='/';
        memcpy(path+length,name,n+1);
    }
    int fd=openat(tree->upper,relative(path),O_PATH|O_NOFOLLOW|O_CLOEXEC);
    if (fd>=0) return fd;
    if (errno!=ENOENT || opaque(tree,path) || tree->lower<0) return -errno;
    fd=openat(tree->lower,relative(path),O_PATH|O_NOFOLLOW|O_CLOEXEC);
    return fd<0 ? -errno : fd;
}
struct entry { uint64_t ino; int64_t offset; uint16_t size; uint8_t type; char name[]; };
ssize_t md_provider_tree_getdents(struct md_provider_tree *tree,int fd,void *out,size_t capacity) {
    char path[PATH_MAX]; int error=md_provider_tree_path(tree,fd,path,sizeof(path));
    if (error) return error;
    off_t position=lseek(fd,0,SEEK_CUR); if (position<0) return -errno;
    int upper=openat(tree->upper,relative(path),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    int lower=opaque(tree,path) || tree->lower<0 ? -1
        : openat(tree->lower,relative(path),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (upper<0 && lower<0) return -errno;
    size_t used=0; off_t index=0,next=position;
    int roots[]={upper,lower},stop=0;
    for (unsigned i=0;i<2 && !stop;++i) {
        if (roots[i]<0) continue;
        int duplicate=fcntl(roots[i],F_DUPFD_CLOEXEC,3);
        DIR *dir=duplicate<0 ? NULL : fdopendir(duplicate);
        if (!dir) { if (duplicate>=0) close(duplicate); error=-errno; break; }
        for (;;) {
            errno=0; struct dirent *e=readdir(dir);
            if (!e) { if (errno) error=-errno; break; }
            if (internal(path,e->d_name)) continue;
            struct stat st;
            if (i && upper>=0 && !fstatat(upper,e->d_name,&st,AT_SYMLINK_NOFOLLOW)) continue;
            if (index++<position) continue;
            size_t n=strlen(e->d_name)+1;
            size_t size=(offsetof(struct entry,name)+n+7)&~(size_t)7;
            if (size>capacity-used) { if (!used) error=-EINVAL; stop=1; break; }
            struct entry *entry=(void *)((char *)out+used);
            memset(entry,0,size); entry->ino=e->d_ino; entry->offset=index;
            entry->size=(uint16_t)size; entry->type=e->d_type; memcpy(entry->name,e->d_name,n);
            int node=tree->ops && tree->ops->control
                ? openat(roots[i],e->d_name,O_PATH|O_NOFOLLOW|O_CLOEXEC) : -1;
            if (node>=0) {
                struct md_control_file control={0};
                int managed=md_provider_tree_control(tree,node,&control);
                if (managed>0) {
                    if (!control.ops->stat(control.context,&st)) {
                        entry->type=S_ISCHR(st.st_mode) ? DT_CHR : entry->type; entry->ino=st.st_ino;
                    }
                    md_control_file_release(control);
                }
                close(node);
            }
            used+=size; next=index;
        }
        closedir(dir);
    }
    if (upper>=0) close(upper);
    if (lower>=0) close(lower);
    if (!error && lseek(fd,next,SEEK_SET)<0) error=-errno;
    return error ? error : (ssize_t)used;
}
int md_provider_tree_control(struct md_provider_tree *tree,int fd,struct md_control_file *out) {
    return tree->ops && tree->ops->control && fd>=0 ? tree->ops->control(tree->context,fd,out) : 0;
}

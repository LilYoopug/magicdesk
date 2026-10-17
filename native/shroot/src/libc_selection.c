#define _GNU_SOURCE
#include "libc_selection.h"
#include "libc_registry.h"
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include "image_identity.h"
#include "cooperative_entry.h"
#include "elf.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int open_guest(struct md_filesystem *fs,const char *path) {
    struct md_fs_request q={.operation=MD_FS_OPEN,.directory={-1,-1},
        .path={path,NULL},.flags=O_RDONLY|O_CLOEXEC|O_NONBLOCK};
    struct md_fs_result out;
    md_fs_view_execute(fs,&q,&out,NULL);
    if (out.error || out.host_path || out.open_completion.kind) {
        if (out.fd>=0) close(out.fd);
        return out.error ? out.error : -ENOTSUP;
    }
    return out.fd;
}
static int directory(struct md_filesystem *fs,const char *path) {
    struct md_view_location location;
    int r=md_view_walk(fs,MD_INODE_ROOT,NULL,path,0,0,0,&location);
    struct stat st;
    if (!r && fstat(location.fd,&st)) r=-errno;
    if (!r && !S_ISDIR(st.st_mode)) r=-ENOTDIR;
    md_view_location_close(&location);
    if (r!=-ENOENT) return r;
    struct md_fs_request q={.operation=MD_FS_MKDIR,.directory={-1,-1},.path={path,NULL},.mode=0755};
    struct md_fs_result out;
    md_fs_view_execute(fs,&q,&out,NULL);
    if (out.error && out.error!=-EEXIST) return out.error;
    r=md_view_walk(fs,MD_INODE_ROOT,NULL,path,0,0,0,&location);
    if (!r && fstat(location.fd,&st)) r=-errno;
    if (!r && !S_ISDIR(st.st_mode)) r=-ENOTDIR;
    md_view_location_close(&location); return r;
}
static int empty_directory(struct md_filesystem *fs,const char *path) {
    int fd=open_guest(fs,path);
    if (fd<0) return fd;
    char data[1024];
    struct md_fs_request q={.operation=MD_FS_GETDENTS,.directory={fd,-1},.capacity=sizeof(data)};
    struct md_fs_result out;
    struct md_fs_output output={.data=data,.capacity=sizeof(data)};
    int error=0;
    do {
        md_fs_view_execute(fs,&q,&out,&output);
        error=out.error;
        for (size_t at=0;!error && at<out.size;) {
            const size_t header=offsetof(struct md_inode_dirent,name);
            if (out.size-at<header+1) { error=-EIO; break; }
            const struct md_inode_dirent *entry=(const void *)(data+at);
            unsigned length=entry->size;
            if (length<header+1 || length>out.size-at || !memchr(entry->name,0,length-header)) { error=-EIO; break; }
            const char *name=entry->name;
            if (strcmp(name,".") && strcmp(name,"..")) error=-ENOTEMPTY;
            at+=length;
        }
    } while (!error && out.size);
    close(fd); return error;
}
static int attach(struct md_filesystem *fs,int bundle,const char *path) {
    struct md_view_location location;
    int r=md_view_walk(fs,MD_INODE_ROOT,NULL,path,1,0,0,&location);
    struct stat present,source;
    if (!r && (fstat(bundle,&source) || fstat(location.fd,&present))) r=-errno;
    if (!r && present.st_dev==source.st_dev && present.st_ino==source.st_ino
            && md_view_readonly(location.mount)) { md_view_location_close(&location); return 0; }
    md_view_location_close(&location);
    if (r && r!=-ENOENT) return r;
    if (fs->store->landlock) return -EACCES;
    const char *parents[]={"/opt","/opt/shroot",MD_LIBC_PREFIX,path};
    for (unsigned i=0;i<4;++i) if ((r=directory(fs,parents[i]))) return r;
    /* Mountpoint directories survive a launch, but never hide guest contents. */
    if ((r=empty_directory(fs,path))) return r;
    r=md_view_walk(fs,MD_INODE_ROOT,NULL,path,0,0,0,&location);
    if (!r) {
        struct md_mount_source mount={.fd=bundle,.policy=MD_MOUNT_READONLY|MD_MOUNT_NODEV|MD_MOUNT_NOSUID
            |MD_MOUNT_LOCK_READONLY|MD_MOUNT_LOCK_NODEV|MD_MOUNT_LOCK_NOSUID};
        r=md_view_attach_source(fs,&mount,&location,NULL);
    }
    md_view_location_close(&location);
    if (!r) md_fs_mount_table_changed(fs);
    return r;
}
void md_libc_select(struct md_filesystem *fs,const struct md_fs_request *q,
        struct md_fs_result *out,const struct md_fs_output *output) {
    md_libc_registry_refresh(fs->libc_registry);
    if (!fs->libc_registry || !md_libc_registry_count(fs->libc_registry)
            || out->error || out->host_path || out->fd<0 || !q->path[0]
            || !output || !output->data || output->capacity<sizeof(struct md_image_identity)) return;
    if (output->origin && (md_fs_anchor_policy(*output->origin)&MD_MOUNT_NOEXEC)) return;
    struct md_fs_request access={.operation=MD_FS_ACCESS,.directory={-1,-1},
        .path={q->path[0],NULL},.mode=X_OK};
    struct md_fs_result allowed;
    md_fs_view_execute(fs,&access,&allowed,NULL);
    if (allowed.error || allowed.host_path) return;
    int disabled=open_guest(fs,"/etc/shroot/libc-base");
    if (disabled>=0) { close(disabled); return; }
    if (disabled!=-ENOENT && disabled!=-ENOTDIR) return;
    char hash[65];
    if (md_libc_registry_hash(fs->libc_registry,out->fd,hash)) return;
    for (unsigned i=0;i<md_libc_registry_count(fs->libc_registry);++i) {
        const struct md_libc_manifest *m=md_libc_registry_entry(fs->libc_registry,i);
        if (m->abi!=MD_ENTRY_VERSION || strcmp(q->path[0],m->interpreter)
                || strcmp(hash,m->interpreter_hash)) continue;
        int libc=open_guest(fs,m->libc);
        if (libc<0) continue;
        char other[65]; int error=md_libc_registry_hash(fs->libc_registry,libc,other);
        close(libc);
        if (error || strcmp(other,m->libc_hash)) continue;
        int bundle=md_libc_registry_claim(fs->libc_registry,i);
        if (bundle<0) continue;
        char prefix[512],loader[1024];
        snprintf(prefix,sizeof(prefix),"%s/%s",MD_LIBC_PREFIX,m->key);
        if (attach(fs,bundle,prefix)) continue;
        snprintf(loader,sizeof(loader),"%s/%s",prefix,m->loader);
        struct md_image_identity identity;
        struct md_fs_anchor *origin=NULL;
        struct md_fs_output capture={.data=&identity,.capacity=sizeof(identity),.origin=&origin};
        struct md_fs_request request={.operation=MD_FS_OPEN_IMAGE,.directory={-1,-1},.path={loader,NULL}};
        struct md_fs_result candidate;
        md_fs_view_execute(fs,&request,&candidate,&capture);
        if (!candidate.error && !candidate.host_path && candidate.fd>=0
                && !(md_fs_anchor_policy(origin)&MD_MOUNT_NOEXEC)
                && !md_elf_validate(candidate.fd,1)) {
            close(out->fd); *out=candidate;
            memcpy(output->data,&identity,sizeof(identity));
            if (output->origin) { md_fs_anchor_release(*output->origin); *output->origin=origin; origin=NULL; }
            md_fs_anchor_release(origin); return;
        }
        if (candidate.fd>=0) close(candidate.fd);
        md_fs_anchor_release(origin);
    }
}

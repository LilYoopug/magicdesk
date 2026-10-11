#define _GNU_SOURCE
#include "fs_control.h"
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct provider { unsigned refs,calls; int error,prepare_error,untyped; };
static void *retain(void *context) { struct provider *p=context; ++p->refs; return p; }
static void release(void *context) { struct provider *p=context; assert(p->refs); --p->refs; }
static const struct md_control_file_ops ops={.retain=retain,.release=release};
static int publish(void *context,const struct md_control_file_ops *operations,void *file,
        const struct md_identity *id,int flags) {
    (void)id; (void)flags;
    struct provider *p=context;
    assert(file==p && operations==&ops && p->refs);
    ++p->calls; return p->error;
}
static int prepare(void *context,int fd,int flags,const struct md_identity *id,
        struct md_fs_anchor *origin,struct md_control_file *file) {
    (void)fd; (void)flags; (void)id;
    struct provider *p=context;
    assert(origin && md_fs_anchor_fd(origin)>=0);
    if (!p->untyped) *file=(struct md_control_file){&ops,retain(p)};
    return p->prepare_error;
}
static int metadata(void *context,int fd,struct stat *st) {
    (void)context; return fstat(fd,st) ? -errno : 0;
}
static unsigned descriptors(void) {
    DIR *dir=opendir("/proc/self/fd"); assert(dir);
    unsigned count=0;
    for (struct dirent *entry;(entry=readdir(dir));)
        if (strcmp(entry->d_name,".") && strcmp(entry->d_name,"..")) ++count;
    closedir(dir); return count;
}
void test_fs_control(const char *base) {
    char path[PATH_MAX]; snprintf(path,sizeof(path),"%s/control-store",base);
    struct md_inode_store *store=NULL; assert(!md_inode_store_open(path,1,&store));
    struct md_filesystem fs={.store=store};
    int fd=md_inode_open(store,-1,"/file",O_CREAT|O_RDWR,0600); assert(fd>=0);
    assert(write(fd,"preserved",9)==9);
    struct provider provider={.refs=1};
    const struct md_fs_control_source source={&provider,metadata,prepare,0x1234};
    struct md_fs_anchor *origin=NULL;
    struct md_fs_output output={.origin=&origin,.control=publish,.control_context=&provider};
    unsigned before=descriptors();
    for (unsigned i=0;i<24;++i) {
        for (unsigned mode=0;mode<6;++mode) {
            struct md_fs_result out={.fd=-1};
            provider.error=mode==1 ? -EACCES : 0;
            provider.prepare_error=mode==2 ? -EIO : 0;
            provider.untyped=mode==5;
            unsigned calls=provider.calls;
            int flags=O_RDWR|O_TRUNC|(mode==4 ? O_DIRECTORY : 0);
            struct md_fs_request q={.operation=MD_FS_OPEN,.flags=(unsigned)flags};
            assert(md_fs_control_operation(&fs,NULL,NULL,fd,&source,&q,&out,mode==3 ? NULL : &output));
            int error=out.error;
            if (mode>=1 && mode<=4) {
                assert(error==(mode==1 ? -EACCES : mode==2 ? -EIO : mode==3 ? -EOPNOTSUPP : -ENOTDIR));
                assert(out.fd==-1 && !origin);
                assert(out.requires_control==(mode==3));
            } else {
                assert(!error && out.fd>=0 && origin);
                char contents[16]={0}; assert(read(out.fd,contents,sizeof(contents))==9);
                assert(!strcmp(contents,"preserved"));
                assert(fcntl(out.fd,F_GETFD)&FD_CLOEXEC);
                close(out.fd); md_fs_anchor_release(origin); origin=NULL;
            }
            assert(provider.refs==1 && provider.calls==calls+(mode==0 || mode==1));
            assert(descriptors()==before);
        }
        struct md_fs_result out={.fd=-1};
        unsigned calls=provider.calls;
        assert(md_fs_control_publish(-EMFILE,(struct md_control_file){&ops,&provider},NULL,
            NULL,O_RDONLY,&out,&output)==-EMFILE);
        assert(provider.calls==calls && out.fd==-1 && !origin);
        int carrier=fcntl(fd,F_DUPFD_CLOEXEC,3); assert(carrier>=0);
        assert(md_fs_control_publish(carrier,(struct md_control_file){&ops,&provider},NULL,
            NULL,O_RDONLY,&out,NULL)==-EOPNOTSUPP);
        assert(fcntl(carrier,F_GETFD)==-1 && errno==EBADF);
        assert(descriptors()==before);
        for (unsigned fail=0;fail<2;++fail) {
            out=(struct md_fs_result){.fd=-1};
            provider.error=fail ? -ENOSPC : 0;
            carrier=fcntl(fd,F_DUPFD_CLOEXEC,3); assert(carrier>=0);
            assert(md_fs_control_publish(carrier,(struct md_control_file){&ops,&provider},NULL,
                NULL,O_RDWR,&out,&output)==provider.error);
            assert(!origin && provider.refs==1);
            if (fail) assert(out.fd==-1 && fcntl(carrier,F_GETFD)==-1 && errno==EBADF);
            else { assert(out.fd==carrier); close(out.fd); }
            assert(descriptors()==before);
        }
    }
    struct md_view_mount mount={.id=37};
    struct md_fs_request q={.operation=MD_FS_STAT};
    struct md_fs_result out={.fd=-1};
    assert(md_fs_control_operation(&fs,NULL,&mount,fd,&source,&q,&out,NULL));
    assert(!out.error && out.info.mount_id==37 && out.info.size==9);
    q.operation=MD_FS_ACCESS; q.flags=~0U;
    assert(md_fs_control_operation(&fs,NULL,&mount,fd,&source,&q,&out,NULL) && out.error==-EINVAL);
    mount.policy.local|=MD_MOUNT_READONLY; q.flags=0; q.mode=W_OK;
    assert(md_fs_control_operation(&fs,NULL,&mount,fd,&source,&q,&out,NULL) && out.error==-EROFS);
    q.operation=MD_FS_OPEN; q.flags=O_RDWR;
    assert(md_fs_control_operation(&fs,NULL,&mount,fd,&source,&q,&out,NULL) && out.error==-EROFS);
    q.flags=O_CREAT|O_EXCL;
    assert(md_fs_control_operation(&fs,NULL,&mount,fd,&source,&q,&out,NULL) && out.error==-EEXIST);
    q.operation=MD_FS_STATFS;
    struct md_fs_statfs statfs={0}; struct md_fs_output stats={.data=&statfs,.capacity=sizeof(statfs)};
    out=(struct md_fs_result){.fd=-1};
    assert(md_fs_control_operation(&fs,NULL,&mount,fd,&source,&q,&out,&stats));
    assert(!out.error && statfs.type==source.filesystem && !statfs.blocks && !statfs.files);
    q.operation=MD_FS_UNLINK;
    assert(!md_fs_control_operation(&fs,NULL,&mount,fd,&source,&q,&out,NULL));
    assert(descriptors()==before);
    close(fd); md_inode_store_close(store);
    puts("PASS virtual file publication: prepare/reopen/host failures, carrier ownership and exact FD cleanup");
}

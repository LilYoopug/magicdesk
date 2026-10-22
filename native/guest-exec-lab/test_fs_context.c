#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "fs_storage.h"
#include "inode_internal.h"
#include "mount_graph.h"
#include "procfs_view.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static unsigned descriptors(void) {
    DIR *d=opendir("/proc/self/fd"); assert(d);
    unsigned n=0; struct dirent *e;
    while ((e=readdir(d))) if (e->d_name[0]!='.') ++n;
    assert(!closedir(d)); return n;
}
static int capture(void *out,const struct md_control_file_ops *ops,void *data,
        const struct md_identity *id,int flags,struct md_fs_anchor *origin) {
    (void)id; (void)flags; (void)origin;
    if (!out) return -ENOMEM;
    *(struct md_control_file *)out=(struct md_control_file){ops,ops->retain(data)}; return 0;
}
static struct md_fs_result call(struct md_filesystem *fs,struct md_fs_request q,const struct md_fs_output *out) {
    assert(!md_fs_request_validate(&q));
    struct md_fs_result result;
    md_fs_execute(fs,&q,&result,out); return result;
}
static void pressure_probe(const char *base) {
    int root=open(base,O_PATH|O_DIRECTORY|O_CLOEXEC); assert(root>=0);
    assert(md_procfs_pressure_probe(root)==0);
    assert(!mkdirat(root,"pressure",0700));
    const char *paths[]={"pressure/cpu","pressure/memory","pressure/io"};
    const char sample[]="some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
    for (unsigned i=0;i<3;++i) {
        int fd=openat(root,paths[i],O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600); assert(fd>=0);
        assert(write(fd,sample,sizeof(sample)-1)==sizeof(sample)-1);
        assert(!close(fd));
        assert(md_procfs_pressure_probe(root)==(i==2));
    }
    assert(!fchmodat(root,paths[1],0000,0));
    assert(md_procfs_pressure_probe(root)==0);
    assert(!fchmodat(root,paths[1],0600,0));
    int fd=openat(root,paths[1],O_WRONLY|O_TRUNC|O_CLOEXEC); assert(fd>=0);
    assert(!close(fd));
    assert(md_procfs_pressure_probe(root)==-EIO);
    for (unsigned i=0;i<3;++i) assert(!unlinkat(root,paths[i],0));
    assert(!unlinkat(root,"pressure",AT_REMOVEDIR));
    assert(md_procfs_pressure_probe(-1)==-EBADF);
    assert(!close(root));
    puts("PASS proc PSI admission: complete, missing, partial, denied and unexpected errors");
}
void test_fs_context(const char *base) {
    unsigned baseline=descriptors();
    pressure_probe(base);
    char path[PATH_MAX]; snprintf(path,sizeof(path),"%s/fs-context",base);
    struct md_inode_store *store=NULL; assert(!md_inode_store_open(path,1,&store));
    struct md_identity root=md_identity_new(0,0); store->identity=&root;
    struct md_fs_storage_cache cache={0};
    struct md_filesystem fs={.store=store,.storage=&cache};
    assert(!md_fs_mounts_open(&fs,NULL,0));
    for (unsigned cycle=0;cycle<24;++cycle) {
        for (unsigned stage=0;stage<3;++stage) {
            struct md_control_file control={0};
            struct md_fs_output out={.control=capture,.control_context=&control};
            struct md_fs_request q={.operation=MD_FS_FSOPEN,.directory={-1,-1},
                .path={"tmpfs",NULL},.flags=O_RDWR|O_CLOEXEC};
            struct md_fs_result opened=call(&fs,q,&out); assert(!opened.error && opened.fd>=0 && control.ops);
            struct md_fs_anchor *anchor=NULL;
            int mounted=-1;
            if (stage) {
                q=(struct md_fs_request){.operation=MD_FS_FSCONFIG,.directory={opened.fd,-1},
                    .control=control,.mode=FSCONFIG_CMD_CREATE};
                assert(!call(&fs,q,NULL).error);
            }
            if (stage==2) {
                q.operation=MD_FS_FSMOUNT; q.mode=0; q.flags=O_PATH|O_CLOEXEC;
                struct md_fs_result mount=call(&fs,q,&(struct md_fs_output){.origin=&anchor});
                assert(!mount.error && mount.fd>=0 && anchor);
                mounted=mount.fd;
                struct md_mount_namespace *copy=NULL;
                struct md_fs_location copied_root;
                assert(!md_fs_mounts_copy(&fs,&(struct md_fs_location){0},&copy,&copied_root));
                md_mount_namespace_release(copy);
                struct md_mount_graph_parcel parcel={0};
                assert(!md_mount_graph_export(fs.mounts,store->lifetime->root,&parcel));
                struct md_mount_namespace *received=NULL;
                assert(!md_mount_graph_import(&parcel,&received));
                assert(received->tree && received->tree->count);
                for (unsigned i=0;i<received->tree->count;++i) {
                    const struct md_view_mount *m=&received->tree->mounts[i];
                    assert(!m->id || (m->detached && !m->parent));
                }
                md_mount_graph_parcel_close(&parcel); md_mount_namespace_release(received);
            }
            control.ops->release(control.context); close(opened.fd);
            if (mounted>=0) close(mounted);
            md_fs_anchor_release(anchor);
            assert(!md_view_mount_collect(&fs));
        }
    }
    unsigned before=descriptors();
    struct md_fs_result rejected=call(&fs,(struct md_fs_request){.operation=MD_FS_FSOPEN,
        .directory={-1,-1},.path={"tmpfs",NULL},.flags=O_RDWR},&(struct md_fs_output){.control=capture});
    assert(rejected.error==-ENOMEM && rejected.fd<0 && descriptors()==before);
    md_fs_storage_close(&cache); md_fs_mounts_close(&fs);
    store->identity=NULL; md_identity_release(&root); md_inode_store_close(store);
    assert(descriptors()==baseline);
    puts("PASS fscontext ownership: cancellation, namespace copy, detached graph transfer and exact FD cleanup");
}

#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <sys/mount.h>
#include <sys/file.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static struct md_fs_result request(struct md_filesystem *fs,unsigned operation,const char *path,
        unsigned flags,unsigned mode,uint64_t resolve,void *data,size_t size) {
    struct md_fs_result out;
    struct md_fs_request q={.operation=operation,.directory={-1,-1},.path={path,NULL},
        .flags=flags,.mode=mode,.resolve=resolve};
    md_fs_execute(fs,&q,&out,&(struct md_fs_output){.data=data,.capacity=size});
    return out;
}
static void dynamic_queries(const char *base) {
    char store[PATH_MAX],native[PATH_MAX],host[PATH_MAX],targets[24][32];
    snprintf(store,sizeof(store),"%s/query-store",base);
    snprintf(native,sizeof(native),"%s/query-native",base); assert(!mkdir(native,0700));
    snprintf(host,sizeof(host),"%s/link",native); assert(!symlink("native",host));
    snprintf(host,sizeof(host),"%s/native",native);
    int hostfd=open(host,O_CREAT|O_WRONLY|O_CLOEXEC,0600); assert(hostfd>=0);
    assert(write(hostfd,"native",6)==6); close(hostfd);
    struct md_inode_store *s=NULL; assert(!md_inode_store_open(store,1,&s));
    assert(!md_inode_mkdir(s,-1,"/tree",0700));
    assert(!md_inode_symlink(s,"target",-1,"/tree/link"));
    int fd=md_inode_create(s,-1,"/tree/target",0600); assert(fd>=0);
    assert(write(fd,"data",4)==4); close(fd);
    struct md_identity root=md_identity_new(0,0); s->identity=&root;
    struct md_filesystem fs={.store=s};
    for (unsigned i=0;i<24;++i) {
        snprintf(targets[i],sizeof(targets[i]),"/mount%u",i);
        assert(!md_inode_mkdir(s,-1,targets[i],0700));
    }
    struct md_fs_attachment attachment={native,targets[0],0};
    assert(!md_fs_mounts_open(&fs,&attachment,1));
    for (unsigned i=1;i<24;++i) {
        struct md_fs_request bind={.operation=MD_FS_MOUNT,.mode=MD_FS_MOUNT_BIND,.flags=MS_BIND,
            .directory={-1,-1},.path={targets[i],targets[0]}};
        struct md_fs_result result; md_fs_execute(&fs,&bind,&result,NULL);
        if (result.error) fprintf(stderr,"query bind %u: %d\n",i,result.error);
        assert(!result.error);
    }
    char buffer[64];
    struct md_inode_statistics stats={0}; md_inode_measure(s,&stats);
    struct md_fs_result r=request(&fs,MD_FS_READLINK,"/tree/link",0,0,0,buffer,sizeof(buffer));
    assert(!r.error && r.size==6 && !memcmp(buffer,"target",6));
    assert(!stats.walk_components && !stats.walk_materializations && stats.lock.calls==1);
    md_inode_measure(s,NULL);
    struct md_inode_store *peer=NULL; assert(!md_inode_store_open(store,0,&peer));
    struct md_fs_context context; assert(!md_fs_context_begin(&fs,0,0,&context));
    struct md_fs_request query={.operation=MD_FS_STAT,.directory={-1,-1},.path={"/tree/target",NULL}};
    assert(md_fs_context_operation_window(&context,&query,0)==s);
    stats=(struct md_inode_statistics){0}; md_inode_measure(s,&stats);
    assert(!md_inode_operation_window_begin(s));
    for (unsigned i=0;i<16;++i) {
        md_fs_context_execute(&context,&query,&r,NULL);
        assert(!r.error && r.info.size==4);
    }
    assert(stats.lock.calls==1 && stats.version.calls==1 && stats.path_prefix_hits);
    assert(flock(peer->objects,LOCK_EX|LOCK_NB)<0 && errno==EWOULDBLOCK);
    query.path[0]="/mount23/native";
    md_fs_context_execute(&context,&query,&r,NULL);
    assert(!r.error && r.info.size==6 && !s->locked && s->operation_window_paused);
    assert(!flock(peer->objects,LOCK_EX|LOCK_NB) && !flock(peer->objects,LOCK_UN));
    query.path[0]="/tree/target";
    md_fs_context_execute(&context,&query,&r,NULL);
    assert(!r.error && r.info.size==4 && !s->locked);
    assert(!md_inode_operation_window_end(s));
    md_fs_context_end(&context); md_inode_measure(s,NULL); md_inode_store_close(peer);
    /* The general walker also completes observations in its existing scope,
     * including symlinks and native crossings back into the inode store. */
    const char *paths[]={"/tree/link","/mount0/../tree/link"};
    for (unsigned i=0;i<2;++i) {
        stats=(struct md_inode_statistics){0}; md_inode_measure(s,&stats);
        r=request(&fs,MD_FS_READLINK,paths[i],0,0,RESOLVE_IN_ROOT,buffer,sizeof(buffer));
        assert(!r.error && r.size==6 && !memcmp(buffer,"target",6));
        assert(stats.walk_components && !stats.walk_materializations);
        r=request(&fs,MD_FS_STAT,paths[i],0,MD_FS_STAT_MOUNT,RESOLVE_IN_ROOT,NULL,0);
        assert(!r.error && r.info.size==4 && r.info.mount_id==fs.mounts->base.id);
        r=request(&fs,MD_FS_ACCESS,paths[i],0,R_OK|W_OK,RESOLVE_IN_ROOT,NULL,0);
        assert(!r.error && !stats.walk_materializations);
        r=request(&fs,MD_FS_READLINK,"/tree/target",0,0,RESOLVE_IN_ROOT,buffer,sizeof(buffer));
        assert(r.error==-EINVAL);
        r=request(&fs,MD_FS_STAT,"/tree/target/",0,0,RESOLVE_IN_ROOT,NULL,0);
        assert(r.error==-ENOTDIR);
        assert(!s->locked && !s->read_depth); md_inode_measure(s,NULL);
    }
    /* A dynamically added file bind covers a native leaf without requiring
     * a database object ID. Removing it invalidates the same placement index. */
    struct md_fs_request mount={.operation=MD_FS_MOUNT,.mode=MD_FS_MOUNT_BIND,.flags=MS_BIND,
        .directory={-1,-1},.path={"/tree/target","/mount0/native"}};
    md_fs_execute(&fs,&mount,&r,NULL); assert(!r.error);
    r=request(&fs,MD_FS_STAT,"/tree/target",0,0,0,NULL,0);
    assert(!r.error && r.info.size==6);
    mount.mode=MD_FS_MOUNT_UMOUNT; mount.flags=MNT_DETACH; mount.path[1]=NULL;
    md_fs_execute(&fs,&mount,&r,NULL); assert(!r.error);
    r=request(&fs,MD_FS_STAT,"/tree/target",0,0,0,NULL,0);
    assert(!r.error && r.info.size==4);
    mount=(struct md_fs_request){.operation=MD_FS_MOUNT,.mode=MD_FS_MOUNT_BIND,.flags=MS_BIND,
        .directory={-1,-1},.path={"/tree","/mount0"}};
    md_fs_execute(&fs,&mount,&r,NULL); assert(!r.error);
    r=request(&fs,MD_FS_READLINK,"/tree/link",0,0,0,buffer,sizeof(buffer));
    assert(!r.error && r.size==6 && !memcmp(buffer,"native",6));
    mount.mode=MD_FS_MOUNT_UMOUNT; mount.flags=MNT_DETACH; mount.path[1]=NULL;
    md_fs_execute(&fs,&mount,&r,NULL); assert(!r.error);
    r=request(&fs,MD_FS_READLINK,"/tree/link",0,0,0,buffer,sizeof(buffer));
    assert(!r.error && r.size==6 && !memcmp(buffer,"target",6));
    md_fs_mounts_close(&fs); md_inode_store_close(s);
    puts("PASS dynamic mount guards and in-walk stat/readlink/access: 24 mounts, retained window, released crossing, warm-prefix directory/file bind and detach");
}

void test_path_walk(const char *base) {
    dynamic_queries(base);
    char store[PATH_MAX], native[PATH_MAX], path[PATH_MAX]="", leaf[PATH_MAX];
    snprintf(store,sizeof(store),"%s/walk-store",base);
    snprintf(native,sizeof(native),"%s/walk-native",base);
    assert(!mkdir(native,0700));
    struct md_inode_store *s=NULL; assert(!md_inode_store_open(store,1,&s));
    assert(!md_inode_mkdir(s,-1,"/native",0700));
    struct md_filesystem fs={.store=s};
    struct md_fs_attachment attachment={native,"/native",0};
    assert(!md_fs_mounts_open(&fs,&attachment,1));
    uint64_t admissions=0;
    for (unsigned depth=1;depth<=24;++depth) {
        strcat(path,"/dir"); assert(!md_inode_mkdir(s,-1,path,0700));
        snprintf(leaf,sizeof(leaf),"%s/value",path);
        int fd=md_inode_create(s,-1,leaf,0600); assert(fd>=0); close(fd);
        struct md_inode_statistics stats={0}; md_inode_measure(s,&stats);
        struct md_view_location result;
        assert(!md_view_walk(&fs,-1,NULL,leaf,1,0,0,&result));
        assert(result.fd>=0 && result.parent>=0 && !strcmp(result.name,"value"));
        assert(stats.walk_components==depth+1 && stats.walk_materializations==2);
        if (depth==1) admissions=stats.lock.calls;
        else assert(stats.lock.calls==admissions);
        assert(!s->locked && !s->read_depth);
        md_view_location_close(&result);
        md_inode_measure(s,NULL);
    }
    /* Relative symlinks retain the logical parent. A native crossing must
     * release the snapshot before a later lookup reenters this same store. */
    assert(!md_inode_symlink(s,"dir/dir",-1,"/short"));
    struct md_view_location result;
    assert(!md_view_walk(&fs,-1,NULL,"/short/value",1,0,0,&result));
    md_view_location_close(&result);
    assert(!md_view_walk(&fs,-1,NULL,"/native/../short/value",1,0,0,&result));
    md_view_location_close(&result);
    assert(md_view_walk(&fs,-1,NULL,"/short/value/child",1,0,0,&result)==-ENOTDIR);
    assert(!s->locked && !s->read_depth);
    assert(!md_view_walk(&fs,-1,NULL,"/short/absent",1,1,0,&result));
    assert(result.fd==-1 && result.parent>=0); md_view_location_close(&result);
    /* A fresh operation sees another connection's rename, including when the
     * previously resolved parent remains open as a logical dirfd. */
    assert(!md_view_walk(&fs,-1,NULL,"/short",1,0,0,&result));
    struct md_inode_store *writer=NULL; assert(!md_inode_store_open(store,0,&writer));
    assert(!md_inode_rename(writer,-1,"/dir/dir",-1,"/moved",0));
    struct md_view_location child;
    assert(!md_view_walk(&fs,result.fd,NULL,"value",1,0,0,&child));
    md_view_location_close(&child); md_view_location_close(&result);
    assert(md_view_walk(&fs,-1,NULL,"/short/value",1,0,0,&result)==-ENOENT);
    assert(!md_view_walk(&fs,-1,NULL,"/moved/value",1,0,0,&result));
    md_view_location_close(&result);
    md_inode_store_close(writer); md_fs_mounts_close(&fs); md_inode_store_close(s);
    printf("PASS logical walk: 24 depths, two result FDs and %llu admissions independent of depth; symlinks, native crossings, errors and independent rename\n",
        (unsigned long long)admissions);
}

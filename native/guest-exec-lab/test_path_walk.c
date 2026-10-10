#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void test_path_walk(const char *base) {
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

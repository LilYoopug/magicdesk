#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <unistd.h>

static unsigned descriptors(void) {
    DIR *dir=opendir("/proc/self/fd"); assert(dir);
    unsigned n=0; struct dirent *entry;
    while ((entry=readdir(dir))) if (strcmp(entry->d_name,".") && strcmp(entry->d_name,"..")) ++n;
    closedir(dir); return n;
}
static int opened(struct md_filesystem *fs, const char *path, unsigned flags) {
    struct md_fs_request q={.operation=MD_FS_OPEN,.directory={-1,-1},.path={path,NULL},.flags=flags};
    struct md_fs_result r; md_fs_execute(fs,&q,&r,NULL);
    assert(!r.error && r.fd>=0); return r.fd;
}
static uint64_t mount_id(struct md_filesystem *fs, const char *path) {
    struct md_fs_request q={.operation=MD_FS_STAT,.directory={-1,-1},.path={path,NULL},.mode=MD_FS_STAT_MOUNT};
    struct md_fs_result r; md_fs_execute(fs,&q,&r,NULL);
    assert(!r.error && r.info.mount_id); return r.info.mount_id;
}
static void rollback(struct md_filesystem *fs, const struct md_fs_location *root) {
    struct rlimit original; assert(!getrlimit(RLIMIT_NOFILE,&original));
    struct rlimit limited=original; if (limited.rlim_cur>256) limited.rlim_cur=256;
    for (unsigned budget=0; budget<=4; ++budget) {
        unsigned before=descriptors();
        assert(!setrlimit(RLIMIT_NOFILE,&limited));
        int held[256]; unsigned count=0;
        for (;;) {
            int fd=open("/dev/null",O_RDONLY|O_CLOEXEC);
            if (fd<0) { assert(errno==EMFILE); break; }
            assert(count<256); held[count++]=fd;
        }
        assert(count>=budget);
        for (unsigned i=0; i<budget; ++i) close(held[--count]);
        struct md_mount_namespace *copy=NULL;
        struct md_fs_location selected={.mount=UINT32_MAX,.object="unchanged"};
        assert(md_fs_mounts_copy(fs,root,&copy,&selected)==-EMFILE);
        assert(!copy && selected.mount==UINT32_MAX && !strcmp(selected.object,"unchanged"));
        while (count) close(held[--count]);
        assert(!setrlimit(RLIMIT_NOFILE,&original));
        assert(descriptors()==before);
    }
}
void test_mount_copy(const char *base) {
    unsigned before=descriptors();
    char store[PATH_MAX], source[2][PATH_MAX], path[PATH_MAX], moved[PATH_MAX];
    snprintf(store,sizeof(store),"%s/copy-store",base);
    for (unsigned i=0; i<2; ++i) {
        snprintf(source[i],sizeof(source[i]),"%s/copy-source-%u",base,i);
        assert(!mkdir(source[i],0700));
    }
    snprintf(path,sizeof(path),"%s/scope",source[0]); assert(!mkdir(path,0700));
    snprintf(path,sizeof(path),"%s/scope/child",source[0]); assert(!mkdir(path,0700));
    snprintf(path,sizeof(path),"%s/value",source[1]);
    int fd=open(path,O_CREAT|O_RDWR|O_CLOEXEC,0600); assert(fd>=0);
    assert(write(fd,"value",5)==5); close(fd);
    struct md_inode_store *store_owner=NULL; assert(!md_inode_store_open(store,1,&store_owner));
    assert(!md_inode_mkdir(store_owner,-1,"/tree",0700));
    assert(!md_inode_mkdir(store_owner,-1,"/jail",0700));
    assert(!md_inode_mkdir(store_owner,-1,"/dev",0755));
    assert(!md_inode_mkdir(store_owner,-1,"/dev/shm",01777));
    struct md_filesystem fs={.store=store_owner};
    struct md_fs_attachment entries[]={{source[0],"/tree",1},{source[1],"/tree/scope/child",0}};
    assert(!md_fs_mounts_open(&fs,entries,2));
    int scope=opened(&fs,"/tree/scope",O_PATH|O_DIRECTORY);
    struct md_fs_location root; assert(!md_fs_root_capture(&fs,scope,NULL,&root)); close(scope);
    /* Populate a cache that the copied topology must not duplicate. */
    for (unsigned i=0; i<32; ++i) {
        snprintf(path,sizeof(path),"%s/cache-%u",source[1],i);
        fd=open(path,O_CREAT|O_RDWR|O_CLOEXEC,0600); assert(fd>=0); close(fd);
        snprintf(path,sizeof(path),"/tree/scope/child/cache-%u",i);
        fd=opened(&fs,path,O_RDONLY); close(fd);
    }
    unsigned original_objects=fs.mounts->tree->objects;
    assert(original_objects>=33);
    struct md_fs_location copied_root;
    struct md_filesystem copy={.store=store_owner};
    unsigned prior=descriptors();
    assert(!md_fs_mounts_copy(&fs,&root,&copy.mounts,&copied_root));
    assert(descriptors()==prior+5 && copy.mounts->tree->objects==1);
    assert(copied_root.mount!=root.mount && strcmp(copied_root.object,root.object));
    assert(md_fs_root_select(&copy,&root)==-ESTALE);
    assert(md_fs_root_select(&fs,&copied_root)==-ESTALE);
    assert(fs.mounts->tree->objects==original_objects);
    assert(copy.mounts->tree->mounts[1].parent==&copy.mounts->tree->mounts[0]);
    assert(copy.mounts->tree->mounts[0].readonly && !copy.mounts->tree->mounts[1].readonly);
    for (unsigned i=0; i<2; ++i) {
        struct md_view_mount *a=&fs.mounts->tree->mounts[i], *b=&copy.mounts->tree->mounts[i];
        assert(a->id!=b->id && a->source!=b->source && a->target!=b->target);
    }
    const char *paths[]={"/","/dev/shm","/tree","/tree/scope/child/value"};
    for (unsigned i=0; i<4; ++i) assert(mount_id(&fs,paths[i])!=mount_id(&copy,paths[i]));
    uint64_t native_a,native_b,again;
    assert(!md_fs_native_mount(&fs,1234,&native_a) && !md_fs_native_mount(&copy,1234,&native_b));
    assert(native_a!=native_b);
    assert(!md_fs_native_mount(&copy,1234,&again) && again==native_b);
    assert(!md_fs_native_mount(&fs,1234,&again) && again==native_a);
    /* Model a policy change in the candidate, not a guest remount syscall. */
    copy.mounts->tree->mounts[1].readonly=1;
    struct md_fs_request q={.operation=MD_FS_OPEN,.directory={-1,-1},
        .path={"/tree/scope/child/value",NULL},.flags=O_RDWR};
    struct md_fs_result r; md_fs_execute(&copy,&q,&r,NULL); assert(r.error==-EROFS);
    md_fs_execute(&fs,&q,&r,NULL); assert(!r.error); close(r.fd);
    copy.mounts->tree->mounts[1].readonly=0;
    struct md_fs_location bad=root; ++bad.mount;
    struct md_mount_namespace *failed=NULL;
    prior=descriptors();
    assert(md_fs_mounts_copy(&fs,&bad,&failed,&bad)==-ESTALE && !failed);
    assert(descriptors()==prior);
    rollback(&fs,&root);

    /* No readable/writable OFD is retained by either the object registry or a
     * tree copy. A closed writer delivers EOF, and a closed lock owner unlocks. */
    int locked=opened(&fs,"/tree/scope/child/value",O_RDWR);
    snprintf(path,sizeof(path),"%s/value",source[1]);
    int independent=open(path,O_RDWR|O_CLOEXEC); assert(independent>=0);
    assert(!flock(locked,LOCK_EX|LOCK_NB));
    assert(flock(independent,LOCK_EX|LOCK_NB)<0 && errno==EWOULDBLOCK);
    struct flock lock={.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_len=1};
    assert(!fcntl(locked,F_OFD_SETLK,&lock));
    assert(fcntl(independent,F_OFD_SETLK,&lock)<0 && (errno==EAGAIN || errno==EACCES));
    /* Shell SELinux may reject native mkfifo. The runtime's guest FIFO backing
     * is also a kernel pipe, so exercise pin lifetime without native mknod. */
    int stream[2]; assert(!pipe2(stream,O_NONBLOCK|O_CLOEXEC));
    int reader=stream[0], writer=stream[1];
    struct md_view_object *object;
    assert(!md_view_record(&fs,writer,&fs.mounts->tree->mounts[1],&object));
    struct md_filesystem retained={.store=store_owner};
    struct md_fs_location retained_root;
    assert(!md_fs_mounts_copy(&fs,&root,&retained.mounts,&retained_root));
    close(writer); char bytes[4096]; assert(read(reader,bytes,1)==0); close(reader);
    close(locked);
    assert(!flock(independent,LOCK_EX|LOCK_NB) && !fcntl(independent,F_OFD_SETLK,&lock));
    close(independent);
    md_fs_mounts_close(&retained);

    snprintf(path,sizeof(path),"%s/scope",source[0]);
    snprintf(moved,sizeof(moved),"%s/renamed",source[0]); assert(!rename(path,moved));
    assert(!md_fs_root_select(&copy,&copied_root));
    md_fs_mounts_close(&fs);
    fd=opened(&copy,"/../../child/value",O_RDONLY);
    assert(read(fd,bytes,5)==5 && !memcmp(bytes,"value",5)); close(fd);
    int table=md_fs_mount_table(&copy,1,O_RDONLY); assert(table>=0);
    ssize_t size=read(table,bytes,sizeof(bytes)-1); assert(size>0); bytes[size]=0; close(table);
    assert(strstr(bytes," / ro - none attachment ro") && strstr(bytes," /child rw - none attachment rw"));
    assert(!strstr(bytes,"/tree") && !strstr(bytes,base));
    md_fs_mounts_close(&copy);

    /* Empty views and inode roots need no attachment tree or descriptor cache. */
    assert(!md_fs_mounts_open(&fs,NULL,0));
    fd=md_inode_open(store_owner,-1,"/jail",O_PATH|O_DIRECTORY,0); assert(fd>=0);
    assert(!md_fs_root_capture(&fs,fd,NULL,&root)); close(fd);
    prior=descriptors();
    assert(!md_fs_mounts_copy(&fs,&root,&copy.mounts,&copied_root));
    assert(!copy.mounts->tree && !copy.mounts->native_ids && descriptors()==prior);
    assert(!copied_root.mount && !strcmp(copied_root.object,root.object));
    assert(!md_fs_root_select(&copy,&copied_root));
    fd=opened(&copy,"/",O_PATH|O_DIRECTORY); close(fd);
    copy.native_root=NULL; store_owner->root_id=NULL;
    md_fs_mounts_close(&copy); md_fs_mounts_close(&fs); md_inode_store_close(store_owner);
    assert(descriptors()==before);
    puts("PASS mount-tree copy, distinct IDs, explicit root rebasing and independent policy");
    puts("PASS mount-copy rollback at every descriptor allocation, rename and source teardown");
    puts("PASS lazy object caches, FIFO EOF and flock/OFD-lock release with live mount views");
}

#define _GNU_SOURCE
#include "network_resolver.h"
#include "network_profile.h"
#include "fs_mounts.h"
#include "fs_storage.h"
#include "inode_internal.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void write_resolver(struct md_inode_store *store,const char *text) {
    int fd=md_inode_open(store,-1,"/etc/resolv.conf",O_WRONLY|O_CREAT|O_TRUNC,0644);
    assert(fd>=0 && write(fd,text,strlen(text))==(ssize_t)strlen(text)); close(fd);
}
static int open_resolver(struct md_filesystem *fs,int flags) {
    struct md_fs_request q={.operation=MD_FS_OPEN,.directory={-1,-1},
        .path={"/etc/resolv.conf",NULL},.flags=(unsigned)flags};
    struct md_fs_result result;
    md_fs_execute(fs,&q,&result,NULL);
    return result.error ? result.error : result.fd;
}
static void contents(struct md_filesystem *fs,const char *expected) {
    char text[512]; int fd=open_resolver(fs,O_RDONLY); assert(fd>=0);
    ssize_t count=read(fd,text,sizeof(text)-1); assert(count>=0); text[count]=0;
    assert(!strcmp(text,expected)); close(fd);
}
void test_network_resolver(const char *base) {
    char path[4096]; snprintf(path,sizeof(path),"%s/launch-resolver",base);
    struct md_inode_store *store=NULL;
    assert(!md_inode_store_open(path,1,&store));
    assert(!md_inode_mkdir(store,-1,"/etc",0755));
    const char *original="search shroot.test\nnameserver 127.0.0.53\nnameserver 192.0.2.53\noptions timeout:1\n";
    write_resolver(store,original);
    struct md_fs_storage_cache storage[2]={{0},{0}};
    struct md_filesystem first={.store=store,.storage=&storage[0]},second={.store=store,.storage=&storage[1]};
    assert(!md_fs_mounts_open(&first,NULL,0) && !md_fs_mounts_open(&second,NULL,0));
    struct md_network_profile profile={0};
    assert(!md_network_profile_add(&profile,"--network","bridge"));
    assert(!md_network_resolver_prepare(&first,&profile));
    contents(&first,"search shroot.test\nnameserver 192.0.2.53\noptions timeout:1\n");
    assert(!md_network_profile_add(&profile,"--dns","198.51.100.53"));
    assert(!md_network_resolver_prepare(&second,&profile));
    contents(&second,"nameserver 198.51.100.53\n");
    int a=open_resolver(&first,O_RDONLY),b=open_resolver(&first,O_RDONLY);
    assert(a>=0 && b>=0);
    char byte; assert(read(a,&byte,1)==1 && lseek(b,0,SEEK_CUR)==0);
    assert(open_resolver(&first,O_WRONLY)==-EROFS);
    assert(md_fs_mount_contents(&first,"/etc","x",1)==-EISDIR);
    assert(md_fs_mount_contents(&first,"/missing","x",1)==-ENOENT);
    md_fs_mounts_close(&first); md_fs_mounts_close(&second);
    assert(pread(a,&byte,1,0)==1 && byte=='s'); close(a); close(b);
    md_fs_storage_close(&storage[0]); md_fs_storage_close(&storage[1]);
    assert(!md_fs_mounts_open(&first,NULL,0));
    contents(&first,original);
    write_resolver(store,"nameserver 127.0.0.53\n");
    profile.dns_count=0;
    assert(md_network_resolver_prepare(&first,&profile)==-EDESTADDRREQ);
    contents(&first,"nameserver 127.0.0.53\n");
    profile.policy=MD_NETWORK_HOST;
    assert(!md_network_resolver_prepare(&first,&profile));
    md_fs_mounts_close(&first); md_fs_storage_close(&storage[0]); md_inode_store_close(store);
    puts("PASS launch DNS: isolated immutable views, independent cursors, retained FDs, stub rejection and unchanged store");
}

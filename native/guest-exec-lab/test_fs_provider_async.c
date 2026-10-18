#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "fs_continuation.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static struct { unsigned admitted,completed,cancelled; int ready; } calls;
struct lookup { struct md_provider_lookup base; int directory,done; char name[NAME_MAX+1]; };
static int ready(struct md_provider_lookup *p) { (void)p; return calls.ready; }
static int complete(struct md_provider_lookup *base) {
    struct lookup *p=(void *)base;
    assert(calls.ready && !p->done); p->done=1; ++calls.completed;
    int fd=openat(p->directory,p->name,O_PATH|O_NOFOLLOW|O_CLOEXEC);
    return fd<0 ? -errno : fd;
}
static void destroy(struct md_provider_lookup *base) {
    struct lookup *p=(void *)base;
    if (!p->done) ++calls.cancelled;
    close(p->directory); free(p);
}
static int lookup(void *context,int directory,const char *name,const struct md_control_actor *actor,
        struct md_provider_lookup **out) {
    (void)context; (void)actor;
    struct lookup *p=calloc(1,sizeof(*p)); assert(p);
    p->base=(struct md_provider_lookup){ready,complete,destroy};
    p->directory=fcntl(directory,F_DUPFD_CLOEXEC,3); assert(p->directory>=0);
    assert(strlen(name)<=NAME_MAX); strcpy(p->name,name);
    ++calls.admitted; calls.ready=0; *out=&p->base; return -EINPROGRESS;
}
static const struct md_provider_tree_ops operations={.lookup=lookup};
static struct md_fs_result run(struct md_filesystem *fs,const char *path,unsigned flags,unsigned expected) {
    struct md_fs_context context={.filesystem=fs};
    struct md_fs_request q={.operation=MD_FS_STAT,.directory={-1,-1},.path={path,NULL},.flags=flags};
    struct md_fs_result r;
    struct md_fs_continuation *pending=NULL;
    struct md_fs_output output={.continuation=&pending};
    unsigned before=calls.admitted;
    md_fs_context_execute(&context,&q,&r,&output);
    for (unsigned waits=0;r.error==-EINPROGRESS;++waits) {
        assert(waits<32 && pending && !pending->ready(pending));
        /* Another operation progresses while the provider has not replied. */
        struct md_fs_request other={.operation=MD_FS_STAT,.directory={-1,-1},.path={"/",NULL}};
        struct md_fs_result result; md_fs_execute(fs,&other,&result,NULL); assert(!result.error);
        calls.ready=1; assert(pending->ready(pending));
        struct md_fs_continuation *old=pending; pending=NULL;
        md_fs_context_resume(&context,old,&r,&output);
        int suspended=md_fs_continuation_pending(old,&pending,&r);
        assert(suspended==(r.error==-EINPROGRESS));
    }
    assert(!pending && calls.admitted-before==expected);
    return r;
}
void md_test_fs_provider_async(struct md_filesystem *fs) {
    struct md_fs_request mkdir={.operation=MD_FS_MKDIR,.directory={-1,-1},.path={"/deferred",NULL},.mode=0755};
    struct md_fs_result result; md_fs_execute(fs,&mkdir,&result,NULL); assert(!result.error);
    int parent=md_fs_private_mounts_parent(fs->store); assert(parent>=0);
    struct md_provider_tree *tree=md_provider_tree_new(parent,-1,NULL,0,&operations,NULL); close(parent); assert(tree);
    int root=md_provider_tree_root(tree); assert(!mkdirat(root,"dir",0700));
    int fd=openat(root,"dir/leaf",O_CREAT|O_RDWR|O_CLOEXEC,0600); assert(fd>=0);
    assert(write(fd,"data",4)==4); close(fd); assert(!symlinkat("dir/leaf",root,"link"));
    assert(!md_fs_provider_mount(fs,tree,"/deferred"));
    result=run(fs,"/deferred/dir/leaf",0,2); assert(!result.error && result.info.size==4);
    result=run(fs,"/deferred/dir/../link",0,5); assert(!result.error && result.info.size==4);
    result=run(fs,"/deferred/link",AT_SYMLINK_NOFOLLOW,1); assert(!result.error && S_ISLNK(result.info.mode));
    result=run(fs,"/deferred/dir/leaf/",0,2); assert(result.error==-ENOTDIR);
    result=run(fs,"/deferred/absent",0,1); assert(result.error==-ENOENT);
    unsigned before=calls.admitted;
    struct md_fs_request q={.operation=MD_FS_STAT,.directory={-1,-1},.path={"/deferred/dir/leaf",NULL}};
    md_fs_execute(fs,&q,&result,NULL); assert(result.error==-EOPNOTSUPP && calls.admitted==before);
    struct md_fs_continuation *pending=NULL;
    struct md_fs_output output={.continuation=&pending};
    md_fs_execute(fs,&q,&result,&output); assert(result.error==-EINPROGRESS && pending);
    pending->destroy(pending); assert(calls.cancelled==1 && calls.completed+calls.cancelled==calls.admitted);
    md_provider_tree_release(tree);
    puts("PASS asynchronous path walk: exact-stage resume, symlinks, errors, cancellation and unrelated progress");
}

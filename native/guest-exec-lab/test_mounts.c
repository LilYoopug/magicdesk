#define _GNU_SOURCE
#include "fs_mounts.h"
#include "inode_watch.h"
#include "task_registry.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

static struct md_fs_result call(struct md_filesystem *fs, unsigned op, int fd, const char *path,
        unsigned flags, unsigned mode, void *data, size_t size) {
    struct md_fs_request q = {.actor=123,.operation=op,.directory={fd,-1},.path={path,NULL},.flags=flags,.mode=mode,.capacity=(unsigned)size};
    struct md_fs_output output = {.data=data,.capacity=size};
    struct md_fs_result r;
    md_fs_execute(fs, &q, &r, &output); return r;
}
static int opened(struct md_filesystem *fs, const char *path, unsigned flags) {
    struct md_fs_result r = call(fs, MD_FS_OPEN, -1, path, flags, 0600, NULL, 0);
    if (r.error) fprintf(stderr, "open %s: %d\n", path, r.error);
    assert(!r.error && r.fd >= 0); return r.fd;
}
static int rejected(void *context, const void *data, size_t size) {
    (void)context; (void)data; (void)size; return -EFAULT;
}
static unsigned descriptors(void) {
    DIR *dir=opendir("/proc/self/fd"); assert(dir);
    unsigned count=0; struct dirent *entry;
    while ((entry=readdir(dir))) if (strcmp(entry->d_name,".") && strcmp(entry->d_name,"..")) ++count;
    closedir(dir); return count;
}
static void nested_mounts(const char *base) {
    char source[3][PATH_MAX], store[PATH_MAX], path[PATH_MAX], bytes[8192];
    snprintf(store,sizeof(store),"%s/nested-store",base);
    for (unsigned i=0; i<3; ++i) {
        snprintf(source[i],sizeof(source[i]),"%s/source-%u",base,i);
        assert(!mkdir(source[i],0700));
        snprintf(path,sizeof(path),"%s/marker",source[i]);
        int fd=open(path,O_CREAT|O_WRONLY|O_CLOEXEC,0600); assert(fd>=0);
        assert(write(fd,&"012"[i],1)==1); close(fd);
    }
    for (unsigned i=0; i<2; ++i) {
        snprintf(path,sizeof(path),"%s/child",source[i]); assert(!mkdir(path,0700));
    }
    struct md_inode_store *s=NULL; assert(!md_inode_store_open(store,1,&s));
    assert(!md_inode_mkdir(s,-1,"/tree",0700));
    assert(!md_inode_mkdir(s,-1,"/tree/child",0700));
    struct md_filesystem fs={.store=s};
    struct md_fs_attachment entries[]={{source[0],"/tree",0},
        {source[1],"/tree/child",1},{source[2],"/tree/child/child",0}};
    snprintf(path,sizeof(path),"%s/child",source[0]);
    int covered=open(path,O_PATH|O_DIRECTORY|O_CLOEXEC); assert(covered>=0);
    assert(!md_fs_mounts_open(&fs,entries,3));
    const char *names[]={"/tree","/tree/child","/tree/child/child"};
    unsigned long long ids[3];
    for (unsigned i=0; i<3; ++i) {
        snprintf(path,sizeof(path),"%s/marker",names[i]);
        int fd=opened(&fs,path,O_RDONLY); assert(read(fd,bytes,1)==1 && bytes[0]=="012"[i]);
        struct md_fs_result r=call(&fs,MD_FS_FSTAT,fd,NULL,0,0,NULL,0);
        assert(!r.error); ids[i]=r.info.mount_id;
        r=call(&fs,MD_FS_PATH,fd,NULL,0,0,bytes,sizeof(bytes));
        assert(!r.error && !strcmp(bytes,path)); close(fd);
        int dir=opened(&fs,names[i],O_PATH|O_DIRECTORY);
        r=call(&fs,MD_FS_OPEN,dir,"../marker",O_RDONLY,0,NULL,0);
        if (!i) assert(r.error==-ENOENT);
        else { assert(!r.error && read(r.fd,bytes,1)==1 && bytes[0]=="012"[i-1]); close(r.fd); }
        r=call(&fs,MD_FS_OPEN,dir,"new",O_CREAT|O_WRONLY,0600,NULL,0);
        if (i==1) assert(r.error==-EROFS);
        else { assert(!r.error); close(r.fd); }
        struct md_fs_request q={.operation=MD_FS_OPEN,.directory={dir,-1},
            .path={"../marker",NULL},.flags=O_RDONLY,.resolve=RESOLVE_NO_XDEV};
        md_fs_execute(&fs,&q,&r,NULL); assert(r.error==-EXDEV);
        q.path[0]="../marker"; q.resolve=RESOLVE_IN_ROOT;
        md_fs_execute(&fs,&q,&r,NULL); assert(!r.error && read(r.fd,bytes,1)==1 && bytes[0]=="012"[i]); close(r.fd);
        q.path[0]="../marker"; q.resolve=RESOLVE_BENEATH;
        md_fs_execute(&fs,&q,&r,NULL); assert(r.error==-EXDEV);
        close(dir);
    }
    assert(ids[0]!=ids[1] && ids[1]!=ids[2] && ids[0]!=ids[2]);
    struct md_fs_result r=call(&fs,MD_FS_MOUNT_TABLE,-1,NULL,1,0,NULL,0); assert(!r.error);
    ssize_t count=read(r.fd,bytes,sizeof(bytes)-1); assert(count>0); bytes[count]=0; close(r.fd);
    for (unsigned i=0; i<3; ++i) {
        char line[80]; snprintf(line,sizeof(line),"%llu %llu ",ids[i],i ? ids[i-1] : (unsigned long long)MD_FS_ROOT_MOUNT);
        assert(strstr(bytes,line));
    }
    assert(!strstr(bytes,base));
    /* A descriptor opened before a covering mount keeps its original view. */
    r=call(&fs,MD_FS_OPEN,covered,"marker",O_RDONLY,0,NULL,0); assert(r.error==-ENOENT);
    r=call(&fs,MD_FS_OPEN,covered,"./marker",O_RDONLY,0,NULL,0); assert(r.error==-ENOENT);
    int leaf=opened(&fs,"/tree/child/child",O_RDONLY|O_DIRECTORY);
    snprintf(path,sizeof(path),"%s/link",source[0]); assert(!symlink("/tree/child/child",path));
    int alias=opened(&fs,"/tree/link/marker",O_RDONLY); assert(read(alias,bytes,1)==1 && bytes[0]=='2'); close(alias);
    r=call(&fs,MD_FS_UNLINK,-1,"/tree/child",AT_REMOVEDIR,0,NULL,0); assert(r.error==-EBUSY || r.error==-EROFS);
    struct md_fs_request rename={.operation=MD_FS_RENAME,.directory={-1,-1},.path={"/tree/marker","/tree/child/marker"}};
    md_fs_execute(&fs,&rename,&r,NULL); assert(r.error==-EXDEV);
    /* Covered dentries move independently of source objects and retained FDs. */
    snprintf(path,sizeof(path),"%s/child",source[0]);
    char moved[PATH_MAX]; snprintf(moved,sizeof(moved),"%s/renamed",source[0]); assert(!renameat(AT_FDCWD,path,AT_FDCWD,moved));
    r=call(&fs,MD_FS_PATH,leaf,NULL,0,0,bytes,sizeof(bytes));
    assert(!r.error && !strcmp(bytes,"/tree/renamed/child"));
    alias=opened(&fs,"/tree/renamed/child/marker",O_RDONLY); close(alias);
    r=call(&fs,MD_FS_OPEN,leaf,"../marker",O_RDONLY,0,NULL,0);
    assert(!r.error && read(r.fd,bytes,1)==1 && bytes[0]=='1'); close(r.fd);
    struct md_guest_domain *context=md_domain_new(); assert(context);
    struct md_identity identity=md_identity_new(0,0);
    fs.tasks=md_task_registry_create(); assert(fs.tasks);
    assert(!md_task_registry_publish(fs.tasks,123,123,&identity,context));
    snprintf(path,sizeof(path),"%s/absolute",source[1]); assert(!symlink("/child/marker",path));
    r=call(&fs,MD_FS_CHROOT,-1,"/tree/renamed",0,0,NULL,0); assert(!r.error);
    alias=opened(&fs,"/../../marker",O_RDONLY); assert(read(alias,bytes,1)==1 && bytes[0]=='1'); close(alias);
    alias=opened(&fs,"/absolute",O_RDONLY); assert(read(alias,bytes,1)==1 && bytes[0]=='2'); close(alias);
    r=call(&fs,MD_FS_OPEN,-1,"/denied",O_CREAT|O_WRONLY,0600,NULL,0); assert(r.error==-EROFS);
    alias=opened(&fs,"/child/writable",O_CREAT|O_WRONLY); close(alias);
    r=call(&fs,MD_FS_PATH,leaf,NULL,0,0,bytes,sizeof(bytes)); assert(!r.error && !strcmp(bytes,"/child"));
    r=call(&fs,MD_FS_PATH,covered,NULL,0,0,bytes,sizeof(bytes)); assert(r.error==-ENOENT);
    r=call(&fs,MD_FS_OPEN,-1,"/proc/self/status",O_RDONLY,0,bytes,sizeof(bytes)); assert(r.error==-ENOENT && !r.host_path);
    r=call(&fs,MD_FS_MOUNT_TABLE,-1,NULL,1,0,NULL,0); assert(!r.error);
    count=read(r.fd,bytes,sizeof(bytes)-1); assert(count>0); bytes[count]=0; close(r.fd);
    assert(strstr(bytes," / ro - none attachment ro") && strstr(bytes," /child rw - none attachment rw"));
    assert(!strstr(bytes,"/tree") && !strstr(bytes,"/proc") && !strstr(bytes,base));
    md_task_registry_destroy(fs.tasks); fs.tasks=NULL;
    md_identity_release(&identity); md_domain_release(context);
    close(leaf); close(covered); md_fs_mounts_close(&fs);
    /* Invalid topology is rejected before a partially usable tree is published. */
    struct md_fs_attachment reversed[]={{source[1],"/tree/child",0},{source[0],"/tree",0}};
    assert(md_fs_mounts_open(&fs,reversed,2)==-EBUSY && !fs.mounts);
    struct md_fs_attachment overlapping[]={{source[0],"/tree",0},{source[0],"/tree/renamed",1}};
    assert(md_fs_mounts_open(&fs,overlapping,2)==-EXDEV && !fs.mounts);
    unsigned before=descriptors();
    struct md_fs_attachment invalid[]={
        {NULL,"/tree",0},{source[0],NULL,0},{"/no-such-mount-source","/tree",0},
        {source[0],"/absent",0},{source[0],"/",0}};
    for (unsigned i=0; i<sizeof(invalid)/sizeof(invalid[0]); ++i) {
        assert(md_fs_mounts_open(&fs,&invalid[i],1)<0 && !fs.mounts);
        assert(descriptors()==before);
    }
    for (unsigned i=0; i<8; ++i) {
        assert(md_fs_mounts_open(&fs,reversed,2)==-EBUSY && !fs.mounts);
        assert(md_fs_mounts_open(&fs,overlapping,2)==-EXDEV && !fs.mounts);
        assert(descriptors()==before);
    }
    md_inode_store_close(s);
    puts("PASS nested mount topology, independent readonly, parent IDs, retained covered FDs and rename");
    puts("PASS native roots, root-clamped traversal, absolute symlinks and nested mount visibility");
    puts("PASS failed mount-tree construction releases partial resources without descriptor leaks");
}
int main(int argc, char **argv) {
    assert(argc == 2 && argv[1][0] == '/'); assert(!mkdir(argv[1], 0700));
    char path[4096], host[4096], readonly[4096], store[4096];
    assert(snprintf(host, sizeof(host), "%s/host", argv[1]) < (int)sizeof(host));
    assert(snprintf(readonly, sizeof(readonly), "%s/readonly", argv[1]) < (int)sizeof(readonly));
    assert(snprintf(store, sizeof(store), "%s/store", argv[1]) < (int)sizeof(store));
    assert(!mkdir(host, 0700) && !mkdir(readonly, 0700));
    struct md_inode_store *s = NULL; assert(!md_inode_store_open(store, 1, &s));
    assert(!md_inode_mkdir(s, -1, "/volume", 0700));
    assert(!md_inode_mkdir(s, -1, "/readonly", 0700));
    int fd = md_inode_open(s, -1, "/guest", O_CREAT | O_RDWR, 0600); assert(fd >= 0);
    assert(write(fd, "guest", 5) == 5); close(fd);
    assert(!md_inode_symlink(s, "/volume", -1, "/link"));
    struct md_fs_attachment attachments[] = {{host,"/volume",0},{readonly,"/readonly",1}};
    struct md_filesystem fs = {.store=s};
    assert(!md_fs_mounts_open(&fs, attachments, 2));
    fd = opened(&fs, "/link/file", O_RDWR | O_CREAT); assert(write(fd, "native", 6) == 6);
    snprintf(path, sizeof(path), "%s/file", host);
    struct stat st, native; assert(!fstat(fd, &st) && !stat(path, &native));
    assert(st.st_dev == native.st_dev && st.st_ino == native.st_ino);
    int directory = opened(&fs, "/volume", O_RDONLY | O_DIRECTORY);
    struct md_fs_result result = call(&fs, MD_FS_OPEN, directory, "../guest", O_RDONLY, 0, NULL, 0);
    assert(!result.error); char bytes[4096] = {0}; assert(read(result.fd, bytes, 5) == 5 && !strcmp(bytes, "guest")); close(result.fd);
    assert(!symlinkat("/guest", directory, "absolute"));
    int guest = opened(&fs, "/volume/absolute", O_RDONLY); close(guest);
    int symlink_fd = opened(&fs, "/volume/absolute", O_PATH | O_NOFOLLOW);
    result = call(&fs, MD_FS_REOPEN, symlink_fd, NULL, O_PATH | O_NOFOLLOW, 0, NULL, 0);
    assert(!result.error && !fstat(result.fd, &st) && S_ISLNK(st.st_mode)); close(result.fd); close(symlink_fd);
    assert(!symlinkat("/volume", directory, "self"));
    result = call(&fs, MD_FS_UNLINK, -1, "/volume/self/", AT_REMOVEDIR, 0, NULL, 0);
    assert(result.error == -ENOTDIR);
    result = call(&fs, MD_FS_OPEN, -1, "/volume/file", O_RDONLY | O_TRUNC, 0, NULL, 0);
    assert(result.error == -EINVAL);
    int watch = md_inode_watch_create(s, IN_NONBLOCK); assert(watch >= 0);
    int wd = md_inode_watch_add(s, watch, directory, IN_CREATE | IN_MOVED_FROM | IN_MOVED_TO); assert(wd > 0);
    int observed = opened(&fs, "/volume/observed", O_CREAT | O_WRONLY); close(observed);
    assert(!renameat(directory, "observed", directory, "renamed"));
    char events[4096]; ssize_t event_bytes = md_inode_watch_read(s, watch, events, sizeof(events), NULL, NULL);
    assert(event_bytes > 0); unsigned mask = 0;
    for (size_t at = 0; at < (size_t)event_bytes;) {
        struct inotify_event *event = (void *)(events+at);
        assert(event->wd == wd); mask |= event->mask; at += sizeof(*event)+event->len;
    }
    assert((mask & (IN_CREATE | IN_MOVED_FROM | IN_MOVED_TO)) == (IN_CREATE | IN_MOVED_FROM | IN_MOVED_TO));
    close(watch);
    result = call(&fs, MD_FS_OPEN, -1, "/readonly/new", O_CREAT | O_RDWR, 0600, NULL, 0); assert(result.error == -EROFS);
    snprintf(path, sizeof(path), "%s/file", readonly);
    int external = open(path, O_CREAT | O_WRONLY | O_CLOEXEC, 0600); assert(external >= 0); close(external);
    int ro = opened(&fs, "/readonly/file", O_RDONLY);
    result = call(&fs, MD_FS_XATTR_OPEN, ro, "user.test", 0, W_OK, NULL, 0); assert(result.error == -EROFS);
    result = call(&fs, MD_FS_XATTR_OPEN, ro, "", 0, F_OK, NULL, 0); assert(result.error == -EXDEV);
    result = call(&fs, MD_FS_REOPEN, ro, NULL, O_PATH | O_CLOEXEC, 1, NULL, 0); assert(result.error == -EROFS);
    assert(!unlink(path));
    result = call(&fs, MD_FS_REOPEN, ro, NULL, O_RDWR, 0, NULL, 0); assert(result.error == -EROFS); close(ro);
    result = call(&fs, MD_FS_PATH, directory, NULL, 0, 0, bytes, sizeof(bytes));
    assert(!result.error && !strcmp(bytes, "/volume"));
    struct md_fs_request q = {.operation=MD_FS_OPEN,.directory={directory,-1},.path={"../guest",NULL},.flags=O_RDONLY,.resolve=RESOLVE_BENEATH};
    md_fs_execute(&fs, &q, &result, NULL); assert(result.error == -EXDEV);
    q.resolve = RESOLVE_NO_XDEV; md_fs_execute(&fs, &q, &result, NULL); assert(result.error == -EXDEV);
    q.path[0] = "/file"; q.resolve = RESOLVE_IN_ROOT;
    md_fs_execute(&fs, &q, &result, NULL); assert(!result.error); close(result.fd);
    q = (struct md_fs_request){.operation=MD_FS_RENAME,.directory={-1,-1},.path={"/guest","/volume/guest"}};
    md_fs_execute(&fs, &q, &result, NULL); assert(result.error == -EXDEV);
    result = call(&fs, MD_FS_UNLINK, -1, "/volume", AT_REMOVEDIR, 0, NULL, 0); assert(result.error == -EBUSY);
    q = (struct md_fs_request){.operation=MD_FS_GETDENTS,.directory={directory,-1},.capacity=sizeof(bytes)};
    struct md_fs_output output = {.data=bytes,.capacity=sizeof(bytes),.deliver=rejected};
    md_fs_execute(&fs, &q, &result, &output); assert(result.error == -EFAULT && lseek(directory, 0, SEEK_CUR) == 0);
    output.deliver = NULL; md_fs_execute(&fs, &q, &result, &output); assert(!result.error && result.size > 0);
    assert(!unlinkat(directory, "file", 0));
    result = call(&fs, MD_FS_REOPEN, fd, NULL, O_RDONLY | O_CLOEXEC, 0, NULL, 0); assert(!result.error);
    memset(bytes, 0, sizeof(bytes)); assert(read(result.fd, bytes, 6) == 6 && !strcmp(bytes, "native")); close(result.fd);
    assert(!md_inode_mkdir(s,-1,"/etc",0755));
    assert(!md_inode_mkdir(s,-1,"/dev",0755));
    assert(!md_inode_mkdir(s,-1,"/dev/shm",01777));
    assert(!md_inode_symlink(s,"../proc/self/mounts",-1,"/etc/mtab"));
    assert(!md_inode_symlink(s,"/dev/shm",-1,"/shared"));
    for (unsigned attached=0; attached<2; ++attached) {
        struct md_filesystem plain={.store=s};
        struct md_filesystem *view=attached ? &fs : &plain;
        result=call(view,MD_FS_OPEN,-1,"/etc/mtab",O_RDONLY,0,bytes,sizeof(bytes));
        assert(!result.error && result.host_path && result.fd==-1 && !strcmp(bytes,"/proc/self/mounts"));
        result=call(view,MD_FS_OPEN,-1,"/etc/mtab",O_PATH|O_NOFOLLOW,0,bytes,sizeof(bytes));
        assert(!result.error && !result.host_path && !fstat(result.fd,&st) && S_ISLNK(st.st_mode)); close(result.fd);
        result=call(view,MD_FS_OPEN,-1,"/shared",O_PATH|O_DIRECTORY,0,bytes,sizeof(bytes));
        assert(!result.error && !result.host_path && result.fd>=0); close(result.fd);
        q=(struct md_fs_request){.operation=MD_FS_OPEN,.directory={-1,-1},.path={"/etc/mtab",NULL},
            .flags=O_RDONLY,.resolve=RESOLVE_NO_XDEV};
        output=(struct md_fs_output){.data=bytes,.capacity=sizeof(bytes)};
        md_fs_execute(view,&q,&result,&output); assert(result.error==-EXDEV);
        q.resolve=RESOLVE_NO_SYMLINKS;
        md_fs_execute(view,&q,&result,&output); assert(result.error==-ELOOP);
        for (unsigned info=0; info<2; ++info) {
            result=call(view,MD_FS_MOUNT_TABLE,-1,NULL,info,0,bytes,sizeof(bytes));
            assert(!result.error && result.fd>=0);
            ssize_t count=read(result.fd,bytes,sizeof(bytes)-1); assert(count>0);
            bytes[count]=0; assert(strstr(bytes,"guestfs") && strstr(bytes,"/proc") && strstr(bytes,"/dev/shm"));
            assert(!strstr(bytes,store) && !strstr(bytes,host));
            if (attached) assert(strstr(bytes,"/readonly") && strstr(bytes,"/volume"));
            assert((fcntl(result.fd,F_GETFL)&O_ACCMODE)==O_RDONLY);
            assert(lseek(result.fd,0,SEEK_SET)==0); close(result.fd);
        }
        md_fs_mounts_close(&plain);
    }
    struct md_guest_domain *context=md_domain_new(); assert(context);
    struct md_identity identity=md_identity_new(0,0);
    fs.tasks=md_task_registry_create(); assert(fs.tasks);
    assert(!md_task_registry_publish(fs.tasks,123,123,&identity,context));
    int inode_root=md_inode_open(s,-1,"/",O_PATH|O_DIRECTORY,0); assert(inode_root>=0);
    result=call(&fs,MD_FS_CHROOT,-1,"/volume",0,0,NULL,0); assert(!result.error);
    result=call(&fs,MD_FS_OPEN,-1,"/renamed",O_RDONLY,0,NULL,0); assert(!result.error); close(result.fd);
    result=call(&fs,MD_FS_PATH,inode_root,NULL,0,0,bytes,sizeof(bytes)); assert(result.error==-ENOENT);
    result=call(&fs,MD_FS_PATH,directory,NULL,0,0,bytes,sizeof(bytes)); assert(!result.error && !strcmp(bytes,"/"));
    result=call(&fs,MD_FS_CHROOT,inode_root,".",0,0,NULL,0); assert(!result.error); close(inode_root);
    result=call(&fs,MD_FS_CHROOT,-1,"/etc",0,0,NULL,0); assert(!result.error);
    result=call(&fs,MD_FS_OPEN,-1,"/guest",O_RDONLY,0,NULL,0); assert(result.error==-ENOENT);
    result=call(&fs,MD_FS_OPEN,directory,"renamed",O_RDONLY,0,NULL,0);
    assert(!result.error); close(result.fd);
    result=call(&fs,MD_FS_MOUNT_TABLE,-1,NULL,1,0,NULL,0); assert(!result.error);
    ssize_t count=read(result.fd,bytes,sizeof(bytes)-1); assert(count>0); bytes[count]=0;
    assert(strstr(bytes,"guestfs") && !strstr(bytes,"/proc") && !strstr(bytes,"/volume") && !strstr(bytes,"/readonly"));
    close(result.fd);
    md_task_registry_destroy(fs.tasks); fs.tasks=NULL;
    md_identity_release(&identity); md_domain_release(context);
    close(fd); close(directory);
    md_fs_mounts_close(&fs); md_inode_store_close(s);
    puts("PASS native attachments, cross-boundary symlinks/dirfds, readonly retained FDs, mount identity and directory publication");
    puts("PASS host-boundary symlinks, guest shared memory, resolution constraints and guest mount tables");
    puts("PASS scoped roots, retained attachments and filtered mount tables");
    nested_mounts(argv[1]);
    return 0;
}

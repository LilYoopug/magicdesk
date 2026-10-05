#define _GNU_SOURCE
#include "task_registry.h"
#include "task_resources.h"
#include "inode_internal.h"
#include "fs_operation.h"
#include "fs_engine.h"
#include "fs_mounts.h"
#include "guest_accounts.h"
#include "linux_abi.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void identities(void) {
    struct md_identity root = md_identity_new(0, 0);
    uint32_t groups[] = {12, 34};
    assert(!md_identity_groups(&root, groups, 2));
    struct md_identity child = md_identity_copy(&root);
    assert(!md_identity_groups(&root, NULL, 0));
    assert(md_identity_group_count(&child) == 2 && md_identity_in_group(&child, 34));
    assert(!md_identity_setresuid(&child, 1000, 1000, 0));
    assert(md_identity_setfsuid(&child, 1234) == 1000 && child.uid.fs == 1000);
    assert(!md_identity_setuid(&child, 0) && child.uid.real == 1000 && child.uid.saved == 0);
    assert(!md_identity_setgid(&child, 2000));
    assert(!md_identity_setuid(&child, 1000));
    assert(md_identity_setuid(&child, 0) == -EPERM);
    assert(md_identity_setresgid(&child, 0, 0, 0) == -EPERM);
    assert(md_identity_setreuid(&child, UINT32_MAX, 0) == -EPERM);
    assert(md_identity_setfsuid(&child, UINT32_MAX) == 1000);
    assert(md_identity_no_new_privs(&child, 0) == -EINVAL);
    assert(!md_identity_no_new_privs(&child, 1));
    struct md_task_registry *registry = md_task_registry_create(); assert(registry);
    assert(!md_task_registry_publish(registry, 123, 120, &child, NULL));
    struct md_task_snapshot read;
    assert(md_task_registry_read(registry, 123, 119, &read) == -EPERM);
    assert(!md_task_registry_read(registry, 123, 120, &read));
    md_identity_release(&child);
    assert(read.identity.uid.effective == 1000 && md_identity_group_count(&read.identity) == 2);
    md_task_snapshot_release(&read);
    md_task_registry_forget(registry, 123);
    assert(md_task_registry_read(registry, 123, 120, &read) == -ESRCH);
    md_task_registry_destroy(registry); md_identity_release(&root);
}
struct publications {
    struct md_task_registry *registry;
    struct md_task_resources resources[2];
    struct md_identity identities[2];
    pthread_barrier_t start;
};
static void *publish_snapshots(void *opaque) {
    struct publications *p=opaque;
    /* EVENT_WAIT: reader joins the publication race; the runner bounds failure. */
    pthread_barrier_wait(&p->start);
    for(unsigned i=0;i<10000;++i) {
        unsigned k=i%2;
        assert(!md_task_registry_publish(p->registry,123,120,&p->identities[k],&p->resources[k]));
    }
    return NULL;
}
static void concurrent_snapshots(void) {
    struct publications p={.registry=md_task_registry_create()}; assert(p.registry);
    for(unsigned i=0;i<2;++i) {
        p.identities[i]=md_identity_new(i,i);
        p.resources[i].fs=md_domain_new(); assert(p.resources[i].fs);
        p.resources[i].mounts=md_mount_namespace_new(); assert(p.resources[i].mounts);
        p.resources[i].files=md_fd_origins_new(); assert(p.resources[i].files);
        struct md_fs_location root={.mount=i+1,.object="a"}; root.object[0]+=(char)i;
        assert(!md_domain_set_root(p.resources[i].fs,&root));
    }
    assert(!md_task_registry_publish(p.registry,123,120,&p.identities[0],&p.resources[0]));
    assert(!pthread_barrier_init(&p.start,NULL,2));
    pthread_t writer; assert(!pthread_create(&writer,NULL,publish_snapshots,&p));
    /* EVENT_WAIT: both participants start before exercising concurrent publication;
     * the fixture runner's deadline bounds a stuck barrier or join. */
    pthread_barrier_wait(&p.start);
    for(unsigned i=0;i<10000;++i) {
        struct md_task_snapshot snapshot;
        assert(!md_task_registry_read(p.registry,123,120,&snapshot));
        unsigned k=snapshot.identity.uid.effective; assert(k<2);
        assert(snapshot.mounts==p.resources[k].mounts && snapshot.root.mount==k+1
            && snapshot.root.object[0]=='a'+(char)k && snapshot.files==p.resources[k].files && !snapshot.cwd);
        md_task_snapshot_release(&snapshot);
    }
    assert(!pthread_join(writer,NULL));
    pthread_barrier_destroy(&p.start); md_task_registry_destroy(p.registry);
    for(unsigned i=0;i<2;++i) {
        md_identity_release(&p.identities[i]); md_domain_release(p.resources[i].fs);
        md_mount_namespace_release(p.resources[i].mounts);
        md_fd_origins_release(p.resources[i].files);
    }
    puts("PASS concurrent identity/root/mount/files snapshots are coherent and retained");
}
static int change(struct md_inode_store *s, int fd, unsigned op, unsigned mode, uint32_t uid, uint32_t gid) {
    struct md_fs_request q = {.operation=op,.directory={fd,-1},.mode=mode,.flags=MD_AT_EACCESS};
    if (op != MD_FS_ACCESS) q.flags = 0;
    q.attributes.uid=uid; q.attributes.gid=gid;
    return md_inode_metadata(s, &q);
}
static void account_file(struct md_inode_store *s, const char *path, const char *content) {
    int fd=md_inode_create(s,-1,path,0644); assert(fd>=0);
    size_t n=strlen(content); assert(write(fd,content,n)==(ssize_t)n); close(fd);
}
static struct md_fs_result root_call(struct md_filesystem *fs, pid_t task, unsigned op,
        int fd, const char *path, unsigned flags, char *data, size_t capacity) {
    struct md_fs_request q={.actor=task,.peer=120,.operation=op,.directory={fd,-1},
        .path={path,NULL},.flags=flags,.capacity=(unsigned)capacity};
    struct md_fs_result out;
    struct md_fs_output output={.data=data,.capacity=capacity};
    md_fs_execute(fs,&q,&out,&output); return out;
}
static void root_context(struct md_inode_store *s) {
    assert(!md_inode_mkdir(s,-1,"/jail",0755));
    assert(!md_inode_mkdir(s,-1,"/jail/sub",0755));
    account_file(s,"/jail/value","inside");
    assert(!md_inode_symlink(s,"/value",-1,"/jail/absolute"));
    struct md_identity ids=md_identity_new(0,0);
    struct md_guest_domain *parent=md_domain_new(); assert(parent);
    struct md_guest_domain *shared=md_domain_fork(parent,1); assert(shared==parent);
    struct md_guest_domain *sibling=md_domain_fork(parent,0); assert(sibling);
    struct md_filesystem fs={.store=s,.tasks=md_task_registry_create()}; assert(fs.tasks);
    assert(!md_fs_mounts_open(&fs,NULL,0));
    struct md_task_resources resources={.fs=parent,.mounts=fs.mounts};
    assert(!md_task_registry_publish(fs.tasks,123,120,&ids,&resources));
    resources.fs=shared;
    assert(!md_task_registry_publish(fs.tasks,124,120,&ids,&resources));
    resources.fs=sibling;
    assert(!md_task_registry_publish(fs.tasks,125,120,&ids,&resources));
    struct md_fs_result out=root_call(&fs,123,MD_FS_CHROOT,-1,"/jail",0,NULL,0);
    assert(!out.error && out.fd==-1);
    for(pid_t task=123;task<=125;task++) {
        out=root_call(&fs,task,MD_FS_OPEN,-1,"/absolute",O_RDONLY,NULL,0);
        if(task==125) assert(out.error==-ENOENT);
        else { assert(!out.error && out.fd>=0); close(out.fd); }
    }
    struct md_fs_location location={0}; struct md_task_snapshot snap;
    assert(md_task_registry_read(fs.tasks,123,119,&snap)==-EPERM);
    assert(md_task_registry_set_root(fs.tasks,123,119,&location)==-EPERM);
    assert(!md_task_registry_read(fs.tasks,123,120,&snap) && snap.root.object[0]);
    assert(snap.mounts==fs.mounts); md_task_snapshot_release(&snap);
    out=root_call(&fs,123,MD_FS_OPEN,-1,"/",O_RDONLY|O_DIRECTORY,NULL,0);
    assert(!out.error); int root=out.fd;
    struct stat st; assert(!md_inode_fstat(s,root,&st));
    char bytes[4096];
    out=root_call(&fs,123,MD_FS_GETDENTS,root,NULL,0,bytes,sizeof(bytes));
    assert(!out.error); unsigned dots=0;
    for(size_t p=0;p<out.size;) {
        struct md_inode_dirent *entry=(void *)(bytes+p);
        if(!strcmp(entry->name,".") || !strcmp(entry->name,"..")) {
            assert(entry->inode==st.st_ino); dots++;
        }
        p+=entry->size;
    }
    assert(dots==2);
    assert(!md_inode_rename(s,-1,"/jail",-1,"/moved-jail",0));
    out=root_call(&fs,123,MD_FS_PATH,root,NULL,0,bytes,sizeof(bytes));
    assert(!out.error && !strcmp(bytes,"/"));
    out=root_call(&fs,124,MD_FS_OPEN,-1,"/sub/../../value",O_RDONLY,NULL,0);
    assert(!out.error); close(out.fd);
    struct md_guest_domain *split=md_domain_unshare_prepare(shared); assert(split && split!=shared);
    resources.fs=split;
    assert(!md_task_registry_publish(fs.tasks,124,120,&ids,&resources));
    md_domain_release(shared);
    out=root_call(&fs,124,MD_FS_CHROOT,-1,"/sub",0,NULL,0); assert(!out.error);
    out=root_call(&fs,123,MD_FS_OPEN,-1,"/value",O_RDONLY,NULL,0); assert(!out.error); close(out.fd);
    out=root_call(&fs,124,MD_FS_OPEN,-1,"/value",O_RDONLY,NULL,0); assert(out.error==-ENOENT);
    md_domain_release(parent); md_domain_release(split); md_domain_release(sibling);
    md_task_registry_destroy(fs.tasks); md_fs_mounts_close(&fs);
    md_identity_release(&ids); close(root);
}
static void accounts(struct md_inode_store *s) {
    struct md_filesystem fs={.store=s}; struct md_identity selected={0};
    assert(!md_guest_user_resolve(&fs,"123:456",&selected));
    assert(selected.uid.real==123 && selected.gid.real==456 && !md_identity_group_count(&selected));
    md_identity_release(&selected);
    assert(!md_inode_mkdir(s,-1,"/etc",0755));
    account_file(s,"/etc/passwd","root:x:0:0:Root:/root:/bin/sh\nalice:x:1000:100:Alice:/home/alice:/bin/sh\n");
    account_file(s,"/etc/group","primary:x:100:\nshared:x:200:alice\nother:x:300:bob,alice\n");
    const char *forms[]={"alice","1000","alice:shared","1000:200","1000:shared","root"};
    for (unsigned i=0;i<sizeof(forms)/sizeof(*forms);i++) {
        assert(!md_guest_user_resolve(&fs,forms[i],&selected));
        assert(selected.uid.real==(i==5 ? 0U : 1000U));
        assert(selected.gid.real==(i==5 ? 0U : i<2 ? 100U : 200U));
        assert(md_identity_group_count(&selected)==(i<2 ? 2U : 0U));
        if (i<2) assert(md_identity_in_group(&selected,200) && md_identity_in_group(&selected,300));
        md_identity_release(&selected);
    }
    assert(md_guest_user_resolve(&fs,"missing",&selected)==-ENOENT);
    assert(md_guest_user_resolve(&fs,"alice:missing",&selected)==-ENOENT);
    assert(md_guest_user_resolve(&fs,"4294967295",&selected)==-EINVAL);
    assert(md_guest_user_resolve(&fs,"1000:",&selected)==-EINVAL);
}
int main(int argc, char **argv) {
    assert(argc == 2); identities(); concurrent_snapshots(); umask(0);
    struct md_inode_store *s = NULL;
    assert(!md_inode_store_open(argv[1], 1, &s));
    struct md_identity root=md_identity_new(0,0), user=md_identity_new(1000,1000), other=md_identity_new(1001,1001);
    s->identity=&root;
    int base=md_inode_open(s,-1,"/",O_PATH|O_DIRECTORY,0); assert(base>=0);
    assert(!change(s,base,MD_FS_CHMOD,0755,0,0));
    accounts(s);
    root_context(s);
    assert(!md_inode_mkdir(s,-1,"/tmp",01777));
    int fd=md_inode_create(s,-1,"/tmp/owned",0640); assert(fd>=0);
    assert(write(fd,"data",4)==4);
    assert(!change(s,fd,MD_FS_CHOWN,0,1000,1000));
    struct stat st,native; assert(!md_inode_fstat(s,fd,&st)); assert(!fstat(fd,&native));
    assert(st.st_uid==1000 && st.st_gid==1000 && (st.st_mode&07777)==0640);
    assert(native.st_uid==getuid() && (native.st_mode&06000)==0);
    assert(!md_inode_link(s,-1,"/tmp/owned",-1,"/tmp/alias",0));
    s->identity=&user;
    assert(!change(s,fd,MD_FS_CHMOD,0644,0,0));
    int noatime=md_inode_open(s,-1,"/tmp/owned",O_RDONLY|O_NOATIME,0);
    assert(noatime>=0); close(noatime);
    noatime=md_inode_reopen(s,fd,O_RDONLY|O_NOATIME,0);
    assert(noatime>=0); close(noatime);
    s->identity=&other;
    int readable=md_inode_open(s,-1,"/tmp/owned",O_RDONLY,0);
    assert(readable>=0); close(readable);
    assert(md_inode_open(s,-1,"/tmp/owned",O_RDONLY|O_NOATIME,0)==-EPERM);
    assert(md_inode_reopen(s,fd,O_RDONLY|O_NOATIME,0)==-EPERM);
    s->identity=&root;
    noatime=md_inode_reopen(s,fd,O_RDONLY|O_NOATIME,0);
    assert(noatime>=0); close(noatime);
    s->identity=&user;
    assert(!change(s,fd,MD_FS_CHMOD,0600,0,0));
    assert(change(s,fd,MD_FS_CHOWN,0,0,0)==-EPERM);
    s->identity=&other;
    assert(md_inode_open(s,-1,"/tmp/owned",O_RDONLY,0)==-EACCES);
    assert(md_inode_unlink(s,-1,"/tmp/owned",0)==-EPERM);
    assert(md_inode_rename(s,-1,"/tmp/owned",-1,"/tmp/stolen",0)==-EPERM);
    assert(change(s,fd,MD_FS_CHMOD,0777,0,0)==-EPERM);
    s->identity=&root;
    assert(!change(s,fd,MD_FS_CHMOD,0000,0,0));
    int opened=md_inode_open(s,-1,"/tmp/owned",O_RDONLY,0); assert(opened>=0); close(opened);
    assert(change(s,fd,MD_FS_ACCESS,X_OK,0,0)==-EACCES);
    assert(!change(s,fd,MD_FS_CHMOD,04755,0,0));
    assert(!md_inode_stat(s,-1,"/tmp/alias",0,&st) && (st.st_mode&07777)==04755);
    assert(!change(s,fd,MD_FS_CHOWN,0,1000,1000));
    assert(!md_inode_fstat(s,fd,&st) && !(st.st_mode&06000));
    assert(!md_inode_mkdir(s,-1,"/shared",02777));
    int shared=md_inode_open(s,-1,"/shared",O_PATH|O_DIRECTORY,0); assert(shared>=0);
    assert(!change(s,shared,MD_FS_CHOWN,0,0,2000));
    s->identity=&user;
    uint32_t group=2000; assert(!md_identity_groups(&user,&group,1));
    assert(!md_inode_mkdir(s,-1,"/shared/child",0750));
    assert(!md_inode_stat(s,-1,"/shared/child",0,&st));
    assert(st.st_gid==2000 && (st.st_mode&07777)==02750);
    s->identity=&other;
    assert(!md_inode_mkdir(s,-1,"/shared/nonmember",0750));
    assert(!md_inode_stat(s,-1,"/shared/nonmember",0,&st));
    assert(st.st_gid==2000 && (st.st_mode&07777)==02750);
    s->identity=NULL;
    close(shared); close(fd); close(base); md_inode_store_close(s);
    assert(!md_inode_store_open(argv[1],0,&s));
    assert(!md_inode_stat(s,-1,"/shared/child",0,&st) && st.st_uid==1000 && st.st_gid==2000);
    md_inode_store_close(s); md_identity_release(&user);
    puts("credentials: identity, inheritance, authority, metadata, hardlinks, sticky, setgid, persistence PASS");
}

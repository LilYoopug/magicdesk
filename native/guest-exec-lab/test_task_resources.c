#define _GNU_SOURCE
#include "task_resources.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <sched.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

void test_fd_origins(void);
void test_ofd_order(void);
void test_user_namespace(void);
static int descriptors(void) {
    DIR *dir = opendir("/proc/self/fd"); assert(dir);
    int count = 0;
    while (readdir(dir)) count++;
    closedir(dir); return count;
}
struct root_thread {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    pid_t tid;
    int release;
};
static void *hold_thread(void *argument) {
    struct root_thread *state=argument;
    assert(!pthread_mutex_lock(&state->mutex));
    state->tid=(pid_t)syscall(SYS_gettid);
    assert(!pthread_cond_signal(&state->condition));
    /* EVENT_WAIT: the fixture releases the owner after root/copy validation;
     * the fixture alarm bounds missing progress. */
    while (!state->release) assert(!pthread_cond_wait(&state->condition,&state->mutex));
    assert(!pthread_mutex_unlock(&state->mutex));
    return NULL;
}
static void nonleader_root(void) {
    int dumpable=prctl(PR_GET_DUMPABLE); assert(dumpable>=0);
    for (int protected=0;protected<2;++protected) {
        assert(!prctl(PR_SET_DUMPABLE,!protected));
        struct root_thread state={.mutex=PTHREAD_MUTEX_INITIALIZER,.condition=PTHREAD_COND_INITIALIZER};
        pthread_t thread; assert(!pthread_create(&thread,NULL,hold_thread,&state));
        assert(!pthread_mutex_lock(&state.mutex));
        /* EVENT_WAIT: the exact non-leader publishes its identity while alive. */
        while (!state.tid) assert(!pthread_cond_wait(&state.condition,&state.mutex));
        assert(state.tid!=getpid());
        struct md_guest_domain *root=md_domain_new(); assert(root);
        assert(!md_domain_restrict(root,state.tid,"/proc/self/fdinfo"));
        assert(!md_domain_chdir_root(root));
        struct md_guest_domain *copy=md_domain_fork(root,0); assert(copy);
        md_domain_release(root);
        assert(!md_domain_chdir_root(copy));
        assert(md_domain_path_error(copy)==-EACCES);
        md_domain_release(copy);
        state.release=1; assert(!pthread_cond_signal(&state.condition));
        assert(!pthread_mutex_unlock(&state.mutex));
        /* EVENT_WAIT: exact thread completion before destroying shared state. */
        assert(!pthread_join(thread,NULL));
        assert(!pthread_cond_destroy(&state.condition));
        assert(!pthread_mutex_destroy(&state.mutex));
    }
    assert(!prctl(PR_SET_DUMPABLE,dumpable));
}
static void contract(void) {
    struct md_task_resources parent, child, sibling;
    struct md_mount_namespace *mounts=md_mount_namespace_new(); assert(mounts);
    assert(!md_resources_init(&parent,mounts));
    md_mount_namespace_release(mounts);
    assert(!md_resources_fork(&parent, CLONE_FS | CLONE_SYSVSEM, &child));
    assert(child.fs == parent.fs && child.sem_undo == parent.sem_undo);
    assert(child.mounts==parent.mounts);
    assert(!md_resources_fork(&parent, 0, &sibling));
    assert(sibling.fs != parent.fs && sibling.sem_undo != parent.sem_undo);
    assert(sibling.files!=parent.files);
    assert(sibling.mounts==parent.mounts);
    struct md_resource_change change;
    assert(!md_resources_unshare_prepare(&child, CLONE_FS | CLONE_SYSVSEM,NULL,&change));
    assert(change.next.fs != child.fs && change.next.sem_undo != child.sem_undo);
    assert(!md_resources_unshare_finish(&child,NULL,&change, -EINVAL));
    assert(child.fs == parent.fs && child.sem_undo == parent.sem_undo);
    assert(!change.next.fs && !change.next.sem_undo && !change.next.mounts);
    assert(!md_resources_unshare_prepare(&child, CLONE_FILES,NULL,&change));
    assert(!change.next.fs && !change.next.sem_undo);
    assert(!md_resources_unshare_finish(&child,NULL,&change, 0));
    assert(child.fs == parent.fs && child.sem_undo == parent.sem_undo);
    assert(!md_resources_unshare_prepare(&child, CLONE_FS,NULL,&change));
    assert(!md_resources_unshare_finish(&child,NULL,&change, 0));
    assert(child.fs != parent.fs && child.sem_undo == parent.sem_undo);
    assert(child.mounts==parent.mounts);
    assert(!md_resources_unshare_prepare(&child, CLONE_SYSVSEM,NULL,&change));
    assert(!md_resources_unshare_finish(&child,NULL,&change, 0));
    assert(child.sem_undo != parent.sem_undo);
    md_domain_pin(child.fs);
    assert(!md_resources_unshare_prepare(&child, CLONE_FS,NULL,&change));
    assert(change.next.fs == child.fs); // A sole owner needs no duplicate.
    assert(!md_resources_unshare_finish(&child,NULL,&change, 0));
    md_domain_unpin(child.fs);
    assert(!md_domain_restrict(child.fs, getpid(), "/proc/self/fdinfo"));
    assert(!md_domain_chdir_root(child.fs));
    assert(md_domain_restricted(child.fs) && !md_domain_restricted(parent.fs));
    assert(!md_resources_release(&sibling));
    assert(!md_resources_fork(&child, CLONE_FS, &sibling));
    assert(!md_resources_unshare_prepare(&sibling, CLONE_FS,NULL,&change));
    assert(change.next.fs != child.fs);
    assert(!md_resources_unshare_finish(&sibling,NULL,&change, 0));
    assert(md_domain_restricted(sibling.fs) && md_domain_path_error(sibling.fs) == -EACCES);
    assert(!md_resources_release(&sibling));
    assert(!md_resources_release(&child));
    assert(!md_resources_release(&parent));
}
static void root_is(struct md_guest_domain *fs, const struct md_fs_location *expected) {
    struct md_fs_location root; struct md_fs_anchor *cwd=NULL;
    md_domain_paths(fs,&root,&cwd);
    assert(root.mount==expected->mount && !strcmp(root.object,expected->object));
    md_fs_anchor_release(cwd);
}
static void pending_root_relocation(void) {
    struct md_mount_namespace *view=md_mount_namespace_new(), *other=md_mount_namespace_new();
    assert(view && other);
    struct md_task_resources parent, child;
    assert(!md_resources_init(&parent,view));
    const struct md_fs_location old={.mount=71,.object="11111111111111111111111111111111"};
    const struct md_fs_location next={.mount=72,.object="22222222222222222222222222222222"};
    assert(!md_domain_set_root(parent.fs,&old));
    assert(!md_resources_fork(&parent,CLONE_FS,&child));
    struct md_resource_change pending;
    assert(!md_resources_unshare_prepare(&child,CLONE_FS,NULL,&pending));
    assert(pending.next.fs && pending.next.fs!=parent.fs);
    struct md_guest_domain *forked=md_domain_fork(parent.fs,0); assert(forked);
    struct md_guest_domain *isolated=md_domain_fork(parent.fs,0); assert(isolated);
    md_domain_bind_mounts(isolated,other);
    /* Neither candidate has a task registry entry. Root relocation must cover
     * copied-but-unpublished contexts, without touching another namespace. */
    md_domain_relocate_roots(view,&old,&next,NULL,NULL);
    root_is(parent.fs,&next); root_is(pending.next.fs,&next); root_is(forked,&next);
    root_is(isolated,&old);
    assert(!md_resources_unshare_finish(&child,NULL,&pending,0)); root_is(child.fs,&next);
    md_domain_release(forked); md_domain_release(isolated);
    assert(!md_resources_release(&child)); assert(!md_resources_release(&parent));
    md_mount_namespace_release(view); md_mount_namespace_release(other);
}
int main(void) {
    alarm(60);
    unsigned long spaces[] = {CLONE_NEWPID, CLONE_NEWNET, CLONE_NEWCGROUP};
    struct md_identity identity=md_identity_new(0,0);
    struct md_task_resources r; assert(!md_resources_init(&r,NULL));
    for (unsigned i = 0; i < sizeof(spaces)/sizeof(*spaces); i++) {
        struct md_resource_change change;
        assert(!md_resources_clone_supported(spaces[i]));
        assert(md_resources_unshare_prepare(&r, spaces[i] | CLONE_FS,NULL,&change) == -ENOTSUP);
        assert(!change.next.fs && !change.next.sem_undo);
    }
    struct md_resource_change change;
    assert(md_resources_clone_supported(CLONE_NEWUTS));
    assert(md_resources_clone_supported(CLONE_NEWIPC));
    assert(!md_resources_clone_supported(CLONE_NEWIPC|CLONE_SYSVSEM));
    struct md_task_resources sibling;
    assert(!md_resources_fork(&r,0,&sibling) && sibling.uts==r.uts);
    assert(!md_uts_namespace_set(r.uts,0,"parent",6));
    assert(!md_resources_unshare_prepare(&r,CLONE_NEWUTS,&identity,&change));
    assert(change.next.uts && change.next.uts!=r.uts);
    assert(!md_resources_unshare_finish(&r,NULL,&change,-EINVAL) && r.uts==sibling.uts);
    assert(!md_resources_unshare_prepare(&r,CLONE_NEWUTS,&identity,&change));
    assert(!md_resources_unshare_finish(&r,NULL,&change,0) && r.uts!=sibling.uts);
    struct utsname names;
    md_uts_namespace_read(r.uts,&names); assert(!strcmp(names.nodename,"parent"));
    assert(!md_uts_namespace_set(r.uts,0,"child",5));
    md_uts_namespace_read(sibling.uts,&names); assert(!strcmp(names.nodename,"parent"));
    assert(!md_resources_release(&sibling));
    assert(md_resources_clone_supported(CLONE_NEWNS));
    assert(!md_resources_clone_supported(CLONE_NEWNS|CLONE_FS));
    assert(md_resources_unshare_prepare(&r,CLONE_NEWNS,NULL,&change)==-ENOTSUP);
    r.mounts=md_mount_namespace_new(); assert(r.mounts);
    assert(!md_resources_unshare_prepare(&r,CLONE_NEWNS,&identity,&change));
    assert(change.copy_mounts && !change.next.fs && !change.next.mounts);
    assert(md_resources_unshare_finish(&r,NULL,&change,0)==-EINVAL);
    assert(md_resources_unshare_prepare(&r, 1UL << 63,NULL,&change) == -EINVAL);
    assert(!md_resources_release(&r));
    int before = descriptors();
    for (unsigned i = 0; i < 100; i++) contract();
    for (unsigned i = 0; i < 100; i++) pending_root_relocation();
    nonleader_root();
    assert(descriptors() == before);
    test_fd_origins();
    test_ofd_order();
    test_user_namespace();
    puts("PASS resource ownership, transactional unshare, retained roots and descriptor lifetime");
    alarm(0);
    return 0;
}

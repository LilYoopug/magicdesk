#define _GNU_SOURCE
#include "task_resources.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <unistd.h>

void test_fd_origins(void);
static int descriptors(void) {
    DIR *dir = opendir("/proc/self/fd"); assert(dir);
    int count = 0;
    while (readdir(dir)) count++;
    closedir(dir); return count;
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
    assert(!md_resources_unshare_prepare(&child, CLONE_FS | CLONE_SYSVSEM, &change));
    assert(change.next.fs != child.fs && change.next.sem_undo != child.sem_undo);
    assert(!md_resources_unshare_finish(NULL, &child, &change, -EINVAL));
    assert(child.fs == parent.fs && child.sem_undo == parent.sem_undo);
    assert(!change.next.fs && !change.next.sem_undo && !change.next.mounts);
    assert(!md_resources_unshare_prepare(&child, CLONE_FILES, &change));
    assert(!change.next.fs && !change.next.sem_undo);
    assert(!md_resources_unshare_finish(NULL, &child, &change, 0));
    assert(child.fs == parent.fs && child.sem_undo == parent.sem_undo);
    assert(!md_resources_unshare_prepare(&child, CLONE_FS, &change));
    assert(!md_resources_unshare_finish(NULL, &child, &change, 0));
    assert(child.fs != parent.fs && child.sem_undo == parent.sem_undo);
    assert(child.mounts==parent.mounts);
    assert(!md_resources_unshare_prepare(&child, CLONE_SYSVSEM, &change));
    assert(!md_resources_unshare_finish(NULL, &child, &change, 0));
    assert(child.sem_undo != parent.sem_undo);
    md_domain_pin(child.fs);
    assert(!md_resources_unshare_prepare(&child, CLONE_FS, &change));
    assert(change.next.fs == child.fs); // A sole owner needs no duplicate.
    assert(!md_resources_unshare_finish(NULL, &child, &change, 0));
    md_domain_unpin(child.fs);
    assert(!md_domain_restrict(child.fs, getpid(), "/proc/self/fdinfo"));
    assert(!md_domain_chdir_root(child.fs));
    assert(md_domain_restricted(child.fs) && !md_domain_restricted(parent.fs));
    assert(!md_resources_release(NULL, &sibling));
    assert(!md_resources_fork(&child, CLONE_FS, &sibling));
    assert(!md_resources_unshare_prepare(&sibling, CLONE_FS, &change));
    assert(change.next.fs != child.fs);
    assert(!md_resources_unshare_finish(NULL, &sibling, &change, 0));
    assert(md_domain_restricted(sibling.fs) && md_domain_path_error(sibling.fs) == -EACCES);
    assert(!md_resources_release(NULL, &sibling));
    assert(!md_resources_release(NULL, &child));
    assert(!md_resources_release(NULL, &parent));
}
int main(void) {
    unsigned long spaces[] = {CLONE_NEWUSER, CLONE_NEWNS, CLONE_NEWUTS,
        CLONE_NEWIPC, CLONE_NEWPID, CLONE_NEWNET, CLONE_NEWCGROUP};
    struct md_task_resources r; assert(!md_resources_init(&r,NULL));
    for (unsigned i = 0; i < sizeof(spaces)/sizeof(*spaces); i++) {
        struct md_resource_change change;
        assert(!md_resources_clone_supported(spaces[i]));
        assert(md_resources_unshare_prepare(&r, spaces[i] | CLONE_FS, &change) == -ENOTSUP);
        assert(!change.next.fs && !change.next.sem_undo);
    }
    struct md_resource_change change;
    assert(md_resources_unshare_prepare(&r, 1UL << 63, &change) == -EINVAL);
    assert(!md_resources_release(NULL, &r));
    int before = descriptors();
    for (unsigned i = 0; i < 100; i++) contract();
    assert(descriptors() == before);
    test_fd_origins();
    puts("PASS resource ownership, transactional unshare, retained roots and descriptor lifetime");
    return 0;
}

#define _GNU_SOURCE
#include "mount_policy.h"
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

enum { MAGIC=0x4d444d50U, VERSION=4U,
    SEALS=F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_FUTURE_WRITE|F_SEAL_SEAL };
struct md_mount_policy_page { uint32_t magic, version, reserved; atomic_uint flags; };
_Static_assert(ATOMIC_INT_LOCK_FREE==2 && sizeof(atomic_uint)==4,
    "mount policy requires process-shared lock-free flags");
_Static_assert(sizeof(struct md_mount_policy_page)==16,"mount policy wire layout");

unsigned md_mount_policy_shared_flags(const struct md_mount_policy *p) {
    return atomic_load_explicit(&p->page->flags,memory_order_acquire);
}
int md_mount_policy_set(struct md_mount_policy *p, unsigned flags) {
    if (!p || flags&~MD_MOUNT_POLICY_MASK
            || ((flags>>MD_MOUNT_LOCK_SHIFT)&~flags)) return -EINVAL;
    unsigned previous=md_mount_policy_flags(p);
    if ((previous>>MD_MOUNT_LOCK_SHIFT)&~flags) return -EPERM;
    flags|=previous&MD_MOUNT_LOCKS;
    if (!p->page) p->local=flags;
    else if (!p->writer) return -EPERM;
    else atomic_store_explicit(&p->page->flags,flags,memory_order_release);
    return 0;
}
int md_mount_policy_lock(struct md_mount_policy *p) {
    unsigned flags=md_mount_policy_flags(p);
    return md_mount_policy_set(p,flags|((flags&MD_MOUNT_FLAGS)<<MD_MOUNT_LOCK_SHIFT));
}
void md_mount_policy_close(struct md_mount_policy *p) {
    if (!p) return;
    if (p->page) { munmap(p->page,sizeof(*p->page)); close(p->fd); }
    *p=(struct md_mount_policy){0};
}
int md_mount_policy_share(struct md_mount_policy *p) {
    if (!p) return -EINVAL;
    if (p->page) return p->fd;
    int fd=memfd_create("shroot-mount-policy",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    if (fd<0) return -errno;
    int r=ftruncate(fd,sizeof(struct md_mount_policy_page)) ? -errno : 0;
    struct md_mount_policy_page *page=MAP_FAILED;
    if (!r) {
        page=mmap(NULL,sizeof(*page),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
        if (page==MAP_FAILED) r=-errno;
    }
    if (!r) {
        *page=(struct md_mount_policy_page){.magic=MAGIC,.version=VERSION};
        atomic_init(&page->flags,p->local);
        /* Only this pre-existing mapping remains writable. Receivers cannot
         * change size, write through the FD or acquire a new writable mapping. */
        if (fcntl(fd,F_ADD_SEALS,SEALS)) r=-errno;
    }
    if (r) {
        if (page!=MAP_FAILED) munmap(page,sizeof(*page));
        close(fd); return r;
    }
    p->page=page; p->fd=fd; p->writer=1; return fd;
}
int md_mount_policy_import(struct md_mount_policy *p, int fd) {
    if (!p || p->page || p->local || fd<0) return -EINVAL;
    int flags=fcntl(fd,F_GETFD);
    if (flags<0) return -errno;
    if (!(flags&FD_CLOEXEC)) return -EINVAL;
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    if (!S_ISREG(st.st_mode) || st.st_size!=sizeof(struct md_mount_policy_page)) return -EPROTO;
    int seals=fcntl(fd,F_GET_SEALS);
    if (seals<0) return -errno;
    if ((seals&SEALS)!=SEALS) return -EPROTO;
    struct md_mount_policy_page *page=mmap(NULL,sizeof(*page),PROT_READ,MAP_SHARED,fd,0);
    if (page==MAP_FAILED) return -errno;
    unsigned flags_value=atomic_load_explicit(&page->flags,memory_order_acquire);
    int r=page->magic!=MAGIC || page->version!=VERSION || page->reserved
        || (flags_value&~MD_MOUNT_POLICY_MASK)
        || ((flags_value>>MD_MOUNT_LOCK_SHIFT)&~flags_value) ? -EPROTO : 0;
    if (r) { munmap(page,sizeof(*page)); return r; }
    p->page=page; p->fd=fd; p->writer=0; return 0;
}

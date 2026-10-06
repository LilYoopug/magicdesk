#define _GNU_SOURCE
#include "fd_delivery.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

void md_fd_delivery_dispose(struct md_fd_delivery *d) {
    if (!d) return;
    if (d->capacity) {
        for (unsigned i=0;i<d->capacity;++i) md_fd_origins_finish(d->updates+i,-1);
        if (d->receipt_fd>=0) {
            if (d->receipt) munmap(d->receipt,md_fd_receipt_size(d->capacity));
            close(d->receipt_fd);
        }
    }
    *d=(struct md_fd_delivery){0};
}
int md_fd_delivery_prepare_mapped(struct md_fd_delivery *d, struct md_fd_origins *files,
        struct md_fs_anchor *const *origins, unsigned flags, unsigned capacity,
        struct md_fd_origin_update *updates, int *numbers, struct md_fd_receipt *receipt) {
    if (!d || !files || !origins || !updates || !numbers || !receipt
            || !md_fd_receipt_size(capacity) || (flags&~FD_CLOEXEC)) return -EINVAL;
    if (d->capacity) return -EBUSY;
    int error=md_fd_origins_prepare_batch(files,origins,flags,capacity,updates);
    if (!error) *d=(struct md_fd_delivery){.capacity=capacity,.updates=updates,.numbers=numbers,
        .receipt=receipt,.receipt_fd=-1};
    return error;
}
int md_fd_delivery_prepare(struct md_fd_delivery *d, struct md_fd_origins *files,
        struct md_fs_anchor *const *origins, unsigned flags, unsigned capacity,
        struct md_fd_origin_update *updates, int *numbers) {
    size_t size=md_fd_receipt_size(capacity);
    if (!d || !files || !origins || !updates || !numbers || !size || (flags&~FD_CLOEXEC)) return -EINVAL;
    if (d->capacity) return -EBUSY;
    int error=md_fd_origins_prepare_batch(files,origins,flags,capacity,updates);
    if (error) return error;
    struct md_fd_delivery next={.capacity=capacity,.updates=updates,.numbers=numbers,.receipt_fd=-1};
    next.receipt_fd=memfd_create("guest-fd-receipt",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    if (next.receipt_fd<0) error=-errno;
    else if (ftruncate(next.receipt_fd,size)
            || fcntl(next.receipt_fd,F_ADD_SEALS,F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_SEAL)) error=-errno;
    else {
        void *memory=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_SHARED,next.receipt_fd,0);
        if (memory==MAP_FAILED) error=-errno;
        else next.receipt=memory;
    }
    if (error) md_fd_delivery_dispose(&next);
    else *d=next;
    return error;
}
int md_fd_delivery_receipt(const struct md_fd_delivery *d) {
    return d && d->capacity ? d->receipt_fd : -1;
}
int md_fd_delivery_publish(struct md_fd_delivery *d) {
    if (!d || !d->capacity) return -EINVAL;
    if (d->published) return -EALREADY;
    int count=md_fd_receipt_read(d->receipt,d->capacity,d->numbers);
    if (count<=0) return count;
    int error=md_fd_origins_finish_batch(d->updates,d->capacity,d->numbers,(unsigned)count);
    if (error) return error;
    d->published=1;
    return count;
}

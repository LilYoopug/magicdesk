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
static int prepare(struct md_fd_delivery *d, struct md_fd_origins *files,
        struct md_fd_object *const *origins, unsigned flags, unsigned capacity,
        struct md_fd_origin_update *updates, int *numbers) {
    if (!d || !files || !origins || !updates || !numbers
            || !md_fd_receipt_size(capacity) || (flags&~FD_CLOEXEC)) return -EINVAL;
    if (d->capacity) return -EBUSY;
    int error=md_fd_origins_prepare_batch(files,origins,flags,capacity,updates);
    if (!error) *d=(struct md_fd_delivery){.capacity=capacity,.updates=updates,.numbers=numbers,
        .receipt_fd=-1};
    return error;
}
int md_fd_delivery_prepare_mapped(struct md_fd_delivery *d, struct md_fd_origins *files,
        struct md_fd_object *const *origins, unsigned flags, unsigned capacity,
        struct md_fd_origin_update *updates, int *numbers, struct md_fd_receipt *receipt) {
    if (!receipt) return -EINVAL;
    int error=prepare(d,files,origins,flags,capacity,updates,numbers);
    if (!error) d->receipt=receipt;
    return error;
}
int md_fd_delivery_prepare_observed(struct md_fd_delivery *d, struct md_fd_origins *files,
        struct md_fd_object *const *origins, unsigned flags, unsigned capacity,
        struct md_fd_origin_update *updates, int *numbers, const struct md_fd_table_observation *observation) {
    if (!observation) return -EINVAL;
    int error=prepare(d,files,origins,flags,capacity,updates,numbers);
    if (!error) d->observation=observation;
    return error;
}
int md_fd_delivery_prepare(struct md_fd_delivery *d, struct md_fd_origins *files,
        struct md_fd_object *const *origins, unsigned flags, unsigned capacity,
        struct md_fd_origin_update *updates, int *numbers) {
    size_t size=md_fd_receipt_size(capacity);
    int error=prepare(d,files,origins,flags,capacity,updates,numbers);
    if (error) return error;
    d->receipt_fd=memfd_create("guest-fd-receipt",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    if (d->receipt_fd<0) error=-errno;
    else if (ftruncate(d->receipt_fd,size)
            || fcntl(d->receipt_fd,F_ADD_SEALS,F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_SEAL)) error=-errno;
    else {
        void *memory=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_SHARED,d->receipt_fd,0);
        if (memory==MAP_FAILED) error=-errno;
        else d->receipt=memory;
    }
    if (error) md_fd_delivery_dispose(d);
    return error;
}
int md_fd_delivery_receipt(const struct md_fd_delivery *d) {
    return d && d->capacity ? d->receipt_fd : -1;
}
int md_fd_delivery_publish(struct md_fd_delivery *d) {
    if (!d || !d->capacity) return -EINVAL;
    if (d->published) return -EALREADY;
    if (d->observation && d->observation->capacity!=d->capacity) return -EINVAL;
    int count=d->observation ? md_fd_table_observation_read(d->observation,d->numbers)
        : md_fd_receipt_read(d->receipt,d->capacity,d->numbers);
    if (count<=0) return count;
    int error=md_fd_origins_finish_batch(d->updates,d->capacity,d->numbers,(unsigned)count);
    if (error) return error;
    d->published=1;
    return count;
}

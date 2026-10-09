#define _GNU_SOURCE
#include "interception_buffers.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

struct slot { uint64_t generation; unsigned references; };
struct md_interception_buffers {
    void *memory;
    size_t size, stride, capacity, clear_prefix;
    unsigned slots, references, next;
    uint64_t generation;
    int fd;
    struct slot slot[];
};
int md_buffers_create(unsigned slots, size_t capacity, size_t clear_prefix, struct md_interception_buffers **out) {
    if (!out || !slots || !capacity || clear_prefix>capacity) return -EINVAL;
    size_t page=(size_t)getpagesize();
    if (capacity>SIZE_MAX-(page-1)) return -EOVERFLOW;
    size_t stride=(capacity+page-1)/page*page;
    size_t bytes;
    if (stride>PTRDIFF_MAX/slots
            || __builtin_mul_overflow((size_t)slots,sizeof(struct slot),&bytes)
            || __builtin_add_overflow(bytes,sizeof(struct md_interception_buffers),&bytes)) return -EOVERFLOW;
    struct md_interception_buffers *p=calloc(1,bytes);
    if (!p) return -ENOMEM;
    p->fd=-1; p->slots=slots; p->capacity=capacity; p->clear_prefix=clear_prefix;
    p->stride=stride; p->size=stride*slots; p->references=1;
    p->fd=memfd_create("guest-request-buffers",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    int error=0;
    if (p->fd<0 || ftruncate(p->fd,(off_t)p->size)
            || fcntl(p->fd,F_ADD_SEALS,F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_SEAL)) error=-errno;
    else {
        void *memory=mmap(NULL,p->size,PROT_READ|PROT_WRITE,MAP_SHARED,p->fd,0);
        if (memory==MAP_FAILED) error=-errno;
        else p->memory=memory;
    }
    if (error) md_buffers_release(p);
    else *out=p;
    return error;
}
struct md_interception_buffers *md_buffers_retain(struct md_interception_buffers *p) {
    if (p) {
        if (p->references==UINT_MAX) return NULL;
        ++p->references;
    }
    return p;
}
void md_buffers_release(struct md_interception_buffers *p) {
    if (!p || --p->references) return;
    if (p->memory) munmap(p->memory,p->size);
    if (p->fd>=0) close(p->fd);
    free(p);
}
int md_buffers_fd(const struct md_interception_buffers *p) { return p ? p->fd : -1; }
size_t md_buffers_size(const struct md_interception_buffers *p) { return p ? p->size : 0; }
static int valid(const struct md_interception_buffer *b) {
    if (!b || !b->pool) return -EINVAL;
    const struct md_interception_buffers *p=b->pool;
    return b->index<p->slots && b->generation && p->slot[b->index].generation==b->generation
        && p->slot[b->index].references ? 0 : -ESTALE;
}
int md_buffers_take(struct md_interception_buffers *p, struct md_interception_buffer *out) {
    if (!p || !out) return -EINVAL;
    if (out->pool) return -EBUSY;
    if (p->generation==UINT64_MAX || p->references==UINT_MAX) return -EOVERFLOW;
    for (unsigned n=0;n<p->slots;++n) {
        unsigned i=(unsigned)(((uint64_t)p->next+n)%p->slots);
        if (p->slot[i].references) continue;
        p->slot[i]=(struct slot){.generation=++p->generation,.references=1};
        ++p->references; p->next=(i+1)%p->slots;
        memset((char *)p->memory+i*p->stride,0,p->clear_prefix);
        *out=(struct md_interception_buffer){.pool=p,.index=i,.generation=p->generation};
        return 0;
    }
    return -EAGAIN;
}
int md_buffer_pin(const struct md_interception_buffer *b, struct md_interception_buffer *out) {
    if (!out) return -EINVAL;
    if (out->pool) return -EBUSY;
    int error=valid(b); if (error) return error;
    struct md_interception_buffers *p=b->pool;
    if (p->references==UINT_MAX || p->slot[b->index].references==UINT_MAX) return -EOVERFLOW;
    ++p->references; ++p->slot[b->index].references; *out=*b;
    return 0;
}
int md_buffer_span(const struct md_interception_buffer *b, struct md_buffer_span *out) {
    if (!out) return -EINVAL;
    int error=valid(b); if (error) return error;
    struct md_interception_buffers *p=b->pool;
    *out=(struct md_buffer_span){.data=(char *)p->memory+b->index*p->stride,
        .size=p->capacity,.offset=b->index*p->stride};
    return 0;
}
int md_buffer_release(struct md_interception_buffer *b) {
    if (!b) return -EINVAL;
    if (!b->pool) return 0;
    int error=valid(b); if (error) return error;
    struct md_interception_buffers *p=b->pool;
    --p->slot[b->index].references;
    *b=(struct md_interception_buffer){0};
    md_buffers_release(p);
    return 0;
}

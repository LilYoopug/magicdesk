#define _GNU_SOURCE
#include "interception_memory.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

struct slot { uintptr_t top; int used; struct slot *next; };
struct exec_range { uintptr_t first, end; };
struct md_interception_memory {
    unsigned references;
    struct slot *slots;
    struct md_interception_buffers *buffers;
    uintptr_t buffer_base;
    struct md_resource_queue mappings;
    struct exec_range *noexec;
    size_t ranges, capacity;
    int execution_unknown;
};

struct md_interception_memory *md_memory_new(void) {
    struct md_interception_memory *s = calloc(1, sizeof(*s));
    if (s) {
        if (md_resource_queue_init(&s->mappings)) { free(s); return NULL; }
        s->references=1;
    }
    return s;
}
struct md_interception_memory *md_memory_fork(struct md_interception_memory *s, int shared) {
    if (shared) { if (s->references==UINT_MAX) return NULL; s->references++; return s; }
    struct md_interception_memory *copy = md_memory_new();
    if (!copy) return NULL;
    /* fork inherits mappings, but not other threads or active continuations. */
    for (struct slot *p = s->slots; p; p = p->next) {
        if (md_memory_stack_add(copy, p->top)) { md_memory_release(copy); return NULL; }
        md_memory_stack_return(copy, p->top);
    }
    if (s->buffers && !(copy->buffers=md_buffers_retain(s->buffers))) {
        md_memory_release(copy); return NULL;
    }
    copy->buffer_base=s->buffer_base;
    if (s->ranges) {
        copy->noexec=malloc(s->ranges*sizeof(*copy->noexec));
        if (!copy->noexec) { md_memory_release(copy); return NULL; }
        memcpy(copy->noexec,s->noexec,s->ranges*sizeof(*copy->noexec));
        copy->ranges=copy->capacity=s->ranges;
    }
    copy->execution_unknown=s->execution_unknown;
    return copy;
}
void md_memory_release(struct md_interception_memory *s) {
    if (!s || --s->references) return;
    while (s->slots) { struct slot *next = s->slots->next; free(s->slots); s->slots = next; }
    md_buffers_release(s->buffers); md_resource_queue_destroy(&s->mappings); free(s->noexec); free(s);
}
uintptr_t md_memory_stack_take(struct md_interception_memory *s) {
    for (struct slot *p = s->slots; p; p = p->next)
        if (!p->used) { p->used = 1; return p->top; }
    return 0;
}
int md_memory_stack_add(struct md_interception_memory *s, uintptr_t top) {
    struct slot *p = malloc(sizeof(*p));
    if (!p) return -ENOMEM;
    *p = (struct slot){.top = top, .used = 1, .next = s->slots}; s->slots = p;
    return 0;
}
void md_memory_stack_return(struct md_interception_memory *s, uintptr_t top) {
    for (struct slot *p = s->slots; p; p = p->next)
        if (p->top == top) { p->used = 0; return; }
}
int md_memory_buffers_prepare(struct md_interception_memory *s, unsigned slots, size_t capacity, size_t clear_prefix) {
    if (!s) return -EINVAL;
    if (s->buffers) return -EALREADY;
    return md_buffers_create(slots,capacity,clear_prefix,&s->buffers);
}
struct md_interception_buffers *md_memory_buffers(struct md_interception_memory *s) {
    return s ? s->buffers : NULL;
}
int md_memory_buffers_mapped(struct md_interception_memory *s, uintptr_t base, size_t size) {
    if (!s || !s->buffers || !base || base%(size_t)getpagesize()
            || size!=md_buffers_size(s->buffers) || base>UINTPTR_MAX-size) return -EINVAL;
    if (s->buffer_base) return -EALREADY;
    s->buffer_base=base; return 0;
}
uintptr_t md_memory_buffer_address(struct md_interception_memory *s, const struct md_interception_buffer *b) {
    struct md_buffer_span span;
    return s && s->buffer_base && b && b->pool==s->buffers && !md_buffer_span(b,&span)
        ? s->buffer_base+span.offset : 0;
}
int md_memory_order_begin(struct md_interception_memory *s, struct md_resource_order *order,
        struct md_resource_wakeup *wake) {
    return s ? md_resource_order_begin(&s->mappings,order,wake) : -EINVAL;
}
int md_memory_has_policy(const struct md_interception_memory *s) {
    return s->ranges || s->execution_unknown;
}
static int rounded(size_t length, size_t *out) {
    size_t page=(size_t)getpagesize();
    if (length>SIZE_MAX-(page-1)) return -ENOMEM;
    *out=(length+page-1)&~(page-1); return 0;
}
static int intersects(const struct md_interception_memory *s, uintptr_t first, size_t length) {
    for (size_t i=0;i<s->ranges && s->noexec[i].first<first+length;++i)
        if (s->noexec[i].end>first) return 1;
    return 0;
}
int md_memory_exec_check(const struct md_interception_memory *s, uintptr_t first, size_t length) {
    if (first%(size_t)getpagesize()) return -EINVAL;
    size_t size;
    int error=rounded(length,&size);
    if (error || first>UINTPTR_MAX-size) return -ENOMEM;
    if (!size) return 0;
    if (s->execution_unknown) return -EIO;
    return intersects(s,first,size) ? -EACCES : 0;
}
static void remove_range(struct md_interception_memory *s, uintptr_t first, size_t size) {
    uintptr_t end=first+size;
    for (size_t i=0;size && i<s->ranges;) {
        struct exec_range *r=s->noexec+i;
        if (r->first>=end) break;
        if (r->end<=first) { ++i; continue; }
        if (r->first<first && r->end>end) {
            assert(s->ranges<s->capacity);
            memmove(r+2,r+1,(s->ranges-i-1)*sizeof(*r));
            r[1]=(struct exec_range){end,r->end}; r->end=first; ++s->ranges; break;
        }
        if (r->first<first) { r->end=first; ++i; }
        else if (r->end>end) { r->first=end; break; }
        else { memmove(r,r+1,(s->ranges-i-1)*sizeof(*r)); --s->ranges; }
    }
}
static void insert_range(struct md_interception_memory *s, uintptr_t first, size_t size) {
    if (!size) return;
    uintptr_t end=first+size;
    size_t begin=0;
    while (begin<s->ranges && s->noexec[begin].end<first) ++begin;
    size_t after=begin;
    while (after<s->ranges && s->noexec[after].first<=end) {
        if (s->noexec[after].first<first) first=s->noexec[after].first;
        if (s->noexec[after].end>end) end=s->noexec[after].end;
        ++after;
    }
    assert(s->ranges-(after-begin)<s->capacity);
    memmove(s->noexec+begin+1,s->noexec+after,(s->ranges-after)*sizeof(*s->noexec));
    s->noexec[begin]=(struct exec_range){first,end};
    s->ranges=s->ranges-(after-begin)+1;
}
int md_memory_mapping_prepare(struct md_interception_memory *s, struct md_mapping_change *c,
        enum md_mapping_operation operation, uintptr_t address, size_t length,
        size_t new_length, unsigned flags, int noexec) {
    if (c->prepared || operation<MD_MAPPING_MAP || operation>MD_MAPPING_REMAP) return -EINVAL;
    size_t size, next;
    int error=rounded(length,&size);
    if (!error) error=rounded(new_length,&next);
    if (error) return error;
    if (operation!=MD_MAPPING_MAP && address>UINTPTR_MAX-size) return -ENOMEM;
    if (operation==MD_MAPPING_REMAP) {
        if (address==UINTPTR_MAX) return -EINVAL;
        noexec=intersects(s,address,size ? size : 1);
    }
    if (s->ranges || noexec) {
        if (s->ranges>SIZE_MAX/sizeof(*s->noexec)-4) return -ENOMEM;
        size_t needed=s->ranges+4;
        if (needed>s->capacity) {
            size_t capacity=needed<=SIZE_MAX/2/sizeof(*s->noexec) ? needed*2 : needed;
            void *ranges=realloc(s->noexec,capacity*sizeof(*s->noexec));
            if (!ranges) return -ENOMEM;
            s->noexec=ranges; s->capacity=capacity;
        }
    }
    *c=(struct md_mapping_change){operation,address,size,next,flags,!!noexec,1};
    return 0;
}
void md_memory_mapping_finish(struct md_interception_memory *s, struct md_mapping_change *c, long result) {
    if (!c->prepared) return;
    if (result>=0) {
        if (c->operation==MD_MAPPING_UNMAP) remove_range(s,c->address,c->length);
        else {
            uintptr_t address=(uintptr_t)result;
            size_t size=c->operation==MD_MAPPING_MAP ? c->length : c->new_length;
            if (c->operation==MD_MAPPING_REMAP && !(c->flags&MREMAP_DONTUNMAP))
                remove_range(s,c->address,c->length);
            remove_range(s,address,size);
            if (c->noexec) insert_range(s,address,size);
        }
    }
    *c=(struct md_mapping_change){0};
}
void md_memory_mapping_abandon(struct md_interception_memory *s, struct md_mapping_change *c) {
    /* A lost mapping result is not proof that the kernel did nothing. Keep
     * surviving CLONE_VM users from granting execute rights to an unknown VMA. */
    if (c->prepared && c->noexec) s->execution_unknown=1;
    *c=(struct md_mapping_change){0};
}

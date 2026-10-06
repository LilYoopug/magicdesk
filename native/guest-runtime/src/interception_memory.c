#include "interception_memory.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

struct slot { uintptr_t top; int used; struct slot *next; };
struct md_interception_memory {
    unsigned references;
    struct slot *slots;
    struct md_interception_buffers *buffers;
    uintptr_t buffer_base;
    struct md_resource_queue mappings;
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
    return copy;
}
void md_memory_release(struct md_interception_memory *s) {
    if (!s || --s->references) return;
    while (s->slots) { struct slot *next = s->slots->next; free(s->slots); s->slots = next; }
    md_buffers_release(s->buffers); md_resource_queue_destroy(&s->mappings); free(s);
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

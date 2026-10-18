#define _GNU_SOURCE
#include "interception_memory.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

struct slot { uintptr_t top; int used; struct slot *next; };
struct policy_range { uintptr_t first, end; unsigned restrictions; };
enum { BACKING_BUCKETS = 127 };
struct backing_pool {
    size_t references;
    struct md_memory_backing *buckets[BACKING_BUCKETS];
};
struct md_memory_backing {
    size_t references;
    int fd, indexed;
    dev_t device;
    ino_t inode;
    struct backing_pool *pool;
    struct md_memory_backing *next;
};
struct md_memory_file_range {
    uintptr_t first, end;
    uint64_t offset;
    struct md_memory_backing *backing;
};
struct md_interception_memory {
    unsigned references;
    struct slot *slots;
    struct md_interception_buffers *buffers;
    uintptr_t buffer_base;
    struct md_resource_queue mappings;
    struct policy_range *restrictions;
    size_t ranges, capacity;
    int policy_unknown;
    struct md_memory_file_range *files;
    size_t file_count, file_capacity;
    struct md_private_memory_access access;
    int access_ready;
    int exposed;
    struct backing_pool *backings;
};
static unsigned backing_bucket(dev_t device, ino_t inode) {
    return ((uint64_t)device ^ (uint64_t)inode) % BACKING_BUCKETS;
}
static struct backing_pool *pool_retain(struct backing_pool *p) {
    assert(p->references<SIZE_MAX); ++p->references; return p;
}
static void pool_release(struct backing_pool *p) {
    if (p && !--p->references) {
        for (unsigned i=0;i<BACKING_BUCKETS;++i) assert(!p->buckets[i]);
        free(p);
    }
}
static struct md_memory_backing *backing_retain(struct md_memory_backing *b) {
    if (b) { assert(b->references<SIZE_MAX); ++b->references; }
    return b;
}
static void backing_release(struct md_memory_backing *b) {
    if (b && !--b->references) {
        struct backing_pool *p=b->pool;
        if (b->indexed) {
            struct md_memory_backing **slot=&p->buckets[backing_bucket(b->device,b->inode)];
            while (*slot && *slot!=b) slot=&(*slot)->next;
            assert(*slot==b); *slot=b->next;
        }
        close(b->fd); free(b); pool_release(p);
    }
}
static void file_ranges_release(struct md_memory_file_range *ranges, size_t count) {
    for (size_t i=0;i<count;++i) backing_release(ranges[i].backing);
    free(ranges);
}
static void files_forget(struct md_interception_memory *s) {
    file_ranges_release(s->files,s->file_count);
    s->files=NULL; s->file_count=s->file_capacity=0;
}

static struct md_interception_memory *memory_new(struct backing_pool *pool) {
    struct md_interception_memory *s = calloc(1, sizeof(*s));
    if (s) {
        if (md_resource_queue_init(&s->mappings)) { free(s); return NULL; }
        if (pool) s->backings=pool_retain(pool);
        else {
            s->backings=calloc(1,sizeof(*s->backings));
            if (!s->backings) { md_resource_queue_destroy(&s->mappings); free(s); return NULL; }
            s->backings->references=1;
        }
        s->references=1;
    }
    return s;
}
struct md_interception_memory *md_memory_new(void) { return memory_new(NULL); }
void md_memory_expose(struct md_interception_memory *s) { s->exposed=1; }
int md_memory_exposed(const struct md_interception_memory *s) { return s && s->exposed; }
struct md_interception_memory *md_memory_new_image(struct md_interception_memory *s) {
    return memory_new(s->backings);
}
struct md_interception_memory *md_memory_fork(struct md_interception_memory *s, int shared) {
    if (shared) { if (s->references==UINT_MAX) return NULL; s->references++; return s; }
    struct md_interception_memory *copy = memory_new(s->backings);
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
        copy->restrictions=malloc(s->ranges*sizeof(*copy->restrictions));
        if (!copy->restrictions) { md_memory_release(copy); return NULL; }
        memcpy(copy->restrictions,s->restrictions,s->ranges*sizeof(*copy->restrictions));
        copy->ranges=copy->capacity=s->ranges;
    }
    copy->policy_unknown=s->policy_unknown;
    if (s->file_count) {
        copy->files=malloc(s->file_count*sizeof(*copy->files));
        if (copy->files) {
            memcpy(copy->files,s->files,s->file_count*sizeof(*copy->files));
            copy->file_count=copy->file_capacity=s->file_count;
            for (size_t i=0;i<copy->file_count;++i) backing_retain(copy->files[i].backing);
        }
    }
    return copy;
}
void md_memory_release(struct md_interception_memory *s) {
    if (!s || --s->references) return;
    while (s->slots) { struct slot *next = s->slots->next; free(s->slots); s->slots = next; }
    md_buffers_release(s->buffers); md_resource_queue_destroy(&s->mappings); free(s->restrictions);
    if (s->access_ready) { close(s->access.maps); close(s->access.memory); close(s->access.pagemap); }
    file_ranges_release(s->files,s->file_count); pool_release(s->backings); free(s);
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
int md_memory_buffers_prepare(struct md_interception_memory *s, unsigned slots, size_t capacity,
        size_t clear_prefix, unsigned reserved) {
    if (!s) return -EINVAL;
    if (s->buffers) return -EALREADY;
    return md_buffers_create(slots,capacity,clear_prefix,reserved,&s->buffers);
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
int md_memory_private_access_set(struct md_interception_memory *s, const struct md_private_memory_access *access) {
    if (s->access_ready) return -EALREADY;
    int inputs[]={access->maps,access->memory,access->pagemap}, retained[3];
    for (unsigned i=0;i<3;++i) {
        retained[i]=fcntl(inputs[i],F_DUPFD_CLOEXEC,0);
        if (retained[i]<0) {
            int error=-errno;
            while (i) close(retained[--i]);
            return error;
        }
    }
    s->access=(struct md_private_memory_access){retained[0],retained[1],retained[2]};
    s->access_ready=1; return 0;
}
const struct md_private_memory_access *md_memory_private_access(const struct md_interception_memory *s) {
    return s->access_ready ? &s->access : NULL;
}
int md_memory_private_access_capture(struct md_interception_memory *s, pid_t task) {
    if (!s || task<=0) return -EINVAL;
    if (s->access_ready) return -EALREADY;
    char path[64];
    snprintf(path,sizeof(path),"/proc/%d",task);
    int directory=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if (directory<0) return -errno;
    const char *names[]={"smaps","mem","pagemap"};
    int fds[3], error=0;
    unsigned count=0;
    for (;count<3;++count) {
        fds[count]=openat(directory,names[count],(count==1 ? O_RDWR : O_RDONLY)|O_CLOEXEC);
        if (fds[count]<0) { error=-errno; break; }
    }
    close(directory);
    if (error) { while (count) close(fds[--count]); return error; }
    s->access=(struct md_private_memory_access){fds[0],fds[1],fds[2]};
    s->access_ready=1; return 0;
}
int md_memory_has_policy(const struct md_interception_memory *s) {
    return s->ranges || s->policy_unknown || s->file_count;
}
static int rounded(size_t length, size_t *out) {
    size_t page=(size_t)getpagesize();
    if (length>SIZE_MAX-(page-1)) return -ENOMEM;
    *out=(length+page-1)&~(page-1); return 0;
}
static int intersects(const struct md_interception_memory *s, uintptr_t first, size_t length) {
    unsigned restrictions=0;
    for (size_t i=0;i<s->ranges && s->restrictions[i].first<first+length;++i)
        if (s->restrictions[i].end>first) restrictions|=s->restrictions[i].restrictions;
    return (int)restrictions;
}
int md_memory_protect_check(const struct md_interception_memory *s, uintptr_t first, size_t length,unsigned protection) {
    if (first%(size_t)getpagesize()) return -EINVAL;
    size_t size;
    int error=rounded(length,&size);
    if (error || first>UINTPTR_MAX-size) return -ENOMEM;
    if (!size) return 0;
    unsigned requested=((protection&PROT_EXEC) ? MD_MAPPING_NOEXEC : 0)
        | ((protection&PROT_WRITE) ? MD_MAPPING_NOWRITE : 0);
    if (requested && s->policy_unknown) return -EIO;
    return intersects(s,first,size)&requested ? -EACCES : 0;
}
static void remove_range(struct md_interception_memory *s, uintptr_t first, size_t size) {
    uintptr_t end=first+size;
    for (size_t i=0;size && i<s->ranges;) {
        struct policy_range *r=s->restrictions+i;
        if (r->first>=end) break;
        if (r->end<=first) { ++i; continue; }
        if (r->first<first && r->end>end) {
            assert(s->ranges<s->capacity);
            memmove(r+2,r+1,(s->ranges-i-1)*sizeof(*r));
            r[1]=(struct policy_range){end,r->end,r->restrictions}; r->end=first; ++s->ranges; break;
        }
        if (r->first<first) { r->end=first; ++i; }
        else if (r->end>end) { r->first=end; break; }
        else { memmove(r,r+1,(s->ranges-i-1)*sizeof(*r)); --s->ranges; }
    }
}
static void insert_range(struct md_interception_memory *s, uintptr_t first, size_t size,unsigned restrictions) {
    if (!size) return;
    uintptr_t end=first+size;
    size_t begin=0;
    while (begin<s->ranges && (s->restrictions[begin].end<first
            || (s->restrictions[begin].end==first && s->restrictions[begin].restrictions!=restrictions))) ++begin;
    size_t after=begin;
    while (after<s->ranges && s->restrictions[after].first<=end && s->restrictions[after].restrictions==restrictions) {
        if (s->restrictions[after].first<first) first=s->restrictions[after].first;
        if (s->restrictions[after].end>end) end=s->restrictions[after].end;
        ++after;
    }
    assert(s->ranges-(after-begin)<s->capacity);
    memmove(s->restrictions+begin+1,s->restrictions+after,(s->ranges-after)*sizeof(*s->restrictions));
    s->restrictions[begin]=(struct policy_range){first,end,restrictions};
    s->ranges=s->ranges-(after-begin)+1;
}
static int files_reserve(struct md_interception_memory *s, size_t extra) {
    if (extra>SIZE_MAX/sizeof(*s->files)-s->file_count) return -ENOMEM;
    size_t needed=s->file_count+extra;
    if (needed<=s->file_capacity) return 0;
    size_t capacity=needed<=SIZE_MAX/2/sizeof(*s->files) ? needed*2 : needed;
    void *files=realloc(s->files,capacity*sizeof(*s->files));
    if (!files) return -ENOMEM;
    s->files=files; s->file_capacity=capacity; return 0;
}
static void files_remove(struct md_interception_memory *s, uintptr_t first, size_t size) {
    uintptr_t end=first+size;
    for (size_t i=0;size && i<s->file_count;) {
        struct md_memory_file_range *r=s->files+i;
        if (r->first>=end) break;
        if (r->end<=first) { ++i; continue; }
        if (r->first<first && r->end>end) {
            assert(s->file_count<s->file_capacity);
            memmove(r+2,r+1,(s->file_count-i-1)*sizeof(*r));
            r[1]=(struct md_memory_file_range){end,r->end,r->offset+end-r->first,backing_retain(r->backing)};
            r->end=first; ++s->file_count; break;
        }
        if (r->first<first) { r->end=first; ++i; }
        else if (r->end>end) { r->offset+=end-r->first; r->first=end; break; }
        else {
            backing_release(r->backing);
            memmove(r,r+1,(s->file_count-i-1)*sizeof(*r)); --s->file_count;
        }
    }
}
static void files_insert(struct md_interception_memory *s, struct md_memory_file_range r) {
    if (r.first==r.end) return;
    size_t i=0;
    while (i<s->file_count && s->files[i].first<r.first) ++i;
    assert(s->file_count<s->file_capacity);
    memmove(s->files+i+1,s->files+i,(s->file_count-i)*sizeof(*s->files));
    r.backing=backing_retain(r.backing); s->files[i]=r; ++s->file_count;
}
int md_memory_mapping_backing(struct md_interception_memory *s, struct md_mapping_change *c, int fd, uint64_t offset) {
    if (!c->prepared || c->operation!=MD_MAPPING_MAP || c->backing
            || (c->flags&MAP_TYPE)!=MAP_PRIVATE || (c->flags&MAP_ANONYMOUS)) return -EINVAL;
    if (offset%(size_t)getpagesize() || c->length>INT64_MAX
            || offset>(uint64_t)INT64_MAX-c->length) return -EINVAL;
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    if (!S_ISREG(st.st_mode)) return 0;
    int flags=fcntl(fd,F_GETFL);
    if (flags<0) return -errno;
    if ((flags&O_PATH) || (flags&O_ACCMODE)==O_WRONLY) return 0;
    int error=files_reserve(s,4);
    if (error) return error;
    /* Backings serve positional file reads/mappings only, never application
     * IO offsets. The pool owns no cached reference: the final mapping or
     * pending change removes its entry and closes the exact retained file. */
    unsigned bucket=backing_bucket(st.st_dev,st.st_ino);
    for (struct md_memory_backing *b=s->backings->buckets[bucket];b;b=b->next) {
        if (b->device==st.st_dev && b->inode==st.st_ino) {
            c->backing=backing_retain(b); c->offset=offset; return 0;
        }
    }
    struct md_memory_backing *b=malloc(sizeof(*b));
    if (!b) return -ENOMEM;
    /* A pooled source has its own read-only open description. Guest F_SETFL
     * cannot change another address space's repair source. If native policy
     * prevents reopening, retain the admitted description without pooling. */
    char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
    int retained=open(path,O_RDONLY|O_CLOEXEC), indexed=retained>=0;
    if (retained<0) retained=fcntl(fd,F_DUPFD_CLOEXEC,0);
    if (retained<0) { int error=-errno; free(b); return error; }
    *b=(struct md_memory_backing){.references=1,.fd=retained,.indexed=indexed,
        .device=st.st_dev,.inode=st.st_ino,.pool=pool_retain(s->backings),
        .next=s->backings->buckets[bucket]};
    if (indexed) s->backings->buckets[bucket]=b;
    c->backing=b; c->offset=offset; return 0;
}
int md_memory_file_view(const struct md_interception_memory *s, uintptr_t first, size_t size,
        int *fd, uint64_t *offset) {
    if (!size || first>UINTPTR_MAX-size || s->policy_unknown) return 0;
    uintptr_t cursor=first, end=first+size;
    const struct md_memory_backing *backing=NULL; uint64_t position=0;
    for (size_t i=0;i<s->file_count && cursor<end;++i) {
        const struct md_memory_file_range *r=s->files+i;
        if (r->end<=cursor) continue;
        if (r->first>cursor) return 0;
        uint64_t at=r->offset+cursor-r->first;
        if (!backing) { backing=r->backing; position=at; }
        else if (r->backing->device!=backing->device || r->backing->inode!=backing->inode
                || at!=position+cursor-first) return 0;
        cursor=r->end<end ? r->end : end;
    }
    if (cursor!=end) return 0;
    *fd=backing->fd; *offset=position; return 1;
}
static void change_release(struct md_mapping_change *c) {
    backing_release(c->backing); file_ranges_release(c->moving,c->moving_count);
    *c=(struct md_mapping_change){0};
}
static int files_prepare(struct md_interception_memory *s, struct md_mapping_change *c) {
    if (!s->file_count) return 0;
    uintptr_t address=c->address;
    size_t size=c->length, next=c->new_length;
    if (c->operation==MD_MAPPING_REMAP && size) {
        size_t count=0;
        for (size_t i=0;i<s->file_count;++i)
            if (s->files[i].first<address+size && s->files[i].end>address) ++count;
        if (count) {
            c->moving=malloc(count*sizeof(*c->moving));
            if (!c->moving) return -ENOMEM;
            for (size_t i=0;i<s->file_count;++i) {
                struct md_memory_file_range r=s->files[i];
                if (r.first>=address+size || r.end<=address) continue;
                if (r.first<address) { r.offset+=address-r.first; r.first=address; }
                if (r.end>address+size) r.end=address+size;
                r.first-=address; r.end-=address;
                if (r.first>=next) continue;
                if (r.end>next || r.end==size) r.end=next;
                if (r.end-r.first>INT64_MAX || r.offset>(uint64_t)INT64_MAX-(r.end-r.first)) return -EOVERFLOW;
                r.backing=backing_retain(r.backing);
                c->moving[c->moving_count++]=r;
            }
        }
    }
    return files_reserve(s,4+c->moving_count);
}
int md_memory_mapping_prepare(struct md_interception_memory *s, struct md_mapping_change *c,
        enum md_mapping_operation operation, uintptr_t address, size_t length,
        size_t new_length, unsigned flags, int restrictions) {
    if (c->prepared || operation<MD_MAPPING_MAP || operation>MD_MAPPING_REMAP) return -EINVAL;
    size_t size, next;
    int error=rounded(length,&size);
    if (!error) error=rounded(new_length,&next);
    if (error) return error;
    if (operation!=MD_MAPPING_MAP && address>UINTPTR_MAX-size) return -ENOMEM;
    if (operation==MD_MAPPING_REMAP) {
        if (address==UINTPTR_MAX) return -EINVAL;
        restrictions=intersects(s,address,size ? size : 1);
    }
    if (s->ranges || restrictions) {
        if (s->ranges>SIZE_MAX/sizeof(*s->restrictions)-4) return -ENOMEM;
        size_t needed=s->ranges+4;
        if (needed>s->capacity) {
            size_t capacity=needed<=SIZE_MAX/2/sizeof(*s->restrictions) ? needed*2 : needed;
            void *ranges=realloc(s->restrictions,capacity*sizeof(*s->restrictions));
            if (!ranges) return -ENOMEM;
            s->restrictions=ranges; s->capacity=capacity;
        }
    }
    struct md_mapping_change candidate={.operation=operation,.address=address,.length=size,
        .new_length=next,.flags=flags,.restrictions=restrictions,.prepared=1};
    if (files_prepare(s,&candidate)) {
        /* File repair is optional. Memory pressure discards its authority,
         * without failing native mapping or dropping mandatory protections. */
        files_forget(s);
        file_ranges_release(candidate.moving,candidate.moving_count);
        candidate.moving=NULL; candidate.moving_count=0;
    }
    *c=candidate;
    return 0;
}
void md_memory_mapping_finish(struct md_interception_memory *s, struct md_mapping_change *c, long result) {
    if (!c->prepared) return;
    if (result>=0) {
        if (c->operation==MD_MAPPING_UNMAP) {
            remove_range(s,c->address,c->length); files_remove(s,c->address,c->length);
        }
        else {
            uintptr_t address=(uintptr_t)result;
            size_t size=c->operation==MD_MAPPING_MAP ? c->length : c->new_length;
            if (c->operation==MD_MAPPING_REMAP && !(c->flags&MREMAP_DONTUNMAP)) {
                remove_range(s,c->address,c->length); files_remove(s,c->address,c->length);
            }
            remove_range(s,address,size);
            files_remove(s,address,size);
            if (c->restrictions) insert_range(s,address,size,c->restrictions);
            if (c->backing) files_insert(s,(struct md_memory_file_range){address,address+size,c->offset,c->backing});
            for (size_t i=0;i<c->moving_count;++i) {
                struct md_memory_file_range r=c->moving[i];
                r.first+=address; r.end+=address; files_insert(s,r);
            }
        }
    }
    change_release(c);
}
void md_memory_mapping_abandon(struct md_interception_memory *s, struct md_mapping_change *c) {
    /* A lost mapping result is not proof that the kernel did nothing. Keep
     * surviving CLONE_VM users from upgrading rights to an unknown VMA. */
    if (c->prepared) {
        if (c->restrictions || s->ranges) s->policy_unknown=1;
        /* Optional repair provenance must not revoke otherwise native execute
         * permission. Losing it disables repair, not the kernel's own check. */
        files_forget(s);
    }
    change_release(c);
}

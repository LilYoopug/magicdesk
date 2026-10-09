#define _GNU_SOURCE
#include "memory_replace.h"
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>

int md_memory_replace_begin(struct md_memory_replace *r, uintptr_t original,
        uintptr_t candidate, size_t length, size_t page) {
    if (!r || r->phase!=MD_MEMORY_REPLACE_EMPTY || !page || (page&(page-1))
            || !original || !candidate || !length || length%page || original%page || candidate%page
            || length>INTPTR_MAX || original>INTPTR_MAX-length || candidate>INTPTR_MAX-length
            || (original<candidate+length && candidate<original+length)) return -EINVAL;
    *r=(struct md_memory_replace){.original=original,.candidate=candidate,.length=length,.page_size=page,
        .phase=MD_MEMORY_REPLACE_RESERVE};
    return 0;
}
static int broken(struct md_memory_replace *r) {
    r->phase=MD_MEMORY_REPLACE_BROKEN; r->pending=0; return -EIO;
}
int md_memory_replace_next(struct md_memory_replace *r, struct md_memory_replace_call *out) {
    if (!r || !out || r->phase==MD_MEMORY_REPLACE_EMPTY) return -EINVAL;
    if (r->phase==MD_MEMORY_REPLACE_BROKEN) return -EIO;
    if (r->pending) return -EBUSY;
    if (r->phase==MD_MEMORY_REPLACE_DONE) return 0;
    if (r->cancelled && !r->committed && r->phase<=MD_MEMORY_REPLACE_INSTALL) {
        r->error=-ECANCELED;
        r->phase=r->displaced ? MD_MEMORY_REPLACE_RESTORE : MD_MEMORY_REPLACE_DROP_CANDIDATE;
    }
    struct md_memory_replace_call call={0};
    switch (r->phase) {
        case MD_MEMORY_REPLACE_RESERVE:
            call=(struct md_memory_replace_call){SYS_mmap,
                {0,r->length,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,(unsigned long)-1,0}};
            break;
        case MD_MEMORY_REPLACE_SAVE:
        case MD_MEMORY_REPLACE_INSTALL:
        case MD_MEMORY_REPLACE_RESTORE:
            call=(struct md_memory_replace_call){SYS_mremap,
                {r->phase==MD_MEMORY_REPLACE_SAVE ? r->original :
                    r->phase==MD_MEMORY_REPLACE_INSTALL ? r->candidate : r->backup,
                 r->length,r->length,MREMAP_MAYMOVE|MREMAP_FIXED,
                 r->phase==MD_MEMORY_REPLACE_SAVE ? r->backup : r->original,0}};
            break;
        case MD_MEMORY_REPLACE_DROP_CANDIDATE:
            /* mremap may leave an empty source VMA when splitting failed.
             * Release both owned scratch ranges even after a successful move. */
            call=(struct md_memory_replace_call){SYS_munmap,{r->candidate,r->length}}; break;
        case MD_MEMORY_REPLACE_DROP_BACKUP:
            call=(struct md_memory_replace_call){SYS_munmap,{r->backup,r->length}}; break;
        default: return broken(r);
    }
    *out=call; r->pending=1; return 1;
}
int md_memory_replace_observed(struct md_memory_replace *r, long result) {
    if (!r || !r->pending) return -EINVAL;
    if (result < -4095) return broken(r);
    r->pending=0;
    switch (r->phase) {
        case MD_MEMORY_REPLACE_RESERVE:
            if (result<0) { r->error=result; r->phase=MD_MEMORY_REPLACE_DROP_CANDIDATE; }
            else {
                r->backup=(uintptr_t)result;
                if (!r->backup || r->backup%r->page_size || r->backup>INTPTR_MAX-r->length
                        || (r->backup<r->original+r->length && r->original<r->backup+r->length)
                        || (r->backup<r->candidate+r->length && r->candidate<r->backup+r->length)) return broken(r);
                r->phase=MD_MEMORY_REPLACE_SAVE;
            }
            break;
        case MD_MEMORY_REPLACE_SAVE:
            if (result<0) { r->error=result; r->phase=MD_MEMORY_REPLACE_DROP_CANDIDATE; }
            else if ((uintptr_t)result!=r->backup) return broken(r);
            else { r->displaced=1; r->phase=MD_MEMORY_REPLACE_INSTALL; }
            break;
        case MD_MEMORY_REPLACE_INSTALL:
            if (result<0) { r->error=result; r->phase=MD_MEMORY_REPLACE_RESTORE; }
            else if ((uintptr_t)result!=r->original) return broken(r);
            else { r->committed=1; r->displaced=0; r->phase=MD_MEMORY_REPLACE_DROP_CANDIDATE; }
            break;
        case MD_MEMORY_REPLACE_RESTORE:
            if ((uintptr_t)result!=r->original) return broken(r);
            r->displaced=0; r->phase=MD_MEMORY_REPLACE_DROP_CANDIDATE; break;
        case MD_MEMORY_REPLACE_DROP_CANDIDATE:
            if (result) return broken(r);
            r->candidate=0;
            r->phase=r->backup ? MD_MEMORY_REPLACE_DROP_BACKUP : MD_MEMORY_REPLACE_DONE;
            break;
        case MD_MEMORY_REPLACE_DROP_BACKUP:
            if (result) return broken(r);
            r->backup=0; r->phase=MD_MEMORY_REPLACE_DONE; break;
        default: return broken(r);
    }
    return 0;
}
void md_memory_replace_cancel(struct md_memory_replace *r) { if (r) r->cancelled=1; }
void md_memory_replace_lost(struct md_memory_replace *r) { if (r) broken(r); }
long md_memory_replace_result(const struct md_memory_replace *r) {
    if (!r || r->phase==MD_MEMORY_REPLACE_EMPTY) return -EINVAL;
    if (r->phase==MD_MEMORY_REPLACE_BROKEN) return -EIO;
    return r->phase==MD_MEMORY_REPLACE_DONE ? r->error : -EINPROGRESS;
}

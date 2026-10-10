#define _GNU_SOURCE
#include "private_memory.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

enum { DONTFORK=1, DONTDUMP=2, SEQUENTIAL=4, RANDOM=8, HUGE=16, NOHUGE=32, MERGEABLE=64, SOFT_DIRTY=128 };
struct vma { uintptr_t first, end; uint64_t offset, inode; unsigned major, minor; int private; };
struct lines { int fd; size_t cursor, size; char bytes[16384]; };
struct md_private_memory_scan {
    struct md_private_memory *mapping;
    struct stat backing;
    struct lines input;
    int selected;
};
static int line(struct lines *r, char *out, size_t capacity) {
    size_t used=0; int truncated=0;
    for (;;) {
        if (r->cursor==r->size) {
            long n=RAW3(read,r->fd,r->bytes,sizeof(r->bytes));
            if (n==-EINTR) continue;
            if (n<0) return (int)n;
            if (!n) return used || truncated ? -EPROTO : 0;
            r->cursor=0; r->size=(size_t)n;
        }
        const char *begin=r->bytes+r->cursor;
        const char *end=memchr(begin,'\n',r->size-r->cursor);
        size_t count=end ? (size_t)(end-begin) : r->size-r->cursor;
        size_t copy=count;
        if (copy>capacity-used-1) { copy=capacity-used-1; truncated=1; }
        memcpy(out+used,begin,copy); used+=copy; r->cursor+=count;
        if (end) { ++r->cursor; out[used]=0; return truncated ? 2 : 1; }
    }
}
static int number(const char **text, unsigned base, uint64_t *out) {
    const char *p=*text; uint64_t value=0; unsigned count=0;
    for (;;) {
        unsigned digit=*p>='0' && *p<='9' ? (unsigned)(*p-'0')
            : *p>='a' && *p<='f' ? (unsigned)(*p-'a'+10) : base;
        if (digit>=base) break;
        if (value>(UINT64_MAX-digit)/base) return 0;
        value=value*base+digit; ++p; ++count;
    }
    if (!count) return 0;
    *text=p; *out=value; return 1;
}
static void spaces(const char **p) { while (**p==' ') ++*p; }
static int header(const char *text, struct vma *v) {
    uint64_t first,end,offset,major,minor,inode;
    if (!number(&text,16,&first) || *text++!='-' || !number(&text,16,&end) || *text++!=' ') return 0;
    char permissions[4];
    for (unsigned i=0;i<4;++i) { if (!*text) return 0; permissions[i]=*text++; }
    if (*text++!=' ') return 0;
    if (!number(&text,16,&offset) || *text++!=' ' || !number(&text,16,&major)
            || *text++!=':' || !number(&text,16,&minor) || *text++!=' ') return 0;
    spaces(&text);
    if (!number(&text,10,&inode) || (*text && *text!=' ') || first>=end
            || first>UINTPTR_MAX || end>UINTPTR_MAX || major>UINT32_MAX || minor>UINT32_MAX) return 0;
    *v=(struct vma){first,end,offset,inode,(unsigned)major,(unsigned)minor,permissions[3]=='p'};
    return 1;
}
static int flags(const char *text, int protection, unsigned *advice, int *mapping_flags) {
    unsigned may=0;
    *advice=0; *mapping_flags=MAP_PRIVATE;
    while (*text) {
        spaces(&text); if (!*text) break;
        if (!text[1] || (text[2] && text[2]!=' ')) return -EPROTO;
        unsigned token=((unsigned char)text[0]<<8)|(unsigned char)text[1]; text+=2;
#define FLAG(a,b) (((a)<<8)|(b))
        switch (token) {
            case FLAG('m','r'): may|=PROT_READ; break;
            case FLAG('m','w'): may|=PROT_WRITE; break;
            case FLAG('m','e'): may|=PROT_EXEC; break;
            case FLAG('r','d'): case FLAG('w','r'): case FLAG('e','x'):
            case FLAG('a','c'): break;
            case FLAG('s','d'): *advice|=SOFT_DIRTY; break;
            case FLAG('n','r'): *mapping_flags|=MAP_NORESERVE; break;
            case FLAG('d','c'): *advice|=DONTFORK; break;
            case FLAG('d','d'): *advice|=DONTDUMP; break;
            case FLAG('s','r'): *advice|=SEQUENTIAL; break;
            case FLAG('r','r'): *advice|=RANDOM; break;
            case FLAG('h','g'): *advice|=HUGE; break;
            case FLAG('n','h'): *advice|=NOHUGE; break;
            case FLAG('m','g'): *advice|=MERGEABLE; break;
            /* Locked, device, huge-TLB, userfaultfd and unknown special VMAs
             * retain the original native error, never approximated semantics. */
            default: return -EOPNOTSUPP;
        }
#undef FLAG
    }
    return ((unsigned)protection&~may) ? -EACCES : 0;
}
long md_private_memory_scan_step(struct md_private_memory_scan *scan,struct md_private_memory_plan *plan) {
    struct md_private_memory *m=scan->mapping;
    char text[512]; struct vma v;
    for (unsigned i=0;i<128;++i) {
        int read=line(&scan->input,text,sizeof(text));
        if (read<=0) return read<0 ? read : -EFAULT;
        if (header(text,&v)) {
            if (v.first>m->address || scan->selected) return -EFAULT;
            if (v.end<=m->address) continue;
            if (v.end<m->address+m->length) return -EOPNOTSUPP;
            if (!v.private || v.inode!=scan->backing.st_ino || makedev(v.major,v.minor)!=scan->backing.st_dev
                    || v.offset>UINT64_MAX-(m->address-v.first)
                    || v.offset+m->address-v.first!=m->offset) return -ESTALE;
            scan->selected=1;
        } else if (scan->selected && md_prefix(text,"VmFlags:")) {
            int error=read==2 ? -EPROTO : flags(text+8,m->protection,&plan->advice,&plan->flags);
            return error ? error : 1;
        }
    }
    return 0;
}
static long exact(int fd, void *buffer, size_t size, uint64_t offset, int write) {
    long n;
    do { n=write ? RAW4(pwrite64,fd,buffer,size,offset) : RAW4(pread64,fd,buffer,size,offset); } while (n==-EINTR);
    return n==(long)size ? 0 : n<0 ? n : -EIO;
}
void md_private_memory_discard(struct md_private_memory *m) {
    if (m->candidate) RAW2(munmap,m->candidate,m->length);
    m->candidate=0;
}
void md_private_memory_access_close(struct md_private_memory_access *access) {
    if (access->maps>=0) RAW1(close,access->maps);
    if (access->memory>=0) RAW1(close,access->memory);
    if (access->pagemap>=0) RAW1(close,access->pagemap);
    *access=(struct md_private_memory_access){-1,-1,-1};
}
long md_private_memory_access_open(struct md_private_memory_access *access) {
    if (access->maps!=-1 || access->memory!=-1 || access->pagemap!=-1) return -EINVAL;
    struct md_private_memory_access next={-1,-1,-1};
    long error=RAW4(openat,AT_FDCWD,"/proc/self/smaps",O_RDONLY|O_CLOEXEC,0);
    if (error>=0) { next.maps=(int)error; error=RAW4(openat,AT_FDCWD,"/proc/self/mem",O_RDWR|O_CLOEXEC,0); }
    if (error>=0) { next.memory=(int)error; error=RAW4(openat,AT_FDCWD,"/proc/self/pagemap",O_RDONLY|O_CLOEXEC,0); }
    if (error>=0) { next.pagemap=(int)error; *access=next; return 0; }
    md_private_memory_access_close(&next); return error;
}
long md_private_memory_scan_begin(struct md_private_memory *m,const struct md_private_memory_access *access,
        struct md_private_memory_scan **out) {
    size_t page=m->page_size;
    if (m->candidate || !page || (page&(page-1)) || !m->length || m->length%page
            || m->address%page || m->address>UINTPTR_MAX-m->length || m->offset%page
            || m->length>INT64_MAX || m->offset>(uint64_t)INT64_MAX-m->length
            || !(m->protection&PROT_EXEC) || (m->protection&~(PROT_READ|PROT_WRITE|PROT_EXEC))) return -EINVAL;
    struct md_private_memory_scan *scan=calloc(1,sizeof(*scan));
    if (!scan) return -ENOMEM;
    long error=RAW2(fstat,m->source,&scan->backing);
    if (!error && !S_ISREG(scan->backing.st_mode)) error=-EOPNOTSUPP;
    if (!error) error=RAW3(lseek,access->maps,0,SEEK_SET);
    if (error<0) { free(scan); return error; }
    scan->mapping=m; scan->input.fd=access->maps; *out=scan; return 0;
}
void md_private_memory_scan_end(struct md_private_memory_scan *scan) { free(scan); }
long md_private_memory_plan(struct md_private_memory *m,const struct md_private_memory_access *access,
        struct md_private_memory_plan *plan) {
    struct md_private_memory_scan *scan=NULL;
    long error=md_private_memory_scan_begin(m,access,&scan);
    if (!error) do { error=md_private_memory_scan_step(scan,plan); } while (!error);
    md_private_memory_scan_end(scan); return error<0 ? error : 0;
}
long md_private_memory_copy_step(struct md_private_memory *m,const struct md_private_memory_access *access,
        const struct md_private_memory_plan *plan,size_t *position,void *scratch,size_t scratch_size) {
    if (!m->candidate || !m->page_size || m->length%m->page_size) return -EINVAL;
    size_t page=m->page_size;
    long error=0;
    if (!*position && !(plan->advice&SOFT_DIRTY)) {
        /* The unpublished candidate is a fresh, untouched mmap of our retained
         * source. Pagemap includes VM_SOFTDIRTY even for absent pages (5.15).
         * Inspect this exact VMA, not kernel-version guesses or another full
         * smaps walk. A cleared original must not become newly soft-dirty. */
        uint64_t entry=0;
        error=exact(access->pagemap,&entry,sizeof(entry),(m->candidate/page)*sizeof(entry),0);
        if (!error && (entry&(UINT64_C(1)<<55))) error=-EOPNOTSUPP;
    }
    if (error) return error;
    if (*position>m->length || *position%page || !scratch || scratch_size<page) return -EINVAL;
    if (!*position) m->copied_pages=0;
    uint64_t entries[256];
    size_t at=*position;
    if (at<m->length) {
        size_t count=(m->length-at)/page;
        if (count>sizeof(entries)/sizeof(*entries)) count=sizeof(entries)/sizeof(*entries);
        error=exact(access->pagemap,entries,count*sizeof(*entries),
            ((m->address+at)/page)*sizeof(*entries),0);
        if (error) return error;
        /* Bit 61 distinguishes file pages from private COW. Copying clean
         * pages would incorrectly detach them from later file writes. PFNs
         * are neither requested nor needed, including protected processes. */
        for (size_t i=0;!error && i<count;) {
            uint64_t entry=entries[i];
            if (!(entry&(UINT64_C(3)<<62)) || (entry&(UINT64_C(1)<<61))) { ++i; at+=page; continue; }
            size_t pages=1;
            while (i+pages<count && pages<scratch_size/page) {
                entry=entries[i+pages];
                if (!(entry&(UINT64_C(3)<<62)) || (entry&(UINT64_C(1)<<61))) break;
                ++pages;
            }
            size_t bytes=pages*page;
            error=exact(access->memory,scratch,bytes,m->address+at,0);
            if (!error) error=exact(access->memory,scratch,bytes,m->candidate+at,1);
            if (!error) m->copied_pages+=pages;
            i+=pages; at+=bytes;
        }
    }
    *position=at; return error ? error : at==m->length;
}
long md_private_memory_copy(struct md_private_memory *m,const struct md_private_memory_access *access,
        const struct md_private_memory_plan *plan) {
    size_t size=MD_PRIVATE_MEMORY_COPY_BYTES;
    if (m->page_size>size) size=m->page_size;
    long scratch=RAW6(mmap,0,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if (scratch<0) return scratch;
    size_t position=0; long result;
    do { result=md_private_memory_copy_step(m,access,plan,&position,(void *)scratch,size); } while (!result);
    RAW2(munmap,scratch,size); return result<0 ? result : 0;
}
int md_private_memory_advice(const struct md_private_memory_plan *plan, unsigned index) {
    const struct { unsigned bit; int value; } properties[]={
        {DONTFORK,MADV_DONTFORK},{DONTDUMP,MADV_DONTDUMP},{SEQUENTIAL,MADV_SEQUENTIAL},
        {RANDOM,MADV_RANDOM},{HUGE,MADV_HUGEPAGE},{NOHUGE,MADV_NOHUGEPAGE},{MERGEABLE,MADV_MERGEABLE}
    };
    for (size_t i=0;i<sizeof(properties)/sizeof(*properties);++i)
        if ((plan->advice&properties[i].bit) && !index--) return properties[i].value;
    return -1;
}
long md_private_memory_prepare(struct md_private_memory *m, const struct md_private_memory_access *access) {
    struct md_private_memory_plan plan;
    long error=md_private_memory_plan(m,access,&plan);
    if (error) return error;
    long candidate=RAW6(mmap,0,m->length,m->protection,plan.flags,m->source,m->offset);
    if (candidate<0) return candidate;
    m->candidate=(uintptr_t)candidate;
    error=md_private_memory_copy(m,access,&plan);
    for (unsigned i=0;!error;++i) {
        int advice=md_private_memory_advice(&plan,i);
        if (advice<0) break;
        error=RAW3(madvise,candidate,m->length,advice);
    }
    if (error) md_private_memory_discard(m);
    return error;
}

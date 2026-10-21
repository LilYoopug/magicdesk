#include "mapping_reader.h"
#include "raw.h"
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

int md_mapping_line(struct md_mapping_reader *r, char *out, size_t capacity) {
    if (!out || !capacity) return -EINVAL;
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
            : *p>='a' && *p<='f' ? (unsigned)(*p-'a'+10)
            : *p>='A' && *p<='F' ? (unsigned)(*p-'A'+10) : base;
        if (digit>=base) break;
        if (value>(UINT64_MAX-digit)/base) return 0;
        value=value*base+digit; ++p; ++count;
    }
    if (!count) return 0;
    *text=p; *out=value; return 1;
}
int md_mapping_parse(const char *text, int truncated, struct md_mapping_record *v) {
    uint64_t first,end,offset,major,minor,inode;
    if (!number(&text,16,&first) || *text++!='-' || !number(&text,16,&end) || *text++!=' ') return 0;
    char permissions[4];
    for (unsigned i=0;i<4;++i) { if (!*text) return 0; permissions[i]=*text++; }
    if (*text++!=' ' || (permissions[0]!='r' && permissions[0]!='-')
            || (permissions[1]!='w' && permissions[1]!='-')
            || (permissions[2]!='x' && permissions[2]!='-')
            || (permissions[3]!='p' && permissions[3]!='s')) return 0;
    if (!number(&text,16,&offset) || *text++!=' ' || !number(&text,16,&major)
            || *text++!=':' || !number(&text,16,&minor) || *text++!=' ') return 0;
    while (*text==' ') ++text;
    if (!number(&text,10,&inode) || (*text && *text!=' ') || (!*text && truncated)
            || first>=end || first>UINTPTR_MAX || end>UINTPTR_MAX
            || major>UINT32_MAX || minor>UINT32_MAX) return 0;
    int protection=(permissions[0]=='r' ? PROT_READ : 0)
        | (permissions[1]=='w' ? PROT_WRITE : 0) | (permissions[2]=='x' ? PROT_EXEC : 0);
    *v=(struct md_mapping_record){first,end,offset,inode,(unsigned)major,(unsigned)minor,
        protection,permissions[3]=='s'};
    return 1;
}
int md_mapping_next(struct md_mapping_reader *r, struct md_mapping_record *v) {
    char text[256];
    int result=md_mapping_line(r,text,sizeof(text));
    return result<=0 ? result : md_mapping_parse(text,result==2,v) ? 1 : -EPROTO;
}

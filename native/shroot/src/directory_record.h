#ifndef MD_DIRECTORY_RECORD_H
#define MD_DIRECTORY_RECORD_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct md_directory_entry { uint64_t inode; int64_t next; uint16_t size; uint8_t type; char name[]; };
_Static_assert(offsetof(struct md_directory_entry,name)==19,"Linux getdents64 ABI");

/* Binary framing only. Each directory owner defines its own cookies and
 * membership; neither inode identity nor ordering is inferred here. */
static inline size_t md_directory_record_size(size_t length) {
    size_t header=offsetof(struct md_directory_entry,name);
    return length>UINT16_MAX-header-8 ? 0 : (header+length+1+7)&~(size_t)7;
}
static inline size_t md_directory_record_write(void *out,size_t capacity,const char *name,size_t length,
        uint64_t inode,int64_t next,uint8_t type) {
    size_t size=md_directory_record_size(length);
    if (!size || size>capacity) return 0;
    struct md_directory_entry entry={.inode=inode,.next=next,.size=(uint16_t)size,.type=type};
    memset(out,0,size);
    memcpy(out,&entry,offsetof(struct md_directory_entry,name));
    memcpy((char *)out+offsetof(struct md_directory_entry,name),name,length);
    return size;
}
/* Name length, or zero for a malformed record. Also used by freestanding
 * launch/adapter code: no allocator or libc string routine is required. */
static inline size_t md_directory_record_read(const void *data,size_t available,struct md_directory_entry *out) {
    size_t header=offsetof(struct md_directory_entry,name);
    if (available<=header) return 0;
    struct md_directory_entry entry={0};
    memcpy(&entry,data,header);
    if (entry.size<=header || entry.size>available || entry.size%8) return 0;
    const char *name=(const char *)data+header;
    size_t length=0,limit=entry.size-header;
    while (length<limit && name[length]) {
        if (name[length]=='/') return 0;
        ++length;
    }
    if (!length || length==limit) return 0;
    *out=entry; return length;
}
#endif

#define _GNU_SOURCE
#include "fd_table_observation.h"
#include "directory_record.h"
#include <limits.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <unistd.h>

static int entry_number(const char *name) {
    if (!strcmp(name,".") || !strcmp(name,"..")) return -1;
    unsigned value=0;
    if (!*name) return -EPROTO;
    for (;*name;++name) {
        if (*name<'0' || *name>'9' || value>((unsigned)INT_MAX-(*name-'0'))/10) return -EPROTO;
        value=value*10+(*name-'0');
    }
    return (int)value;
}
/* Proc emits numeric entries in allocation order. A receive installs the
 * lowest available slots in that same order; control/header faults can leave
 * only a prefix. Bounded storage depends on parcel size, not RLIMIT_NOFILE. */
static int scan(const struct md_fd_table_observation *o, int *candidates) {
    if (lseek(o->directory,0,SEEK_SET)<0) return -errno;
    char buffer[4096];
    unsigned index=0, installed=0;
    long next=0, previous=-1;
    for (;;) {
        ssize_t size;
        do { size=syscall(SYS_getdents64,o->directory,buffer,sizeof(buffer)); } while (size<0 && errno==EINTR);
        if (size<0) return -errno;
        if (!size) break;
        for (size_t at=0;at<(size_t)size;) {
            struct md_directory_entry entry;
            if (!md_directory_record_read(buffer+at,(size_t)size-at,&entry)) return -EPROTO;
            int number=entry_number(buffer+at+offsetof(struct md_directory_entry,name));
            if (number<0 && number!=-1) return number;
            at+=entry.size;
            if (number<0) continue;
            if (number<=previous) return -EPROTO;
            previous=number;
            if (candidates) {
                while (next<number && index<o->capacity) candidates[index++]=(int)next++;
                if (index==o->capacity) return 0;
                next=(long)number+1;
            } else {
                while (index<o->capacity && o->candidates[index]<number) ++index;
                if (index==o->capacity) return (int)installed;
                if (o->candidates[index]==number) {
                    if (installed!=index) return -EPROTO;
                    ++installed; ++index;
                }
            }
        }
    }
    if (!candidates) return (int)installed;
    while (index<o->capacity) {
        if (next>INT_MAX) return -EOVERFLOW;
        candidates[index++]=(int)next++;
    }
    return 0;
}
int md_fd_table_observation_begin(struct md_fd_table_observation *o, int directory, unsigned capacity) {
    if (!o || directory<0 || !capacity || capacity>MD_FD_RECEIPT_MAX) return -EINVAL;
    if (o->capacity) return -EBUSY;
    o->directory=directory; o->capacity=capacity;
    int error=scan(o,o->candidates);
    if (error) *o=(struct md_fd_table_observation){0};
    return error;
}
int md_fd_table_observation_read(const struct md_fd_table_observation *o, int *numbers) {
    if (!o || !o->capacity || !numbers) return -EINVAL;
    int count=scan(o,NULL);
    if (count>0) memcpy(numbers,o->candidates,(unsigned)count*sizeof(*numbers));
    return count;
}

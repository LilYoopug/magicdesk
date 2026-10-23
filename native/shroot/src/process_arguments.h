#ifndef MD_PROCESS_ARGUMENTS_H
#define MD_PROCESS_ARGUMENTS_H
#include "proc_paths.h"
#include "arguments.h"
#include <errno.h>
#include <stdint.h>

typedef long (*md_argument_reader)(void *, uintptr_t, void *, size_t);
/* Linux's setproctitle convention: a replaced final argv NUL selects one
 * string, bounded by one page and the contiguous startup argument/environment
 * area. Both local and remote proc snapshots use this same selection. */
static inline long md_process_arguments_read(const struct md_process_image *image,
        size_t page_size, md_argument_reader read, void *context,
        void *out, size_t capacity, size_t offset) {
    size_t arguments=image->argument_bytes, environment=image->environment_bytes;
    uintptr_t start=(uintptr_t)image->arguments;
    if (arguments>MD_EXEC_BYTES || environment>MD_EXEC_BYTES
            || arguments>SIZE_MAX-environment || start>UINTPTR_MAX-arguments-environment) return -EPROTO;
    if (!arguments || !capacity || offset>=arguments+environment) return 0;
    char last=0;
    long result=read(context,start+arguments-1,&last,1);
    if (result!=1 || !last) {
        if (offset>=arguments) return 0;
        size_t size=arguments-offset;
        if (size>capacity) size=capacity;
        return read(context,start+offset,out,size);
    }
    size_t limit=arguments+environment, copied=0;
    if (limit>page_size) limit=page_size;
    if (offset>=limit) return 0;
    for (size_t position=0;position<limit;) {
        char bytes[256];
        size_t count=limit-position;
        if (count>sizeof(bytes)) count=sizeof(bytes);
        result=read(context,start+position,bytes,count);
        if (result<=0) return copied ? (long)copied : result;
        if ((size_t)result>count) return -EIO;
        for (long i=0;i<result;++i,++position) {
            if (position>=offset) ((char *)out)[copied++]=bytes[i];
            if (!bytes[i] || copied==capacity) return (long)copied;
        }
    }
    return (long)copied;
}
#endif

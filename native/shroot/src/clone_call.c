#include "clone_call.h"
#include "adapter_buffer.h"
#include "interception.h"
#include "raw.h"
#include <errno.h>
#include <string.h>

long md_clone3_prepare(unsigned long address,unsigned long size) {
    if (size>md_page_size) return -E2BIG;
    if (size<CLONE_ARGS_SIZE_VER0) return -EINVAL;
    long memory=md_adapter_buffer_take();
    if (memory<0) return memory;
    struct clone_args *args=(void *)memory;
    memset(args,0,sizeof(*args));
    long result=md_read_memory(args,(void *)address,size);
    if (!result) for (unsigned long i=sizeof(*args);i<size;++i)
        if (((unsigned char *)args)[i]) { result=-E2BIG; break; }
    /* These need logical PID allocation/cgroup admission, not host identities. */
    if (!result && (args->set_tid_size || (args->flags&CLONE_INTO_CGROUP))) result=-EOPNOTSUPP;
    if (!result && (args->flags&CLONE_NEWPID)) result=md_pid_filter_install();
    if (!result) return MD_CALL_CLONE;
    md_adapter_buffer_release(); return result;
}

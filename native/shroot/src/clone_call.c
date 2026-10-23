#include "clone_call.h"
#include "adapter_buffer.h"
#include "interception.h"
#include "fd_client.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <string.h>

static int valid_flags(const struct clone_args *args) {
    /* clone3 reserves the old signal/detached bits. Validate before acquiring
     * namespace/cgroup authority, in the same order as kernel argument copy. */
    uint64_t flags=args->flags;
    return !(flags&~(UINT64_C(0xffffffff)|CLONE_CLEAR_SIGHAND|CLONE_INTO_CGROUP))
        && !(flags&(CLONE_DETACHED|CSIGNAL))
        && (flags&(CLONE_SIGHAND|CLONE_CLEAR_SIGHAND))!=(CLONE_SIGHAND|CLONE_CLEAR_SIGHAND)
        && (!(flags&(CLONE_THREAD|CLONE_PARENT)) || !args->exit_signal)
        && (!!args->stack==!!args->stack_size);
}
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
    if (!result && (args->set_tid_size>MD_PID_LEVELS || !!args->set_tid!=!!args->set_tid_size)) result=-EINVAL;
    if (!result && args->exit_signal>=NSIG) result=-EINVAL;
    if (!result && (args->flags&CLONE_INTO_CGROUP)
            && (args->cgroup>INT_MAX || size<CLONE_ARGS_SIZE_VER2)) result=-EINVAL;
    if (!result && args->set_tid_size)
        result=md_read_memory(((struct md_clone_request *)args)->tids,
            (void *)args->set_tid,args->set_tid_size*sizeof(pid_t));
    if (!result && !valid_flags(args)) result=-EINVAL;
    if (!result && (args->flags&CLONE_NEWPID)) result=md_pid_filter_install();
    if (!result && (args->flags&CLONE_INTO_CGROUP)) {
        result=md_fd_control(MD_FD_USE,0,0,0);
        if (!result) {
            result=md_guest_buffer_control(MD_BUFFER_CLONE_CGROUP,args->cgroup,0);
            if (result==1) {
                result=RAW2(fcntl,(int)args->cgroup,F_GETFD);
                if (result>=0) result=-EINVAL;
            }
            /* Admission pins the cgroup, like kernel fget(), not the FD number. */
            long released=md_fd_control(MD_FD_RELEASE,0,0,0);
            if (!result) result=released;
        }
    }
    if (!result) return MD_CALL_CLONE;
    md_adapter_buffer_release(); return result;
}

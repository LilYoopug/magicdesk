/* Compiled inside musl, not linked with Bionic or loaded into ART. */
#include "pthread_impl.h"
#include "cooperative_entry.h"
#include "atomic.h"
#include <stdlib.h>

hidden const struct md_entry_api *__shroot_entry;
static int enabled;
hidden long __syscall_cp_asm(volatile void *,long,long,long,long,long,long,long);

static long cancellation_kernel(long nr,const uint64_t *args)
{
    return __syscall_cp_asm(&__pthread_self()->cancel,nr,
        args[0],args[1],args[2],args[3],args[4],args[5]);
}

hidden int __shroot_cp_try(long nr,long a,long b,long c,long d,long e,long f,long *result)
{
    pthread_t self=__pthread_self();
    if (!enabled || self->cancelasync || !md_entry_offered(__shroot_entry,nr,MD_ENTRY_CANCELLATION)) return 0;
    struct md_entry_call call={.number=nr,.args={a,b,c,d,e,f},.kernel=cancellation_kernel};
    enum md_entry_outcome outcome=__shroot_entry->try_syscall(&self->shroot_client,&call);
    if (outcome==MD_ENTRY_UNKNOWN) a_crash();
    if (outcome==MD_ENTRY_DECLINED) return 0;
    *result=call.result; return 1;
}

__attribute__((noinline)) static long kernel_call(long number,const uint64_t *args)
{
    register long x8 __asm__("x8")=number;
    register long x0 __asm__("x0")=args[0];
    register long x1 __asm__("x1")=args[1];
    register long x2 __asm__("x2")=args[2];
    register long x3 __asm__("x3")=args[3];
    register long x4 __asm__("x4")=args[4];
    register long x5 __asm__("x5")=args[5];
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5) : "memory","cc");
    return x0;
}

hidden void __shroot_init(size_t *auxv)
{
    const char *disabled=getenv("SHROOT_COOPERATIVE");
    enabled=!(disabled && disabled[0]=='0' && !disabled[1]);
    for (; auxv[0]; auxv+=2) if (auxv[0]==MD_AT_COOPERATIVE) {
        const struct md_entry_api *api=(void *)auxv[1];
        if (md_entry_api_valid(api)) __shroot_entry=api;
        break;
    }
    if (!__shroot_entry) enabled=0;
}

hidden int __shroot_try(long nr,long a,long b,long c,long d,long e,long f,long *result)
{
    struct md_entry_call call={.number=nr,.args={a,b,c,d,e,f},.kernel=kernel_call};
    if (!enabled) { *result=kernel_call(nr,call.args); return 1; }
    pthread_t self=__pthread_self();
    if (self->cancelasync) { *result=kernel_call(nr,call.args); return 1; }
    /* These are non-cancellation-point wrappers. Preserve cancellation state:
     * a signal handler may longjmp past this frame. The supervisor retires
     * worker memory ownership before delivering a signal or terminal stop. */
    enum md_entry_outcome outcome=__shroot_entry->try_syscall(&self->shroot_client,&call);
    if (outcome==MD_ENTRY_UNKNOWN) a_crash();
    if (outcome==MD_ENTRY_DECLINED) call.result=kernel_call(nr,call.args);
    *result=call.result;
    return 1;
}

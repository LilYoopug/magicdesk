#include "cooperative_channel.h"
#include "adapter_buffer.h"
#include "interception.h"
#include "raw.h"
#include "spin_policy.h"
#include "vdso.h"
#include "file_open.h"
#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <time.h>

extern long md_guest_entry_kernel(long,const uint64_t *);
static md_vdso_clock_fn vdso_clock;
static unsigned char offers[512];
void md_cooperative_init(const void *vdso,size_t first_page) {
    vdso_clock=md_vdso_clock(vdso,first_page);
    for (unsigned i=0;i<sizeof(offers);++i) {
        enum md_entry_route route=md_entry_route(i);
        offers[i]=(route!=MD_ENTRY_CALLER ? MD_ENTRY_ORDINARY : 0)
            |(route==MD_ENTRY_FD ? MD_ENTRY_CANCELLATION : 0);
    }
}
static enum md_entry_outcome kernel_call(struct md_entry_call *call) {
    md_entry_kernel_fn kernel=call->kernel ? call->kernel : md_guest_entry_kernel;
    call->result=kernel(call->number,call->args);
    return MD_ENTRY_COMPLETED;
}
static void native_cancel_check(struct md_entry_call *call) {
    if (call->number==SYS_openat && call->kernel) {
        const uint64_t args[6]={0,FUTEX_WAKE_PRIVATE,0,0,0,0};
        call->kernel(SYS_futex,args);
    }
}
static uint64_t now(void) {
    struct timespec ts;
    if ((!vdso_clock || vdso_clock(CLOCK_MONOTONIC,&ts))
            && RAW2(clock_gettime,CLOCK_MONOTONIC,&ts)<0) return 0;
    return (uint64_t)ts.tv_sec*1000000000ULL+ts.tv_nsec;
}
static enum md_entry_outcome invoke(struct md_entry_client *client,struct md_entry_call *call) {
    if (!client || !call || call->reserved || !md_entry_supported(call->number)) return MD_ENTRY_DECLINED;
    uintptr_t control=__atomic_fetch_or(&client->opaque[MD_ENTRY_CLIENT_CONTROL],MD_ENTRY_CLIENT_BUSY,__ATOMIC_ACQUIRE);
    if (control&MD_ENTRY_CLIENT_BUSY) return MD_ENTRY_DECLINED;
    struct md_entry_channel *c=(void *)client->opaque[MD_ENTRY_CLIENT_CHANNEL];
    enum md_entry_outcome outcome=MD_ENTRY_DECLINED;
    if (md_entry_route(call->number)==MD_ENTRY_TASK) goto kernel;
    if (c && !atomic_load_explicit(&c->enabled,memory_order_acquire)) goto kernel;
    if (!c) {
        uint32_t retry=(uint32_t)(control>>1);
        if (retry) {
            if (retry!=UINT32_MAX) control=(uintptr_t)(retry-1)<<1;
            goto kernel;
        }
        /* Registration is a supervisor trap, not a helper syscall through an
         * already installed application filter. Rejected clients touch no gate. */
        long address=md_guest_buffer_control(MD_BUFFER_COOPERATIVE,0,0);
        if (address<0) {
            control=(uintptr_t)(address==-EAGAIN || address==-ENOMEM ? 128 : UINT32_MAX)<<1;
            goto kernel;
        }
        c=(void *)address;
        client->opaque[MD_ENTRY_CLIENT_CHANNEL]=(uintptr_t)c;
        client->opaque[MD_ENTRY_CLIENT_OWNER]=(uintptr_t)c->owner;
    } else if ((uintptr_t)RAW0(gettid)!=client->opaque[MD_ENTRY_CLIENT_OWNER]) goto done;
    unsigned available=atomic_load_explicit(&c->state,memory_order_acquire);
    if (!atomic_load_explicit(&c->enabled,memory_order_acquire)
            || (available!=MD_ENTRY_IDLE && available!=MD_ENTRY_RETIRING)
            || c->sequence==UINT64_MAX) goto done;
    int native=md_entry_native_fd(call->number,call->args)
        || (call->number==SYS_openat && md_open_native_plan(call->args[2]));
    int create_probe=native && call->number==SYS_openat && (call->args[2]&O_CREAT);
    if (create_probe && c->create_cooldown) {
        --c->create_cooldown; native=0; create_probe=0;
    }
    int descriptor=md_entry_route(call->number)==MD_ENTRY_FD && !native;
    if (native) native_cancel_check(call);
    ++c->sequence; c->call=*call;
    atomic_store_explicit(&c->state,descriptor ? MD_ENTRY_FD_REQUEST : MD_ENTRY_REQUEST,memory_order_seq_cst);
    long descriptor_result=0;
    outcome=MD_ENTRY_UNKNOWN; call->result=-EIO;
    if (descriptor) {
        /* The original syscall is the only publication carrier. Its kernel
         * admission also preserves libc cancellation regions and filters.
         * No descriptor effect is allowed before the exact notification. */
        kernel_call(call); descriptor_result=call->result;
        unsigned pending=MD_ENTRY_FD_REQUEST;
        if (atomic_compare_exchange_strong_explicit(&c->state,&pending,MD_ENTRY_IDLE,
                memory_order_acq_rel,memory_order_acquire)) {
            /* A kernel filter rejected the call before broker admission. The
             * worker never consumes FD requests without a notification. */
            --c->sequence; outcome=MD_ENTRY_COMPLETED; goto done;
        }
    } else if (!atomic_load_explicit(&c->awake,memory_order_seq_cst))
        md_guest_buffer_admit(MD_ENTRY_WAKE);
    struct md_spin_policy policy=c->feedback;
    unsigned budget=0, parked=0, checks=0, spun=0, native_sent=0;
    uint64_t spin=0, time=0;
    for (;;) {
        unsigned state=atomic_load_explicit(&c->state,memory_order_acquire);
        if (state==MD_ENTRY_NATIVE && !native_sent) {
            if (atomic_load_explicit(&c->native.state,memory_order_acquire)==MD_NATIVE_READY) {
                /* Reenter libc's cancellation check before the effect, never
                 * after a successful open. Filtered callers cannot get a plan. */
                native_cancel_check(call);
                if (call->number==SYS_openat) c->native.args[1]=(uintptr_t)c->native_path;
                md_cooperative_native(&c->native);
            }
            native_sent=1;
            if (atomic_load_explicit(&c->native.state,memory_order_acquire)==MD_NATIVE_DONE) {
                long result=c->native.result;
                unsigned offered=MD_ENTRY_NATIVE;
                /* The kernel result is final. The worker still owns the table
                 * turn, journal and pin; a following request may queue in call,
                 * but cannot execute or reuse native until that owner retires. */
                if (atomic_compare_exchange_strong_explicit(&c->state,&offered,MD_ENTRY_RETIRING,
                        memory_order_seq_cst,memory_order_acquire)) {
                    if (!atomic_load_explicit(&c->awake,memory_order_seq_cst)) md_guest_buffer_admit(MD_ENTRY_WAKE);
                    outcome=MD_ENTRY_COMPLETED; call->result=result; break;
                }
            }
            atomic_thread_fence(memory_order_seq_cst);
            if (!atomic_load_explicit(&c->awake,memory_order_seq_cst)) md_guest_buffer_admit(MD_ENTRY_WAKE);
            continue;
        }
        if (state==MD_ENTRY_RESPONSE) {
            if (c->receipt!=c->sequence) break;
            outcome=c->outcome; call->result=c->result;
            if (outcome!=MD_ENTRY_DECLINED && outcome!=MD_ENTRY_COMPLETED) outcome=MD_ENTRY_UNKNOWN;
            if (descriptor && outcome!=MD_ENTRY_UNKNOWN) {
                outcome=MD_ENTRY_COMPLETED; call->result=descriptor_result;
            }
            atomic_store_explicit(&c->state,MD_ENTRY_IDLE,memory_order_release);
            break;
        }
        if (state==MD_ENTRY_CLOSED) break;
        if (!checks) {
            budget=md_spin_budget(&policy,25000);
            time=budget ? now() : 0; spin=time ? time+budget : 0;
        } else if (budget && (!(checks%32) || parked)) time=now();
        ++checks;
        if (time && time<spin) { spun=1; __asm__ volatile("yield" ::: "memory"); continue; }
        parked=1;
        atomic_store_explicit(&c->sleeping,1,memory_order_seq_cst);
        state=atomic_load_explicit(&c->state,memory_order_seq_cst);
        if (state==MD_ENTRY_REQUEST || state==MD_ENTRY_RUNNING || (state==MD_ENTRY_NATIVE && native_sent)) {
            /* EVENT_WAIT: exact response or owner closure. Launch teardown
             * terminates the task. Never abandon an accepted output pointer
             * while its worker can still write into the caller's stack. */
            RAW6(futex,&c->state,FUTEX_WAIT,state,0,0,0);
        }
        atomic_store_explicit(&c->sleeping,0,memory_order_seq_cst);
    }
    /* A response already ready after the notification wake is not evidence
     * that spinning helped. Nor is a response observed after descheduling. */
    if (budget && (spun || parked))
        md_spin_observed(&policy,!parked && outcome==MD_ENTRY_COMPLETED,now(),spin);
    c->feedback=policy;
    /* DECLINED is an explicit pre-execution transfer of ownership. Once the
     * worker accepts a call, UNKNOWN is terminal and must never enter here. */
    if (outcome==MD_ENTRY_DECLINED) {
        /* Repeated births cannot use a pinned existing object. Avoid probing
         * before every carrier call, but resample after a bounded number of
         * creating opens. Ordinary opens and all engine checks are unchanged. */
        if (create_probe) c->create_cooldown=128;
        goto kernel;
    }
done:
    __atomic_store_n(&client->opaque[MD_ENTRY_CLIENT_CONTROL],control,__ATOMIC_RELEASE);
    return outcome;
kernel:
    outcome=kernel_call(call);
    goto done;
}
const struct md_entry_api md_cooperative_entry={
    .version=MD_ENTRY_VERSION,.size=sizeof(struct md_entry_api),.try_syscall=invoke,
    .offers=offers,.syscall_count=sizeof(offers)
};

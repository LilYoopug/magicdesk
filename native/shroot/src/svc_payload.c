#include "svc_payload.h"

/* Relocation-free entry driver: no TLS, libc, stack protector,
 * SIMD or external helper calls. Only the supplied cooperative API is called.
 * Shared by the bootstrap and copied laboratory fixtures. The supervisor
 * revokes admission for the address space before an application filter commits,
 * so even gettid is skipped on the filtered fallback. */
__attribute__((section("md_svc_payload"),noinline))
int md_svc_payload_dispatch(uint64_t *r,struct md_svc_payload_state *s) {
    if (!__atomic_load_n(&s->admitted,__ATOMIC_ACQUIRE)) return 0;
    const struct md_entry_api *api=s->api;
    if (!md_entry_api_valid(api) || !md_entry_offered(api,(long)r[8],MD_ENTRY_ORDINARY)) return 0;
    long tid=api->thread_identity();
    struct md_entry_client *client=0;
    if (tid<=0) return 0;
    for (unsigned j=0;j<MD_SVC_PAYLOAD_CLIENTS;++j) {
        unsigned i=((unsigned long)tid+j)%MD_SVC_PAYLOAD_CLIENTS;
        uint64_t owner=__atomic_load_n(&s->clients[i].tid,__ATOMIC_ACQUIRE);
        if (!owner) {
            uint64_t empty=0;
            if (__atomic_compare_exchange_n(&s->clients[i].tid,&empty,(uint64_t)tid,0,
                    __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) owner=tid;
        }
        if (owner==(uint64_t)tid) { client=&s->clients[i].client; break; }
    }
    if (!client) return 0;
    struct md_entry_call call={.number=(int)r[8],.args={r[0],r[1],r[2],r[3],r[4],r[5]}};
    enum md_entry_outcome outcome=api->try_syscall(client,&call);
    for (;;) {
        md_entry_step_fn next=call.next;
        if (outcome==MD_ENTRY_COMPLETED) {
            r[0]=(uint64_t)call.result;
            if ((uint64_t)call.number==s->selected_number)
                __atomic_fetch_add(&s->selected_completed,1,__ATOMIC_RELAXED);
            __atomic_fetch_add(&s->completed,1,__ATOMIC_RELAXED); return 1;
        }
        if (outcome==MD_ENTRY_DECLINED || (outcome==MD_ENTRY_KERNEL_CALL && !next)) {
            __atomic_fetch_add(&s->declined,1,__ATOMIC_RELAXED); return 0;
        }
        if (outcome==MD_ENTRY_NATIVE_EFFECT && call.effect && next) call.effect(call.effect_context);
        else if (outcome==MD_ENTRY_KERNEL_CALL && call.kernel && next)
            call.result=call.kernel(call.number,call.args);
        else {
            __atomic_fetch_add(&s->unknown,1,__ATOMIC_RELAXED);
            /* Never replay an operation with an unknown committed effect. */
            __builtin_trap();
        }
        outcome=next(client,&call);
    }
}

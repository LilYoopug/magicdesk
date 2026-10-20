#ifndef MD_LAB_SVC_PAYLOAD_H
#define MD_LAB_SVC_PAYLOAD_H
#include "cooperative_entry.h"
#include "svc_borrowed.h"
#include "svc_edge.h"
#define MD_SVC_PAYLOAD_STATE (MD_SVC_POOL_BASE+MD_SVC_SLOT_COUNT*MD_SVC_SLOT_SIZE)
#define MD_SVC_PAYLOAD_SIZE 16384
#define MD_SVC_PAYLOAD_CLIENTS 128
#define MD_SVC_SIGNAL_MAGIC UINT64_C(0x4d44535643534947)
struct md_svc_signal_window {
    uint64_t magic;
    uintptr_t begin,end;
    struct md_svc_edge edge;
    uint32_t original,replacement;
    uintptr_t kernel_alias;
};
struct md_svc_payload_state {
    const struct md_entry_api *api;
    uint64_t completed,declined,unknown;
    uint64_t admitted,revoked;
    uint64_t selected_number,selected_completed;
    uint64_t retired_clients;
    struct { uint64_t tid; struct md_entry_client client; } clients[MD_SVC_PAYLOAD_CLIENTS];
    struct md_svc_signal_window window;
};
extern unsigned char __start_md_svc_payload[],__stop_md_svc_payload[];
int md_svc_payload_dispatch(uint64_t *registers,struct md_svc_payload_state *);
#endif

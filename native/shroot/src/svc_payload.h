#ifndef MD_SVC_PAYLOAD_H
#define MD_SVC_PAYLOAD_H
#include "cooperative_entry.h"
#include "svc_frame.h"
#define MD_SVC_PAYLOAD_SIZE 16384
#define MD_SVC_PAYLOAD_CLIENTS 128
struct md_svc_payload_state {
    const struct md_entry_api *api;
    uint64_t completed,declined,unknown;
    uint64_t admitted,revoked;
    uint64_t retired_clients;
    struct { uint64_t tid; struct md_entry_client client; } clients[MD_SVC_PAYLOAD_CLIENTS];
};
extern unsigned char __start_md_svc_payload[],__stop_md_svc_payload[];
int md_svc_payload_dispatch(uint64_t *registers,struct md_svc_payload_state *);
#endif

#ifndef MD_LAB_COOPERATIVE_CHANNEL_H
#define MD_LAB_COOPERATIVE_CHANNEL_H
#include <stdatomic.h>
#include <stdint.h>
#include <limits.h>
#include <sys/types.h>
#include "fs_operation.h"
#include "spin_policy.h"

/* Laboratory protocol, not a public libc ABI. It carries captured values, never
 * guest pointers, credentials or mount handles. The shared-files experiment
 * requires a kernel CLONE_FILES relationship, not a guessed numeric FD. */
enum md_cooperative_state { MD_COOPERATIVE_IDLE, MD_COOPERATIVE_REQUEST,
    MD_COOPERATIVE_RUNNING, MD_COOPERATIVE_DELEGATED, MD_COOPERATIVE_RESPONSE, MD_COOPERATIVE_RECEIPT, MD_COOPERATIVE_CLOSED };
enum md_cooperative_outcome { MD_COOPERATIVE_DECLINED, MD_COOPERATIVE_COMPLETED,
    MD_COOPERATIVE_UNKNOWN, MD_COOPERATIVE_PLAN };
struct md_cooperative_request {
    uint64_t sequence;
    int syscall;
    unsigned flags, mode;
    uint32_t length[2];
    char path[2][PATH_MAX];
};
struct md_cooperative_response {
    uint64_t sequence;
    enum md_cooperative_outcome outcome;
    int error;
    /* Separate tables transfer rights. A CLONE_FILES receipt transfers ownership
     * of the actual shared slot; a successful sender must not close it. */
    int fd;
    struct md_fs_info info;
    struct { int owner, pin; unsigned flags; uint64_t device, inode; } open_plan;
};
enum md_cooperative_completion_kind { MD_COOPERATIVE_OPENED, MD_COOPERATIVE_CLOSED_FD };
struct md_cooperative_completion {
    enum md_cooperative_completion_kind kind;
    uint64_t sequence;
    int fd, error;
};
struct md_cooperative_channel {
    _Alignas(64) atomic_uint state;
    unsigned spin_ns, selective_wake, adaptive_spin, shared_files, park_owner_handoff;
    unsigned receive_spin_ns, receive_spin_override;
    unsigned prepared_open;
    unsigned completion_queue;
    _Alignas(64) atomic_uint completion_write, completion_read, completion_waiting;
    struct md_cooperative_completion completions[64];
    _Alignas(64) atomic_uint sleeping[2];
    atomic_uint event[2];
    /* Each endpoint owns its own feedback. Peer notification reads only the
     * atomic sleeping flag; feedback is inspected after the endpoint exits. */
    struct md_spin_policy feedback[2];
    struct md_cooperative_request request;
    _Alignas(64) struct md_cooperative_response response;
};
struct md_cooperative_client {
    struct md_cooperative_channel *channel;
    pid_t tid;
    int delivery;
    uint64_t sequence;
    atomic_flag busy;
    struct md_cooperative_client *closer;
};
void md_cooperative_client_init(struct md_cooperative_client *,struct md_cooperative_channel *,int delivery);
/* Input is an already captured packet. Invalid application pointers and libc
 * cancellation must be handled by a future adapter before publication. */
struct md_cooperative_response md_cooperative_call(struct md_cooperative_client *,
    const struct md_cooperative_request *);
/* Fixed-actor plan experiment: complete the previous result's publication
 * before a later tracked operation can observe or reuse its descriptor. */
int md_cooperative_sync(struct md_cooperative_client *);
int md_cooperative_receipt_complete(struct md_cooperative_channel *);
int md_cooperative_completion_peek(struct md_cooperative_channel *,struct md_cooperative_completion *);
void md_cooperative_completion_consume(struct md_cooperative_channel *);
/* The owner must release any retained read scope before it parks. */
int md_cooperative_receive(struct md_cooperative_channel *,struct md_cooperative_request *,
        void (*before_wait)(void *),void *);
/* A downstream actor should park while its executor awaits another owner. */
int md_cooperative_delegate(struct md_cooperative_channel *);
/* Private worker handoff: completion goes to the original guest channel, not
 * back to the producer. One producer, one consumer, one outstanding job. */
int md_cooperative_post(struct md_cooperative_channel *,const struct md_cooperative_request *);
int md_cooperative_retire(struct md_cooperative_channel *);
/* Maintenance does not change request state; advance the endpoint event even
 * before it registers as sleeping, so its before-wait drain cannot miss work. */
void md_cooperative_notify_owner(struct md_cooperative_channel *);
/* Separate tables: borrows fd, caller closes its copy. Shared table: successful
 * publication transfers the slot even if the subsequent wake fails. */
int md_cooperative_reply(struct md_cooperative_channel *,const struct md_cooperative_response *,int delivery,int *published);
void md_cooperative_close(struct md_cooperative_channel *);
#endif

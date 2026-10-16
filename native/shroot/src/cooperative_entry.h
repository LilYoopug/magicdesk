#ifndef MD_COOPERATIVE_ENTRY_H
#define MD_COOPERATIVE_ENTRY_H
#include <stdint.h>

/* Private auxv contract, independent of the libc ABI. The caller retains its
 * original SVC instruction, including clone/signal-return stack semantics. */
#define MD_AT_COOPERATIVE 0x4d440001UL
#define MD_ENTRY_VERSION 4
enum md_entry_outcome { MD_ENTRY_DECLINED, MD_ENTRY_COMPLETED, MD_ENTRY_UNKNOWN };
typedef long (*md_entry_kernel_fn)(long,const uint64_t *);
struct md_entry_call {
    uint64_t args[6];
    int64_t result;
    int32_t number;
    uint32_t reserved;
    /* Optional caller-owned SVC continuation. A libc uses the same site with
     * entry enabled or disabled, preserving instruction-pointer filter policy.
     * With no installed filter, a native open plan can also invoke this with
     * a harmless futex wake to enter libc's pre-effect cancellation check. */
    md_entry_kernel_fn kernel;
};
/* Fixed caller storage, not the transport's state layout. Zero once per thread
 * and after fork; never inspect/copy an active handle or share it across threads.
 * Reentry/inherited handles decline before publication. UNKNOWN forbids replay. */
struct md_entry_client {
    uintptr_t opaque[3];
};
enum { MD_ENTRY_ORDINARY = 1, MD_ENTRY_CANCELLATION = 2 };
struct md_entry_api {
    uint32_t version, size;
    enum md_entry_outcome (*try_syscall)(struct md_entry_client *, struct md_entry_call *);
    /* Immutable for this process image; flags describe caller integration, not
     * engine routes or authority. Unlisted calls retain their original SVC. */
    const unsigned char *offers;
    uint32_t syscall_count, reserved;
};
static inline int md_entry_api_valid(const struct md_entry_api *api) {
    return api && api->version==MD_ENTRY_VERSION && api->size>=sizeof(*api)
        && api->try_syscall && api->offers && !api->reserved;
}
static inline int md_entry_offered(const struct md_entry_api *api,long number,unsigned kind) {
    return api && (unsigned long)number<api->syscall_count && (api->offers[number]&kind);
}
extern const struct md_entry_api md_cooperative_entry;
#endif

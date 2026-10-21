#ifndef MD_SIGNAL_PROTOCOL_H
#define MD_SIGNAL_PROTOCOL_H
#include <signal.h>
#include <stdint.h>

static inline uint64_t md_signal_blockable_mask(void) {
    return UINT64_MAX & ~(UINT64_C(1)<<(SIGKILL-1)) & ~(UINT64_C(1)<<(SIGSTOP-1));
}

/* Service checkpoints are ptrace events, not forced application signals. */
static inline uint64_t md_signal_protocol_mask(void) {
    return md_signal_blockable_mask();
}
#endif

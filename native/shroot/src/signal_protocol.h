#ifndef MD_SIGNAL_PROTOCOL_H
#define MD_SIGNAL_PROTOCOL_H
#include <signal.h>
#include <stdint.h>

/* Internal BRK returns must reach ptrace unblocked. Linux resets a blocked
 * synchronous signal's disposition before reporting the stop, which can also
 * affect other threads sharing sighand. Restore the caller's mask afterwards. */
static inline uint64_t md_signal_protocol_mask(void) {
    return UINT64_MAX & ~(UINT64_C(1)<<(SIGKILL-1))
        & ~(UINT64_C(1)<<(SIGSTOP-1)) & ~(UINT64_C(1)<<(SIGTRAP-1));
}
#endif

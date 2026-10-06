#ifndef MD_TASK_SEND_H
#define MD_TASK_SEND_H
#include <stdint.h>

enum { MD_TASK_SEND_INPUTS=254 };
/* Socket and application rights remain at their captured numbers in the
 * helper's private table. Only token_slot is patched with a private FD. */
struct md_task_send {
    uintptr_t message, token_slot;
    int socket, flags;
    unsigned count;
    int keep[MD_TASK_SEND_INPUTS];
};
#endif

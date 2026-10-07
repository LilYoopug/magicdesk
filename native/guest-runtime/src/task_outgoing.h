#ifndef MD_TASK_OUTGOING_H
#define MD_TASK_OUTGOING_H
#include "task_send.h"
#include "task_receive.h"
#include "ipc_outgoing.h"

/* Export owns scratch until reaping; import reuses it only afterwards. Final
 * headers/address live outside scratch. The retained socket, not its caller
 * slot, supplies final IO; its number is preserved for application filters. */
struct md_task_outgoing_frame {
    union {
        struct md_task_receive_frame capture;
        struct md_task_send_import import;
    } scratch;
    struct md_task_send input;
    struct msghdr message;
    struct md_ipc_send_options options;
    struct md_ipc_send_address destination;
    unsigned rights, transport;
};
#endif

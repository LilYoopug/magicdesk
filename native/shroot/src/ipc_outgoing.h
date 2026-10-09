#ifndef MD_IPC_OUTGOING_H
#define MD_IPC_OUTGOING_H
#include <sys/socket.h>

/* Copied at admission; binary abstract names retain their exact length. */
struct md_ipc_send_options {
    struct sockaddr_storage address;
    socklen_t length;
    unsigned addressed, credentials, brokered;
    struct ucred claimed;
};
/* The optional pathname anchor is custody, never an application right. */
struct md_ipc_send_address {
    struct sockaddr_storage address;
    socklen_t length;
    int anchor;
    unsigned credentials, brokered;
};
#endif

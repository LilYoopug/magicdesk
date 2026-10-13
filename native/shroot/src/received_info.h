#ifndef MD_RECEIVED_INFO_H
#define MD_RECEIVED_INFO_H
#include <sys/socket.h>

enum { MD_RECEIVED_CREDENTIALS=1 };
/* Indices address the selected custody, not caller FD numbers. Each input
 * right maps to [first[i], first[i+1]) output entries. Credentials index the
 * original sender PIDFD; it is published only for an actual SCM_PIDFD header.
 * A framed message can expand to 253 data rights plus one identity token. */
struct md_received_info { int index; unsigned flags, selectors; struct ucred credentials; };
struct md_received_message {
    unsigned count, first[254];
    struct md_received_info entries[254];
};

#endif

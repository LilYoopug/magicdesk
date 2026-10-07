#ifndef MD_RECEIVED_INFO_H
#define MD_RECEIVED_INFO_H
#include <sys/socket.h>

enum { MD_RECEIVED_CREDENTIALS=1, MD_RECEIVED_WATCH=2 };
/* Indices address the selected custody, not caller FD numbers. Each input
 * right maps to [first[i], first[i+1]) output entries. Credentials have no FD.
 * A framed message can expand to 253 data rights plus one identity token. */
struct md_received_info { int index; unsigned flags; struct ucred credentials; };
struct md_received_message {
    unsigned count, first[254];
    struct md_received_info entries[254];
};

#endif

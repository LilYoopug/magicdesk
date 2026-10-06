#ifndef MD_RECEIVED_INFO_H
#define MD_RECEIVED_INFO_H
#include <sys/socket.h>

enum { MD_RECEIVED_CREDENTIALS=1, MD_RECEIVED_WATCH=2 };
/* Source indices refer to retained kernel descriptions, not application slots.
 * Classification is not proof of a descriptor's originating mount view. */
struct md_received_info { unsigned flags; struct ucred credentials; };

#endif

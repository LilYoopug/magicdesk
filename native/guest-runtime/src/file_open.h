#ifndef MD_FILE_OPEN_H
#define MD_FILE_OPEN_H
#include <fcntl.h>

/* A deferred pin is an authorized O_PATH descriptor, not a data endpoint.
 * FIFO rendezvous and terminal acquisition finish outside the filesystem
 * worker; MD_OPEN_CALLER preserves the opening task's session semantics. */
enum md_open_kind { MD_OPEN_READY, MD_OPEN_FIFO, MD_OPEN_PIPE, MD_OPEN_CALLER };
struct md_open_completion {
    enum md_open_kind kind;
    /* Owned only for MD_OPEN_PIPE; a regular-file rendezvous mapping. */
    int control;
};
int md_complete_open(int, int, struct md_open_completion);
/* Reopen one retained native object; FIFO completion remains deferred. */
int md_reopen_file(int fd, int flags, struct md_open_completion *);
static inline int md_open_endpoint_flags(int flags) {
    return flags & ~(O_CREAT | O_EXCL | O_NOFOLLOW);
}
#endif

#include "fd_selector.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
enum { BYTES = (MD_FD_SELECTOR_MASK + 1) / 8 };
struct md_fd_selector { unsigned references, all; unsigned char *bits[MD_FD_SELECTOR_KINDS]; };
struct md_fd_selector *md_fd_selector_new(void) {
    struct md_fd_selector *a = calloc(1, sizeof(*a));
    if (a) a->references = 1;
    return a;
}
struct md_fd_selector *md_fd_selector_fork(struct md_fd_selector *a, int shared) {
    if (shared) { a->references++; return a; }
    struct md_fd_selector *copy = md_fd_selector_new();
    if (copy) copy->all=a->all;
    for (unsigned i=0;copy && i<MD_FD_SELECTOR_KINDS;++i) if (a->bits[i]) {
        copy->bits[i] = malloc(BYTES);
        if (!copy->bits[i]) { md_fd_selector_release(copy); return NULL; }
        memcpy(copy->bits[i], a->bits[i], BYTES);
    }
    return copy;
}
void md_fd_selector_release(struct md_fd_selector *a) {
    if (!a || --a->references) return;
    for (unsigned i=0;i<MD_FD_SELECTOR_KINDS;++i) free(a->bits[i]);
    free(a);
}
int md_fd_selector_has(struct md_fd_selector *a, unsigned kind, int fd) {
    if (!a || kind>=MD_FD_SELECTOR_KINDS || fd< -1) return -EINVAL;
    if (kind==MD_FD_SELECTOR_POLL) fd=-1;
    if (a->all&(1U<<kind)) return 1;
    if (fd==-1) return 0;
    fd &= MD_FD_SELECTOR_MASK;
    /* Allocate before installing an irreversible kernel filter. */
    if (!a->bits[kind] && !(a->bits[kind] = calloc(1, BYTES))) return -ENOMEM;
    return !!(a->bits[kind][fd / 8] & (1U << (fd % 8)));
}
int md_fd_selector_mark(struct md_fd_selector *a, unsigned kind, int fd) {
    if (!a || kind>=MD_FD_SELECTOR_KINDS || fd< -1) return -EINVAL;
    if (kind==MD_FD_SELECTOR_POLL) fd=-1;
    if (fd==-1) {
        a->all|=1U<<kind;
        if (kind==MD_FD_SELECTOR_PROC) a->all|=1U<<MD_FD_SELECTOR_WATCH;
        return 0;
    }
    fd &= MD_FD_SELECTOR_MASK;
    if (!a->bits[kind]) return -EINVAL;
    a->bits[kind][fd / 8] |= (1U << (fd % 8)); return 0;
}

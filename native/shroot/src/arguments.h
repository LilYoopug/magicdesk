#ifndef MD_ARGUMENTS_H
#define MD_ARGUMENTS_H
#include <stddef.h>

/* Linux/aarch64 exec's ceiling (3/4 of _STK_LIM), not an ARG_MAX promise.
 * The kernel still enforces RLIMIT_STACK, environment and individual strings. */
#define MD_EXEC_BYTES (6U * 1024 * 1024)
#define MD_EXEC_POINTERS (MD_EXEC_BYTES / sizeof(char *))
struct md_arguments {
    char **values;
    size_t count, capacity;
    char *local[64];
};
void md_arguments_init(struct md_arguments *);
int md_arguments_reserve(struct md_arguments *, size_t);
/* Reads a caller-owned NULL-terminated vector without dereferencing it. */
int md_arguments_read(struct md_arguments *, char *const *);
void md_arguments_close(struct md_arguments *);
#endif

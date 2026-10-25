#define _GNU_SOURCE
#include "raw.h"
#include <errno.h>

size_t md_page_size;
size_t md_length(const char *s) { size_t n = 0; while (s[n]) ++n; return n; }
int md_equal(const char *a, const char *b) {
    size_t i = 0; while (a[i] && a[i] == b[i]) ++i;
    return a[i] == b[i];
}
int md_prefix(const char *a, const char *b) {
    size_t i = 0; while (b[i] && a[i] == b[i]) ++i;
    return !b[i];
}
int md_copy(char *out, size_t size, const char *in) {
    size_t n = md_length(in);
    if (n >= size) return -ENAMETOOLONG;
    memcpy(out, in, n + 1);
    return 0;
}
int md_append(char *out, size_t size, const char *in) {
    size_t n = md_length(out);
    return md_copy(out + n, size - n, in);
}
void md_decimal(char *out, unsigned long value) {
    char digits[32]; size_t n = 0;
    do { digits[n++] = (char)('0' + value % 10); value /= 10; } while (value);
    size_t i = 0; while (n) out[i++] = digits[--n];
    out[i] = 0;
}
void md_error(const char *reason, long error) {
    char code[32]; md_decimal(code, (unsigned long)(error < 0 ? -error : error));
    RAW3(write, 2, "md-bootstrap: ", 14);
    RAW3(write, 2, reason, md_length(reason));
    RAW3(write, 2, " errno=", 7);
    RAW3(write, 2, code, md_length(code));
    RAW3(write, 2, "\n", 1);
}
void md_die(const char *reason, long error) {
    md_error(reason, error);
    RAW1(exit_group, error == -ENOENT ? 127 : 126);
    __builtin_unreachable();
}
/* Versioned syscall structures accept only zero-filled unknown tail fields. */
long md_read_struct(void *out, size_t known, const void *in, size_t supplied) {
    if (supplied>md_page_size) return -E2BIG;
    if (supplied<known) return -EINVAL;
    uintptr_t address=(uintptr_t)in;
    if (address>UINTPTR_MAX-supplied) return -EFAULT;
    long r=md_read_memory(out,in,known);
    if (r<0) return r;
    for (size_t i=known;i<supplied;) {
        unsigned char tail[64];
        size_t n=supplied-i;
        if (n>sizeof(tail)) n=sizeof(tail);
        r=md_read_memory(tail,(const void *)(address+i),n);
        if (r<0) return r;
        for (size_t j=0;j<n;++j) if (tail[j]) return -E2BIG;
        i+=n;
    }
    return 0;
}

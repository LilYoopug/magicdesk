#ifndef MD_SYSCTL_VALUE_H
#define MD_SYSCTL_VALUE_H
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

/* Scalar proc controls accept one nonnegative decimal with optional whitespace. */
static inline int md_sysctl_parse_uint(const void *data,size_t size,uint32_t *out) {
    if (size>128) return -E2BIG;
    if (!size) return -EINVAL;
    const unsigned char *p=data,*end=p+size;
    while (p<end && isspace(*p)) ++p;
    if (p==end || !isdigit(*p)) return -EINVAL;
    uint32_t value=0;
    do {
        unsigned digit=*p++-'0';
        if (value>((unsigned)INT_MAX-digit)/10) return -EINVAL;
        value=value*10+digit;
    } while (p<end && isdigit(*p));
    while (p<end && isspace(*p)) ++p;
    if (p!=end) return -EINVAL;
    *out=value; return 0;
}
#endif

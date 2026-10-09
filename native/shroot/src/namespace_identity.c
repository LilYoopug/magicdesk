#include "namespace_identity.h"
#include <errno.h>
#include <sys/random.h>

int md_namespace_identity_new(uint64_t *out) {
    uint64_t value;
    for (;;) {
        ssize_t count=getrandom(&value,sizeof(value),0);
        if (count<0) { if (errno==EINTR) continue; return -errno; }
        if (count!=sizeof(value)) return -EIO;
        value&=UINT64_MAX>>1;
        if (value>1) { *out=value; return 0; }
    }
}

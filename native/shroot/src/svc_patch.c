#include "svc_patch.h"
#include <errno.h>

int md_svc_branch(uintptr_t from,uintptr_t to,uint32_t *out) {
    if (!out || ((from|to)&3)) return -EINVAL;
    uint64_t distance=from>to ? from-to : to-from;
    if (distance>(UINT64_C(1)<<27)-(to>=from ? 4 : 0)) return -ERANGE;
    int64_t words=to>=from ? (int64_t)(distance/4) : -(int64_t)(distance/4);
    *out=UINT32_C(0x14000000)|((uint32_t)words&UINT32_C(0x03ffffff));
    return 0;
}

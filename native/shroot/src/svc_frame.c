#include "svc_frame.h"
#include <errno.h>
#include <string.h>
extern const unsigned char md_svc_single_begin[],md_svc_single_end[];
size_t md_svc_single_size(void) { return (size_t)(md_svc_single_end-md_svc_single_begin); }
/* Only our untouched templates are relocated here, before inserting guest
 * instructions or literals. Every MOVK belongs to a frame-base construction. */
int md_svc_frame_relocate(unsigned char *code,size_t size,uintptr_t frames) {
    if (!frames || (frames&(MD_SVC_POOL_SIZE-1)) || frames>UINTPTR_MAX-MD_SVC_POOL_SIZE-65536)
        return -EINVAL;
    unsigned pieces[3]={0};
    for (size_t at=0;at+4<=size;at+=4) {
        uint32_t word; memcpy(&word,code+at,4);
        if ((word&UINT32_C(0xff800000))!=UINT32_C(0xf2800000)) continue;
        unsigned half=(word>>21)&3;
        if (!half) return -EINVAL;
        word=(word&~UINT32_C(0x001fffe0))|(((frames>>(half*16))&65535)<<5);
        memcpy(code+at,&word,4); ++pieces[half-1];
    }
    return pieces[0] && pieces[0]==pieces[1] && pieces[1]==pieces[2] ? 0 : -EINVAL;
}

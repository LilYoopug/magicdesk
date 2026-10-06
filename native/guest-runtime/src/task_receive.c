#define _GNU_SOURCE
#include "task_receive.h"
#include <errno.h>
#include <limits.h>

long md_task_receive_collect(struct md_task_receive_frame *frame) {
    frame->count=0;
    if (!frame->total) {
        frame->descriptors[frame->count++]=frame->input.socket;
        frame->total=1;
    }
    while (frame->cursor<frame->input.count && frame->count<253) {
        struct msghdr *m;
        if (frame->input.batch) {
            struct mmsghdr *batch=(void *)frame->input.messages;
            if (batch[frame->cursor].msg_len==UINT_MAX) break;
            m=&batch[frame->cursor].msg_hdr;
        } else {
            if (frame->result<0) break;
            m=(void *)frame->input.messages;
        }
        unsigned visited=0;
        for (size_t offset=0; m->msg_control && m->msg_controllen-offset>=sizeof(struct cmsghdr);) {
            struct cmsghdr *h=(void *)((char *)m->msg_control+offset);
            if (h->cmsg_len<CMSG_LEN(0) || h->cmsg_len>m->msg_controllen-offset) return -EPROTO;
            if (h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_RIGHTS) {
                size_t n=(h->cmsg_len-CMSG_LEN(0))/sizeof(int);
                if (n>253-visited) return -EPROTO;
                int *fds=(void *)CMSG_DATA(h);
                for (unsigned i=0;i<n;++i,++visited) {
                    if (visited<frame->offset) continue;
                    if (frame->count==253) return 1;
                    frame->descriptors[frame->count++]=fds[i];
                    fds[i]=(int)frame->total++;
                    ++frame->offset;
                }
            }
            size_t step=CMSG_ALIGN(h->cmsg_len);
            if (step>m->msg_controllen-offset) break;
            offset+=step;
        }
        ++frame->cursor; frame->offset=0;
    }
    return frame->count ? 1 : 0;
}

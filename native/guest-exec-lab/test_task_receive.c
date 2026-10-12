#define _GNU_SOURCE
#include "task_receive.h"
#include "socket_control.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

union control { struct cmsghdr align; char bytes[2*CMSG_SPACE(253*sizeof(int))+CMSG_SPACE(sizeof(struct ucred))]; };

static unsigned rights(struct msghdr *message, size_t offset, unsigned count, unsigned first) {
    struct cmsghdr *h=(void *)((char *)message->msg_control+offset);
    *h=(struct cmsghdr){.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_RIGHTS,.cmsg_len=CMSG_LEN(count*sizeof(int))};
    int *fds=(void *)CMSG_DATA(h);
    for (unsigned i=0;i<count;++i) fds[i]=(int)(first+i);
    return CMSG_SPACE(count*sizeof(int));
}
static void vectors(unsigned messages_count, unsigned rights_count, unsigned completed, int split, int *budget) {
    struct mmsghdr *messages=calloc(messages_count,sizeof(*messages));
    union control *controls=calloc(messages_count,sizeof(*controls));
    assert(messages && controls);
    unsigned total=0;
    for (unsigned i=0;i<messages_count;++i) {
        struct msghdr *m=&messages[i].msg_hdr;
        m->msg_control=&controls[i];
        if (split) {
            m->msg_controllen=rights(m,0,rights_count/2,2000+total);
            struct cmsghdr *h=(void *)(controls[i].bytes+m->msg_controllen);
            *h=(struct cmsghdr){.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_CREDENTIALS,.cmsg_len=CMSG_LEN(sizeof(struct ucred))};
            m->msg_controllen+=CMSG_SPACE(sizeof(struct ucred));
            m->msg_controllen+=rights(m,m->msg_controllen,rights_count-rights_count/2,2000+total+rights_count/2);
        } else m->msg_controllen=rights(m,0,rights_count,2000+total);
        if (rights_count==254) {
            struct cmsghdr *h=(void *)controls[i].bytes;
            h->cmsg_len=CMSG_LEN(253*sizeof(int));
            m->msg_controllen=CMSG_SPACE(253*sizeof(int));
            h=(void *)(controls[i].bytes+m->msg_controllen);
            *h=(struct cmsghdr){.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_PIDFD,.cmsg_len=CMSG_LEN(sizeof(int))};
            int fd=2000+total+253; memcpy(CMSG_DATA(h),&fd,sizeof(fd));
            m->msg_controllen+=CMSG_SPACE(sizeof(fd));
        }
        total+=rights_count;
        messages[i].msg_len=i<completed ? 1 : UINT_MAX;
    }
    struct md_task_receive_frame frame={.input={.messages=(uintptr_t)messages,.count=messages_count,.batch=1,.socket=123}};
    unsigned exported=0, parcels=0;
    *budget=0;
    for (;;) {
        long r=md_task_receive_collect(&frame);
        assert(r==0 || r==1);
        if (!r) break;
        ++parcels;
        assert(frame.count && frame.count<=253);
        for (unsigned i=0;i<frame.count;++i,++exported)
            assert(frame.descriptors[i]==(exported ? (int)(1999+exported) : 123));
    }
    assert(!md_task_receive_collect(&frame) && !frame.count);
    *budget=-1;
    unsigned expected=1+completed*rights_count;
    assert(exported==expected && frame.total==expected && parcels==(expected+252)/253);
    unsigned index=1;
    for (unsigned i=0;i<messages_count;++i) {
        struct msghdr *m=&messages[i].msg_hdr;
        for (struct cmsghdr *h=CMSG_FIRSTHDR(m);h;h=CMSG_NXTHDR(m,h)) {
            unsigned count=md_socket_control_fds(h);
            int *fds=(void *)CMSG_DATA(h);
            for (unsigned j=0;j<count;++j,++index) assert(fds[j]==(i<completed ? (int)index : (int)(1999+index)));
        }
    }
    free(controls); free(messages);
    printf("PASS receive vectors messages=%u rights=%u completed=%u split=%d parcels=%u allocations=0\n",
        messages_count,rights_count,completed,split,parcels);
}
void test_task_receive(int *budget) {
    const unsigned counts[]={0,1,2,252,253};
    for (unsigned i=0;i<sizeof(counts)/sizeof(*counts);++i) {
        vectors(1,counts[i],1,0,budget);
        vectors(4,counts[i],4,1,budget);
        vectors(4,counts[i],2,1,budget);
        vectors(4,counts[i],0,0,budget);
    }
    vectors(1024,2,1024,0,budget);
    vectors(1024,253,1024,1,budget);
    vectors(1,254,1,0,budget);
    vectors(4,254,4,0,budget);
    vectors(4,254,2,0,budget);
    union control control={0};
    control.align=(struct cmsghdr){.cmsg_level=SOL_SOCKET,.cmsg_type=SCM_PIDFD,.cmsg_len=CMSG_LEN(sizeof(int))};
    int error=-EMFILE; memcpy(CMSG_DATA(&control.align),&error,sizeof(error));
    assert(!md_socket_control_fds(&control.align));
}

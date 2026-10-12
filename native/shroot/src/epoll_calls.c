#include "epoll_calls.h"
#include "adapter_buffer.h"
#include "fs_buffer.h"
#include "raw.h"
#include "descriptor_capture.h"
#include <errno.h>
#include <limits.h>

long md_epoll_call(long nr,const unsigned long *a) {
    long memory=md_adapter_buffer_take();
    if (memory<0) return memory;
    struct md_epoll_frame *f=(void *)memory;
    memset(f,0,sizeof(*f));
    long result=0;
    if (nr==SYS_epoll_ctl) {
        if ((int)a[1]!=EPOLL_CTL_DEL) result=md_read_memory(&f->event,(void *)a[3],sizeof(f->event));
    } else {
        if ((int)a[2]<=0 || a[2]>INT_MAX/sizeof(struct epoll_event)) result=-EINVAL;
        f->capacity=a[2]>MD_EPOLL_EVENTS ? MD_EPOLL_EVENTS : (int)a[2];
        if (nr==SYS_epoll_pwait2 && a[3]) {
            result=md_read_memory(&f->timeout,(void *)a[3],sizeof(f->timeout));
            f->timed=1;
            if (!result && (f->timeout.tv_sec<0 || f->timeout.tv_nsec<0 || f->timeout.tv_nsec>=1000000000)) result=-EINVAL;
        } else if (nr==SYS_epoll_pwait && (int)a[3]>=0) {
            f->timed=1; f->timeout=(struct timespec){(int)a[3]/1000,((int)a[3]%1000)*1000000L};
        }
        if (!result && a[4]) {
            if (a[5]!=sizeof(f->mask)) result=-EINVAL;
            else result=md_read_memory(&f->mask,(void *)a[4],sizeof(f->mask));
            f->masked=1;
        }
    }
    if (!result) result=md_guest_buffer_control(MD_BUFFER_EPOLL_BEGIN,0,0);
    if (result>0 && result!=MD_EPOLL_NATIVE && result!=MD_EPOLL_CAPTURED) {
        int fd=(int)a[0];
        static const struct md_descriptor_capture_protocol p={MD_FS_BUFFER_EPOLL_ADMIT,MD_BUFFER_EPOLL_CAPTURE_READY,
            MD_BUFFER_EPOLL_CAPTURE_SENT,MD_BUFFER_EPOLL_CAPTURE_OBSERVED,MD_EPOLL_CAPTURED};
        result=md_descriptor_capture_inputs(result,&f->capture,&fd,1,&p);
    }
    if (result==MD_EPOLL_CAPTURED) result=md_guest_buffer_control(MD_BUFFER_EPOLL_WAIT,0,0);
    if (result>0 && result!=MD_EPOLL_NATIVE && nr!=SYS_epoll_ctl) {
        if (result>f->capacity) result=-EPROTO;
        else if (md_write_memory((void *)a[1],f->events,(size_t)result*sizeof(*f->events))) result=-EFAULT;
    }
    long released=md_adapter_buffer_release();
    if (result==MD_EPOLL_NATIVE) return md_raw(nr,a[0],a[1],a[2],a[3],a[4],a[5]);
    return result ? result : released;
}

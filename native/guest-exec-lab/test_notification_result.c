#include "notification_result.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static int listener=-1, install_error, expired, sends, installs, released;
int __real_ioctl(int,unsigned long,...);
int __wrap_ioctl(int fd,unsigned long request,...) {
    va_list args; va_start(args,request);
    void *argument=va_arg(args,void *); va_end(args);
    if (fd!=listener) return __real_ioctl(fd,request,argument);
    if (request==SECCOMP_IOCTL_NOTIF_ID_VALID) {
        errno=ENOENT; return expired ? -1 : 0;
    }
    if (request==SECCOMP_IOCTL_NOTIF_ADDFD) {
        ++installs;
        struct seccomp_notif_addfd *add=argument;
        assert(add->flags==SECCOMP_ADDFD_FLAG_SEND);
        errno=install_error; return install_error ? -1 : 42;
    }
    assert(request==SECCOMP_IOCTL_NOTIF_SEND);
    ++sends; errno=ENOENT; return expired ? -1 : 0;
}
static void release(struct md_fd_object *object) { (void)object; ++released; }
void md_test_notification_result(void) {
    struct md_fd_origins *files=md_fd_origins_new(); assert(files);
    struct md_fd_object origin;
    const struct md_fd_object_type type={.destroy=release};
    md_fd_object_init(&origin,&type);
    int source=open("/dev/null",O_RDONLY|O_CLOEXEC); assert(source>=0);
    listener=dup(source); assert(listener>=0);
    struct seccomp_data call={.nr=SYS_openat,.instruction_pointer=0x1000,.args={1,2,3,4,5,6}};
    struct md_notification_result result={0};
    assert(!md_notification_result_fd(&result,&call,files,source,&origin,O_CLOEXEC));
    assert(md_notification_result_matches(&result,&call));
    for (unsigned i=0;i<6;++i) {
        call.args[i]^=1; assert(!md_notification_result_matches(&result,&call)); call.args[i]^=1;
    }
    install_error=ESRCH; expired=1;
    assert(md_notification_result_offer(&result,listener,1,NULL)==MD_NOTIFICATION_CANCELLED);
    assert(!result.delivered && result.source==source && !sends);
    install_error=0; expired=0;
    assert(md_notification_result_offer(&result,listener,2,NULL)==MD_NOTIFICATION_DELIVERED);
    assert(result.value==42 && installs==2 && !sends);
    struct md_fd_object *published=md_fd_origins_object(files,42,NULL);
    assert(published==&origin); md_fd_object_release(published);
    assert(!md_notification_result_clear(&result));
    assert(!md_fd_origins_close_range(files,42,42,0));

    assert(!md_notification_result_fd(&result,&call,files,source,&origin,0));
    install_error=EMFILE;
    assert(md_notification_result_offer(&result,listener,3,NULL)==MD_NOTIFICATION_STATUS);
    assert(result.value==-EMFILE && !sends && installs==3);
    expired=1;
    assert(md_notification_result_reply(&result)==MD_NOTIFICATION_CANCELLED);
    expired=0;
    assert(md_notification_result_offer(&result,listener,4,NULL)==MD_NOTIFICATION_STATUS);
    assert(installs==3);
    assert(md_notification_result_reply(&result)==MD_NOTIFICATION_DELIVERED && result.value==-EMFILE);
    assert(!md_notification_result_clear(&result));

    struct md_fd_order busy={0};
    assert(md_fd_order_begin(files,&busy,NULL)==1 && !md_fd_order_start(&busy));
    assert(!md_notification_result_fd(&result,&call,files,source,&origin,0));
    install_error=0;
    assert(md_notification_result_offer(&result,listener,5,NULL)==MD_NOTIFICATION_WAIT);
    expired=1;
    assert(md_notification_result_progress(&result)==MD_NOTIFICATION_CANCELLED);
    expired=0;
    assert(md_notification_result_offer(&result,listener,6,NULL)==MD_NOTIFICATION_WAIT);
    assert(!md_notification_result_clear(&result) && !md_fd_order_complete(&busy));
    assert(installs==3 && sends==2 && !released && fcntl(source,F_GETFD)>=0);
    md_fd_object_release(&origin); assert(released==1);
    md_fd_origins_release(files);
    assert(!close(listener) && !close(source)); listener=-1;
    puts("PASS notification result: queued ESRCH cancellation, retained FD, explicit scalar reply, retry and ownership");
}

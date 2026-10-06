#include "fd_install.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <sys/ioctl.h>

int md_fd_install_begin(struct md_fd_install *p, struct md_fd_origins *files,
        int listener, uint64_t notification, int source, struct md_fs_anchor *origin,
        unsigned flags, struct md_resource_wakeup *wakeup) {
    if (!p || p->files.table || !files || listener<0 || source<0 || flags&~O_CLOEXEC) return -EINVAL;
    *p=(struct md_fd_install){.listener=listener,.notification=notification,
        .source=source,.origin=origin,.flags=flags};
    int result=md_fd_order_begin(files,&p->files,wakeup);
    return result<0 ? result : 0;
}
int md_fd_install_progress(struct md_fd_install *p) {
    if (!p || !p->files.table) return -EINVAL;
    if (md_fd_order_state(&p->files)!=MD_RESOURCE_ORDER_READY) return MD_FD_INSTALL_WAIT;
    int result=md_fd_order_start(&p->files);
    if (result) return result;
    struct md_fd_origin_update update={0};
    result=md_fd_origins_prepare(p->files.table,p->origin,p->flags&O_CLOEXEC ? FD_CLOEXEC : 0,&update);
    if (!result) {
        struct seccomp_notif_addfd add={.id=p->notification,.flags=SECCOMP_ADDFD_FLAG_SEND,
            .srcfd=p->source,.newfd_flags=p->flags};
        result=ioctl(p->listener,SECCOMP_IOCTL_NOTIF_ADDFD,&add);
        if (result<0) result=-errno;
    }
    md_fd_origins_finish(&update,result);
    p->retire_error=md_fd_order_complete(&p->files);
    return result;
}
int md_fd_install_cancel(struct md_fd_install *p) {
    if (!p) return -EINVAL;
    if (!p->files.table) return 0;
    int result=md_fd_order_cancel(&p->files);
    return result==1 ? md_fd_order_complete(&p->files) : result;
}

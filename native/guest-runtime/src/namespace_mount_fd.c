#include "namespace_internal.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <sys/syscall.h>

long md_namespace_mount_fd(const struct md_fs *fs,long nr,const unsigned long *a) {
    struct md_fs_request q={.directory={-1,-1}};
    char key[PATH_MAX],value[PATH_MAX];
    long r=0;
    if (nr==SYS_move_mount) {
        unsigned flags=(unsigned)a[4];
        if (flags&~MOVE_MOUNT__MASK) return -EINVAL;
        q.operation=MD_FS_MOUNT; q.mode=MD_FS_MOUNT_MOVE_FD; q.flags=flags;
        q.directory[0]=(int)a[2]; q.directory[1]=(int)a[0];
        r=md_read_string(key,sizeof(key),(const char *)a[3]);
        if (r>=0) r=md_read_string(value,sizeof(value),(const char *)a[1]);
        if (r<0) return r;
        if ((!*key && !(flags&MOVE_MOUNT_T_EMPTY_PATH)) || (!*value && !(flags&MOVE_MOUNT_F_EMPTY_PATH))) return -ENOENT;
        q.path[0]=key; q.path[1]=value;
        return md_namespace_mount_request(fs,&q);
    }
    if (nr==SYS_fsopen) {
        if ((unsigned)a[1]&~FSOPEN_CLOEXEC) return -EINVAL;
        r=md_read_string(key,sizeof(key),(const char *)a[0]);
        q.operation=MD_FS_FSOPEN; q.path[0]=key;
        q.flags=O_RDWR|((a[1]&FSOPEN_CLOEXEC) ? O_CLOEXEC : 0);
    } else if (nr==SYS_fsmount) {
        if ((unsigned)a[1]&~FSMOUNT_CLOEXEC) return -EINVAL;
        q.operation=MD_FS_FSMOUNT; q.directory[0]=(int)a[0]; q.mode=(unsigned)a[2];
        q.flags=O_PATH|((a[1]&FSMOUNT_CLOEXEC) ? O_CLOEXEC : 0);
    } else {
        q.operation=MD_FS_FSCONFIG; q.directory[0]=(int)a[0]; q.mode=(unsigned)a[1];
        if (q.directory[0]<0) return -EINVAL;
        switch (q.mode) {
        case FSCONFIG_SET_FLAG:
            if (!a[2] || a[3] || (int)a[4]) return -EINVAL;
            break;
        case FSCONFIG_SET_STRING:
            if (!a[2] || !a[3] || (int)a[4]) return -EINVAL;
            r=md_read_string(value,sizeof(value),(const char *)a[3]);
            if (r>=0) { q.value=value; q.value_size=(unsigned)md_length(value)+1; }
            break;
        case FSCONFIG_CMD_CREATE: case FSCONFIG_CMD_RECONFIGURE:
            if (a[2] || a[3] || (int)a[4]) return -EINVAL;
            break;
        default: return -EOPNOTSUPP;
        }
        if (r>=0 && a[2]) {
            r=md_read_string(key,sizeof(key),(const char *)a[2]); q.path[0]=key;
        }
    }
    if (r<0) return r;
    struct md_fs_response out;
    r=md_fs_call(fs->endpoint,5000,&q,&out);
    if (r>=0) r=out.result.error;
    if (r<0 || nr==SYS_fsconfig) return r;
    return md_namespace_open_result(&out.result,(int)q.flags);
}

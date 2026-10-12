#include "namespace_internal.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/syscall.h>

long md_namespace_mount(const struct md_fs *fs, long nr, const unsigned long *a) {
    char target[PATH_MAX], source[PATH_MAX], data[PATH_MAX];
    source[0]=data[0]=0;
    struct md_fs_request q={.operation=MD_FS_MOUNT,.directory={AT_FDCWD,-1},
        .path={target,NULL}};
    long r=md_read_string(target,sizeof(target),(const char *)a[nr==SYS_mount ? 1 : 0]);
    if (r<0) return r;
    if (!*target) return -ENOENT;
    if (nr==SYS_pivot_root) {
        q.mode=MD_FS_MOUNT_PIVOT;
        r=md_read_string(source,sizeof(source),(const char *)a[1]);
    } else if (nr==SYS_umount2) { q.mode=MD_FS_MOUNT_UMOUNT; q.flags=a[1]; }
    else {
        if (a[3]>UINT32_MAX) return -EINVAL;
        q.flags=a[3];
        /* Linux's legacy magic prefix and diagnostic-only flag carry no mount
         * policy. Normalize once at the syscall ABI, before selecting a verb. */
        if ((q.flags&MS_MGC_MSK)==MS_MGC_VAL) q.flags&=~MS_MGC_MSK;
        q.flags&=~MS_SILENT;
        if (q.flags&MS_REMOUNT) {
            q.mode=MD_FS_MOUNT_REMOUNT;
            if (!(q.flags&MS_BIND) && a[4]) {
                r=md_read_string(data,sizeof(data),(const char *)a[4]);
                if (r>=0) { q.value=data; q.value_size=(uint32_t)md_length(data)+1; }
            }
        }
        else if (q.flags&MS_BIND) {
            q.mode=MD_FS_MOUNT_BIND;
            r=md_read_string(source,sizeof(source),(const char *)a[0]);
        } else if (q.flags&(MS_PRIVATE|MS_SLAVE|MS_SHARED|MS_UNBINDABLE)) q.mode=MD_FS_MOUNT_PROPAGATION;
        else if (q.flags&MS_MOVE) {
            q.mode=MD_FS_MOUNT_MOVE;
            r=md_read_string(source,sizeof(source),(const char *)a[0]);
        } else {
            char type[32];
            r=md_read_string(type,sizeof(type),(const char *)a[2]);
            if (r<0) return r;
            if (md_equal(type,"tmpfs")) q.mode=MD_FS_MOUNT_TMPFS;
            else if (md_equal(type,"overlay")) q.mode=MD_FS_MOUNT_OVERLAY;
            else if (md_equal(type,"proc")) q.mode=MD_FS_MOUNT_PROC;
            else if (md_equal(type,"devpts")) q.mode=MD_FS_MOUNT_DEVPTS;
            else if (md_equal(type,"cgroup")) q.mode=MD_FS_MOUNT_CGROUP;
            else if (md_equal(type,"cgroup2")) q.mode=MD_FS_MOUNT_CGROUP2;
            else if (md_equal(type,"sysfs")) q.mode=MD_FS_MOUNT_SYSFS;
            else if (md_equal(type,"mqueue")) q.mode=MD_FS_MOUNT_MQUEUE;
            else return -ENODEV;
            if (a[4]) r=md_read_string(data,sizeof(data),(const char *)a[4]);
            if (r>=0 && a[4]) { q.value=data; q.value_size=(uint32_t)md_length(data)+1; }
        }
    }
    if (r<0) return r;
    if ((q.mode==MD_FS_MOUNT_BIND || q.mode==MD_FS_MOUNT_MOVE || q.mode==MD_FS_MOUNT_PIVOT)
            && !*source) return -ENOENT;
    if (*source) { q.directory[1]=AT_FDCWD; q.path[1]=source; }
    return md_namespace_paths_request(fs,&q);
}

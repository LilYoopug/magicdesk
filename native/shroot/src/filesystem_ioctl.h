#ifndef MD_FILESYSTEM_IOCTL_H
#define MD_FILESYSTEM_IOCTL_H
#include <linux/fs.h>
#include <asm/ioctls.h>

/* Filesystem metadata belongs to the selected provider, not to its Android
 * storage inode. Opening a devpts peer also retains its mount identity;
 * ordinary device, terminal and socket commands stay separate. */
static inline int md_filesystem_ioctl_opens(unsigned command) {
    return command==TIOCGPTPEER;
}
static inline int md_filesystem_ioctl_command(unsigned command) {
    return command==FS_IOC_GETFLAGS || command==FS_IOC_SETFLAGS
        || command==FS_IOC_GETVERSION || command==FS_IOC_SETVERSION
        || command==FS_IOC_FSGETXATTR || command==FS_IOC_FSSETXATTR
        || md_filesystem_ioctl_opens(command);
}
static inline int md_filesystem_ioctl_writes(unsigned command) {
    return command==FS_IOC_SETFLAGS || command==FS_IOC_SETVERSION || command==FS_IOC_FSSETXATTR;
}
#endif

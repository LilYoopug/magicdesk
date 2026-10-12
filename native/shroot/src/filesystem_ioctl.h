#ifndef MD_FILESYSTEM_IOCTL_H
#define MD_FILESYSTEM_IOCTL_H
#include <linux/fs.h>

/* Filesystem metadata belongs to the selected provider, not to its Android
 * storage inode. Ordinary device, terminal and socket commands stay separate. */
static inline int md_filesystem_ioctl_command(unsigned command) {
    return command==FS_IOC_GETFLAGS || command==FS_IOC_SETFLAGS
        || command==FS_IOC_GETVERSION || command==FS_IOC_SETVERSION
        || command==FS_IOC_FSGETXATTR || command==FS_IOC_FSSETXATTR;
}
static inline int md_filesystem_ioctl_writes(unsigned command) {
    return command==FS_IOC_SETFLAGS || command==FS_IOC_SETVERSION || command==FS_IOC_FSSETXATTR;
}
#endif

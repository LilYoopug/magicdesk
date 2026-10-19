#define _GNU_SOURCE
#include "render_device.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int md_render_device_sysfs(struct md_control_file file,int root) {
    unsigned number=md_render_device_minor(file);
    if (!number) return -EINVAL;
    char node[128]; snprintf(node,sizeof(node),"devices/platform/shroot-gpu/drm/renderD%u",number);
    const char *dirs[]={"bus/platform","class/drm","devices/platform","devices/platform/shroot-gpu",
        "devices/platform/shroot-gpu/drm",node};
    for (unsigned i=0;i<sizeof(dirs)/sizeof(*dirs);++i)
        if (mkdirat(root,dirs[i],0755)) return -errno;
    const char *links[][2]={
        {"dev/char/226:%u","../../devices/platform/shroot-gpu/drm/renderD%u"},
        {"class/drm/renderD%u","../../devices/platform/shroot-gpu/drm/renderD%u"},
        {"devices/platform/shroot-gpu/subsystem","../../../bus/platform"},
        {"devices/platform/shroot-gpu/drm/renderD%u/device","../.."},
        {"devices/platform/shroot-gpu/drm/renderD%u/subsystem","../../../../../class/drm"},
    };
    for (unsigned i=0;i<sizeof(links)/sizeof(*links);++i) {
        char path[128],target[128];
        snprintf(path,sizeof(path),links[i][0],number);
        snprintf(target,sizeof(target),links[i][1],number);
        if (symlinkat(target,root,path)) return -errno;
    }
    const char *files[][2]={
        {"devices/platform/shroot-gpu/uevent","MODALIAS=platform:shroot-gpu\n"},
        {"devices/platform/shroot-gpu/drm/renderD%u/dev","226:%u\n"},
        {"devices/platform/shroot-gpu/drm/renderD%u/uevent","MAJOR=226\nMINOR=%u\nDEVNAME=dri/renderD%u\nDEVTYPE=drm_minor\n"},
    };
    for (unsigned i=0;i<sizeof(files)/sizeof(*files);++i) {
        char path[128],contents[128];
        snprintf(path,sizeof(path),files[i][0],number);
        snprintf(contents,sizeof(contents),files[i][1],number,number);
        int fd=openat(root,path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0444);
        if (fd<0) return -errno;
        size_t size=strlen(contents);
        ssize_t written=write(fd,contents,size);
        int error=written<0 ? -errno : (size_t)written!=size ? -EIO : 0;
        close(fd); if (error) return error;
    }
    return 0;
}

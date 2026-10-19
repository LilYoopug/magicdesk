#define _GNU_SOURCE
#include "fs_engine.h"
#include "render_device.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void md_fs_render_prepare(struct md_filesystem *fs) {
    struct md_fs_request q={.operation=MD_FS_OPEN,.directory={-1,-1},
        .path={"/etc/shroot/render-node",NULL},.flags=O_RDONLY|O_CLOEXEC|O_NONBLOCK};
    struct md_fs_result out;
    md_fs_view_execute(fs,&q,&out,NULL);
    char profile[8]={0}; struct stat st;
    int selected=!out.error && !out.host_path && !out.open_completion.kind && out.fd>=0
        && !fstat(out.fd,&st) && S_ISREG(st.st_mode)
        && read(out.fd,profile,sizeof(profile))==7 && !memcmp(profile,"turnip\n",7);
    if (out.fd>=0) close(out.fd);
    if (!selected) return;
    int error=md_render_device_admit(&fs->render_device);
    if (error) fprintf(stderr,"Shroot: render-node unavailable: %s; retaining existing graphics path\n",strerror(-error));
}

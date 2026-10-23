#include "pid_descriptor.h"
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
struct pid_descriptor {
    struct md_fd_object object;
    struct md_pid_identity *identity;
};
static void destroy(struct md_fd_object *object) {
    struct pid_descriptor *p=(void *)object;
    md_pid_identity_release(p->identity); free(p);
}
static const struct md_fd_object_type type={.destroy=destroy};
struct md_fd_object *md_pid_descriptor_new(struct md_pid_identity *identity) {
    struct pid_descriptor *p=calloc(1,sizeof(*p));
    if (!p) return NULL;
    md_fd_object_init(&p->object,&type); p->identity=md_pid_identity_retain(identity);
    return &p->object;
}
struct md_pid_identity *md_pid_descriptor_identity(struct md_fd_object *object) {
    return object && object->type==&type ? ((struct pid_descriptor *)object)->identity : NULL;
}
int md_pid_descriptor_read(int fd,pid_t *pid) {
    char path[64]; snprintf(path,sizeof(path),"/proc/self/fdinfo/%d",fd);
    int info=open(path,O_RDONLY|O_CLOEXEC);
    if (info<0) return -errno;
    char text[1024]; ssize_t size;
    do size=pread(info,text,sizeof(text)-1,0); while (size<0 && errno==EINTR);
    int error=errno; close(info);
    if (size<0) return -error;
    text[size]=0; *pid=0;
    for (char *line=text;line && *line;) {
        char *next=strchr(line,'\n');
        if (next) *next++=0;
        long value;
        if (sscanf(line,"Pid:\t%ld",&value)==1) {
            if (value < -1 || value>INT_MAX) return -EPROTO;
            *pid=(pid_t)value;
        }
        line=next;
    }
    return 0;
}

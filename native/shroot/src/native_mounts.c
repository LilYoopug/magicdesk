#define _GNU_SOURCE
#include "native_mounts.h"
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct md_native_mounts { FILE *source; char *data; size_t size; int valid; };

void md_native_mounts_release(struct md_native_mounts *s) {
    if (!s) return;
    if (s->source) fclose(s->source);
    free(s->data); free(s);
}
static int changed(struct md_native_mounts *s) {
    /* Nonblocking generation observation, not a state wait. Linux mountinfo
     * poll acknowledges namespace changes; reading alone does not. */
    struct pollfd p={.fd=fileno(s->source),.events=POLLPRI};
    int r=poll(&p,1,0);
    if (r<0) return -errno;
    if (p.revents&(POLLHUP|POLLNVAL)) return -EIO;
    return !!(p.revents&(POLLPRI|POLLERR));
}
static int below(const char *path,const char *root) {
    size_t n=strlen(root);
    return !strncmp(path,root,n) && (!path[n] || path[n]=='/');
}
int md_native_mounts_read(struct md_native_mounts **owner,const char **data,size_t *size) {
    struct md_native_mounts *s=*owner;
    if (!s) {
        s=calloc(1,sizeof(*s));
        if (!s) return -ENOMEM;
        s->source=fopen("/proc/self/mountinfo","re");
        if (!s->source) { int r=-errno; free(s); return r; }
        *owner=s;
    }
    int r=changed(s);
    if (r<0) { s->valid=0; return r; }
    if (!s->valid || r) {
        s->valid=0;
        if (fseek(s->source,0,SEEK_SET)) return -errno;
        clearerr(s->source);
        char *bytes=NULL,*line=NULL; size_t length=0,capacity=0;
        FILE *out=open_memstream(&bytes,&length);
        if (!out) return -errno;
        r=0;
        while (getline(&line,&capacity,s->source)>=0) {
            char path[PATH_MAX];
            if (sscanf(line,"%*u %*u %*s %*s %4095s",path)!=1) { r=-EPROTO; break; }
            if ((below(path,"/proc") || below(path,"/dev")) && !below(path,"/dev/shm"))
                if (fputs(line,out)==EOF) { r=-EIO; break; }
        }
        if (!r && ferror(s->source)) r=-EIO;
        free(line);
        if (fclose(out) && !r) r=-EIO;
        if (!r) {
            int event=changed(s);
            if (event<0) r=event;
            else s->valid=!event;
        }
        if (r) { free(bytes); return r; }
        /* A change during reading prevents reuse, without retrying in a loop.
         * Virtual mounts and namespace-relative IDs are never cached here. */
        free(s->data); s->data=bytes; s->size=length;
    }
    *data=s->data; *size=s->size; return 0;
}

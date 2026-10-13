#include "fifo_description.h"
#include "fifo_readiness.h"
#include "fd_selector.h"
#include <errno.h>
#include <stdlib.h>

struct description {
    struct md_fd_object object;
    struct md_fs_anchor *origin;
    struct md_fifo_readiness *ready;
};
static void destroy(struct md_fd_object *object) {
    struct description *d=(void *)object;
    md_fifo_readiness_free(d->ready);
    md_fs_anchor_release(d->origin); free(d);
}
static struct md_fs_anchor *origin(struct md_fd_object *object) {
    return ((struct description *)object)->origin;
}
static struct md_control_file readiness(struct md_fd_object *object) {
    return md_fifo_readiness_control(((struct description *)object)->ready);
}
static const struct md_fd_object_type type={.destroy=destroy,.origin=origin,.readiness=readiness,
    .selectors=(1U<<MD_FD_SELECTOR_EPOLL_TARGET)|(1U<<MD_FD_SELECTOR_POLL)};
int md_fifo_description_is(const struct md_fd_object *object) {
    return object && object->type==&type;
}
struct md_fd_object *md_fifo_description_new(struct md_fs_anchor *anchor,int endpoint,int control,uint32_t writers) {
    if (!anchor) { errno=EINVAL; return NULL; }
    struct description *d=calloc(1,sizeof(*d));
    if (!d) return NULL;
    md_fd_object_init(&d->object,&type);
    d->origin=md_fs_anchor_retain(anchor);
    d->ready=md_fifo_readiness_new(control,writers);
    int error=d->ready ? md_fifo_readiness_attach(d->ready,endpoint) : -errno;
    if (error) { destroy(&d->object); errno=-error; return NULL; }
    return &d->object;
}
int md_fifo_description_state(const struct md_fd_object *object,uint32_t *writers) {
    return md_fifo_description_is(object)
        ? md_fifo_readiness_state(((const struct description *)object)->ready,writers) : -EINVAL;
}

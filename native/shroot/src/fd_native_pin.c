#define _GNU_SOURCE
#include "fd_native_pin.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct native_pin { struct md_fd_object object; int descriptor; };
static void destroy(struct md_fd_object *object) {
    struct native_pin *pin=(void *)object;
    close(pin->descriptor);
    free(pin);
}
static const struct md_fd_object_type type={.destroy=destroy};
struct md_fd_object *md_fd_native_pin_new(int fd) {
    char path[64];
    snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
    int descriptor=open(path,O_PATH|O_CLOEXEC);
    if (descriptor<0) return NULL;
    struct native_pin *pin=malloc(sizeof(*pin));
    if (!pin) { int error=errno; close(descriptor); errno=error; return NULL; }
    md_fd_object_init(&pin->object,&type);
    pin->descriptor=descriptor;
    return &pin->object;
}
int md_fd_native_pin_descriptor(const struct md_fd_object *object) {
    return object && object->type==&type ? ((const struct native_pin *)object)->descriptor : -1;
}

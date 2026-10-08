#include "pid_descriptor.h"
#include <stdlib.h>
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

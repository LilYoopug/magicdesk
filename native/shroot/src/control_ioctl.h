#ifndef MD_CONTROL_IOCTL_H
#define MD_CONTROL_IOCTL_H
#include "control_file.h"
#include <errno.h>
#include <string.h>

static inline long md_control_ioctl_size(const struct md_control_ioctl *s) {
    if (s->size>MD_CONTROL_IOCTL_MAX
            || s->direction&~(MD_CONTROL_IN|MD_CONTROL_OUT|MD_CONTROL_STRING|MD_CONTROL_INDIRECT)
            || s->fields>MD_CONTROL_IOCTL_FIELDS
            || !!s->fields!=!!(s->direction&MD_CONTROL_INDIRECT)) return -EPROTO;
    if (s->fields && (!(s->direction&MD_CONTROL_IN) || (s->direction&MD_CONTROL_STRING))) return -EPROTO;
    size_t total=s->size;
    for (unsigned i=0;i<s->fields;++i) {
        const struct md_control_ioctl_field *f=&s->field[i];
        if (s->size<sizeof(uintptr_t) || f->pointer>s->size-sizeof(uintptr_t)
                || s->size<sizeof(size_t) || f->length>s->size-sizeof(size_t)
                || !f->direction || f->direction&~(MD_CONTROL_IN|MD_CONTROL_OUT)
                || f->capacity>MD_CONTROL_IOCTL_MAX-total) return -EPROTO;
        total+=f->capacity;
    }
    return (long)total;
}
static inline size_t md_control_ioctl_field_size(const struct md_control_ioctl *s,unsigned index,const void *data) {
    size_t length;
    memcpy(&length,(const char *)data+s->field[index].length,sizeof(length));
    return length<s->field[index].capacity ? length : s->field[index].capacity;
}
#endif

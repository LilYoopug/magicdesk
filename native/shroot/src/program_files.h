#ifndef MD_PROGRAM_FILES_H
#define MD_PROGRAM_FILES_H
#include "fs.h"
#include "image_identity.h"

struct md_fs_anchor;
struct md_program {
    int fd;
    unsigned mount_flags;
    struct md_image_identity identity;
    /* Owned only by supervisor proc capture; released with the captured FD. */
    struct md_fs_anchor *origin;
};
long md_program_open(const struct md_fs *, const char *, int executable);
long md_program_acquire(const struct md_fs *, int base, const char *, int flags, struct md_program *);
long md_program_interpreter(const struct md_fs *,const char *,struct md_program *);
/* Capture a borrowed descriptor, including open-unlinked executable identity. */
long md_program_capture(const struct md_fs *, int fd, const char *, struct md_program *);
#endif

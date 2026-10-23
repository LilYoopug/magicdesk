#ifndef MD_GUEST_ADMISSION_H
#define MD_GUEST_ADMISSION_H
#include "guest_identity.h"
#include <sys/stat.h>

/* One explicit, trusted launch admission. No guest may
 * choose this record's logical owner or mode. */
struct md_admission {
    int source;
    struct stat source_stat;
    struct md_exec_image *image;
    char object[33];
};
int md_admission_open(struct md_admission *, const char *endpoint, const char *guest_path);
/* Takes ownership of source, including on failure. */
int md_admission_snapshot(struct md_admission *, int source);
/* Borrow the exact filesystem-selected image; retain immutable content with
 * logical ownership. Interpreted input requires an admitted binfmt rule. */
int md_exec_image_snapshot(int source, uint32_t uid, uint32_t gid, mode_t mode,
    const struct md_file_capabilities *,int native_elf,struct md_exec_image **out);
int md_admission_match(const struct md_admission *, const char *endpoint, int fd);
void md_admission_close(struct md_admission *);
#endif

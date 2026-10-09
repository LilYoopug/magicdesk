#ifndef MD_FILE_PERMISSIONS_H
#define MD_FILE_PERMISSIONS_H
#include "guest_identity.h"
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
static inline int md_file_permissions(const struct stat *st,unsigned mode,const struct md_identity *id) {
    if (!id || mode&~7U) return -EINVAL;
    unsigned shift=id->uid.fs==st->st_uid ? 6 : md_identity_in_group(id,st->st_gid) ? 3 : 0;
    if (((st->st_mode>>shift)&mode)==mode) return 0;
    if ((!(mode&X_OK) || S_ISDIR(st->st_mode) || (st->st_mode&0111))
            && md_identity_file_capable(id,st->st_uid,st->st_gid,CAP_DAC_OVERRIDE)) return 0;
    return -EACCES;
}
#endif

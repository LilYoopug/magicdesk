#ifndef MD_DESCRIPTOR_PARCEL_H
#define MD_DESCRIPTOR_PARCEL_H
#include "fs_origin_transfer.h"
#include "received_fds.h"

/* Authenticated envelope for filesystem origins plus live anonymous metadata.
 * Ordinary filesystem-only messages retain their existing compact format. */
int md_descriptor_parcel_export(const struct md_fd_message *, const int *data,
    struct md_fs_origin_parcel *);
/* Annotates only after complete validation; consumes filesystem entries from
 * the parcel, whose remaining rights still belong to the caller. */
int md_descriptor_parcel_import(struct md_fs_origin_imports *, const struct md_fd_message_route *,
    struct md_fs_origin_parcel *, struct md_received_fds *);
#endif

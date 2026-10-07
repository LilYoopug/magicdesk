#ifndef MD_MOUNT_COPY_SERVICE_H
#define MD_MOUNT_COPY_SERVICE_H
#include "mount_namespace.h"
#include "guest_domain.h"
struct md_fs_worker;
struct md_mount_copy_service;
struct md_mount_copy_request;
int md_mount_copy_service_create(struct md_fs_worker *,
        void (*complete)(struct md_mount_copy_request *, int actor, int error),
        struct md_mount_copy_service **);
/* Supervisor-only. Caller already owns its file-table and FS-context turns.
 * Worker snapshots mount state; neither candidate is published before success. */
int md_mount_copy_submit(struct md_mount_copy_service *, int actor,
        struct md_mount_namespace *, struct md_guest_domain *, struct md_mount_copy_request **);
void md_mount_copy_cancel(struct md_mount_copy_request **);
int md_mount_copy_take(struct md_mount_copy_request *,
        struct md_mount_namespace **, struct md_guest_domain **);
/* Worker must have joined. Also retires cancelled work without completions. */
void md_mount_copy_service_destroy(struct md_mount_copy_service *);
#endif

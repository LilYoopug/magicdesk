#ifndef MD_EXEC_PREPARE_H
#define MD_EXEC_PREPARE_H
#include "command_image.h"
struct md_fs_context;
struct md_fs_request;
struct md_fs_anchor;
struct md_exec_preparation;
struct md_exec_image;
enum { MD_EXEC_INACCESSIBLE=1, MD_EXEC_OBJECT=2, MD_EXEC_TRACED=4 };
/* Worker-only preparation under an already captured task/mount context.
 * EREMOTE selects an owned proc-image request after namespace resolution.
 * The supervisor authorizes/captures that image before worker continuation.
 * Ordinary exec leaves this optional allocation NULL. */
int md_fs_command_prepare(struct md_fs_context *, const struct md_fs_request *,
    struct md_program **proc_image, struct md_command_recipe *, struct md_command_images *,
    struct md_fs_anchor **image_origin,struct md_exec_image **,struct md_exec_preparation **);
int md_exec_preparation_ready(struct md_exec_preparation *);
void md_exec_preparation_destroy(struct md_exec_preparation *);
#endif

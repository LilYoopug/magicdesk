#ifndef MD_EXEC_PREPARE_H
#define MD_EXEC_PREPARE_H
#include "command_image.h"
struct md_fs_context;
struct md_fs_request;
enum { MD_EXEC_INACCESSIBLE=1, MD_EXEC_OBJECT=2 };
/* Worker-only preparation under an already captured task/mount context. */
int md_fs_command_prepare(struct md_fs_context *, const struct md_fs_request *,
    struct md_command_recipe *, struct md_command_images *);
#endif

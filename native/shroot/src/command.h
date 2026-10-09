#ifndef MD_COMMAND_H
#define MD_COMMAND_H
#include "command_image.h"
#define MD_ARG_MAX 1024
/* Storage remains live until the loader takes ownership of argv strings. */
struct md_command {
    char path[PATH_MAX], object[33];
    char scripts[MD_SCRIPT_DEPTH][PATH_MAX];
    char lines[MD_SCRIPT_DEPTH][MD_SCRIPT_HEADER];
    char *argv[MD_ARG_MAX+16];
    unsigned argc;
    int fd, interpreter_fd;
};
int md_command_arguments(struct md_command *, const char *, char *const []);
int md_command_apply_recipe(struct md_command *, const struct md_command_recipe *);
/* Borrows input (NULL selects the path); success owns both prepared images. */
int md_command_prepare(const struct md_fs *, struct md_command *, const char *, char *const [],
    const struct md_program *input, int inaccessible);
void md_command_close(struct md_command *);
#endif

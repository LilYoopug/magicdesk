#ifndef MD_COMMAND_IMAGE_H
#define MD_COMMAND_IMAGE_H
#include "program_files.h"
#include "elf.h"
#include "binfmt_rule.h"

enum { MD_SCRIPT_DEPTH=4, MD_SCRIPT_HEADER=256 };
enum { MD_REDIRECT_SCRIPT, MD_REDIRECT_BINARY, MD_REDIRECT_PRESERVE };
struct md_command_redirect {
    unsigned kind;
    char text[MD_BINFMT_REGISTER_MAX];
};
/* Pointer-free recipe; argv is assembled only in the caller's address space. */
struct md_command_recipe {
    struct md_image_identity image;
    unsigned redirects, loader, execfd;
    struct md_command_redirect redirect[MD_SCRIPT_DEPTH];
};
struct md_command_images { int program, loader, execfd, anonymous; unsigned mount_flags; };
#define MD_COMMAND_IMAGES_EMPTY { .program=-1, .loader=-1, .execfd=-1 }
enum md_command_file { MD_COMMAND_EXECUTABLE, MD_COMMAND_INTERPRETER };
typedef long (*md_command_acquire)(void *, const char *, struct md_program *, enum md_command_file);
typedef int (*md_command_format)(void *,const struct md_program *,const void *,size_t,char *);
/* Consume one already acquired readable image. Returns zero on completion,
 * kind+1 and the next path on acquisition, or a negative error. Pure image
 * inspection is separate from filesystem IO, which may suspend. */
int md_command_images_step(struct md_command_recipe *,struct md_command_images *,
    struct md_program *,enum md_command_file,int inaccessible,char next[MD_INTERPRETER_MAX],
    md_command_format,void *);
/* Borrows first; owns output images on success, none on failure. */
int md_command_images_prepare(struct md_command_recipe *, struct md_command_images *,
    const struct md_program *first, int inaccessible, md_command_acquire, void *);
void md_command_images_close(struct md_command_images *);
/* Parses a copied header in place. Used by image selection and argv assembly. */
int md_command_script(char line[MD_SCRIPT_HEADER], char **name, char **option);
#endif

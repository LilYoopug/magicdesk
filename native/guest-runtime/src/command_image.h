#ifndef MD_COMMAND_IMAGE_H
#define MD_COMMAND_IMAGE_H
#include "program_files.h"

enum { MD_SCRIPT_DEPTH=4, MD_SCRIPT_HEADER=256 };
/* Pointer-free recipe; argv is assembled only in the caller's address space. */
struct md_command_recipe {
    struct md_image_identity image;
    unsigned scripts, loader;
    char lines[MD_SCRIPT_DEPTH][MD_SCRIPT_HEADER];
};
struct md_command_images { int program, loader; };
typedef long (*md_command_acquire)(void *, const char *, struct md_program *);
/* Borrows first; owns output images on success, none on failure. */
int md_command_images_prepare(struct md_command_recipe *, struct md_command_images *,
    const struct md_program *first, int inaccessible, md_command_acquire, void *);
void md_command_images_close(struct md_command_images *);
/* Parses a copied header in place. Used by image selection and argv assembly. */
int md_command_script(char line[MD_SCRIPT_HEADER], char **name, char **option);
#endif

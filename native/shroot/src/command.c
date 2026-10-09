#define _GNU_SOURCE
#include "command.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int md_command_arguments(struct md_command *c, const char *program, char *const argv[]) {
    c->fd=c->interpreter_fd=-1;
    long r=md_read_string(c->path,sizeof(c->path),program);
    if (r<0) return (int)r;
    c->argc=0;
    for (;c->argc<MD_ARG_MAX;++c->argc) {
        if (!argv) break;
        r=md_read_memory(&c->argv[c->argc],argv+c->argc,sizeof(char *));
        if (r<0) return (int)r;
        if (!c->argv[c->argc]) break;
    }
    if (!c->argc) c->argv[c->argc++]="";
    c->argv[c->argc]=NULL;
    return c->argc==MD_ARG_MAX ? -E2BIG : 0;
}
int md_command_apply_recipe(struct md_command *c, const struct md_command_recipe *recipe) {
    if (recipe->scripts>MD_SCRIPT_DEPTH || recipe->loader>1
            || recipe->image.path[PATH_MAX-1] || recipe->image.object[32]) return -EPROTO;
    for (unsigned depth=0;depth<recipe->scripts;++depth) {
        md_copy(c->scripts[depth],PATH_MAX,c->path);
        memcpy(c->lines[depth],recipe->lines[depth],MD_SCRIPT_HEADER);
        char *name, *option;
        int error=md_command_script(c->lines[depth],&name,&option);
        if (error) return error;
        unsigned shift=*option ? 2 : 1;
        memmove(c->argv+1+shift,c->argv+1,c->argc*sizeof(char *));
        c->argv[0]=name;
        if (*option) c->argv[1]=option;
        c->argv[shift]=c->scripts[depth];
        c->argc+=shift;
        md_copy(c->path,sizeof(c->path),name);
    }
    md_copy(c->path,sizeof(c->path),recipe->image.path);
    memcpy(c->object,recipe->image.object,sizeof(c->object));
    return 0;
}
static long acquire(void *context, const char *path, struct md_program *program) {
    return md_program_acquire(context,AT_FDCWD,path,0,program);
}
int md_command_prepare(const struct md_fs *fs, struct md_command *c, const char *program, char *const argv[],
        const struct md_program *input, int inaccessible) {
    int error=md_command_arguments(c,program,argv);
    if (error) return error;
    struct md_program first;
    if (!input) {
        error=(int)acquire((void *)fs,c->path,&first);
        if (error) return error;
        input=&first;
    }
    struct md_command_recipe recipe;
    struct md_command_images images;
    error=md_command_images_prepare(&recipe,&images,input,inaccessible,acquire,(void *)fs);
    if (input==&first) RAW1(close,first.fd);
    if (!error) {
        c->fd=images.program; c->interpreter_fd=images.loader;
        error=md_command_apply_recipe(c,&recipe);
        if (error) md_command_close(c);
    }
    return error;
}
void md_command_close(struct md_command *c) {
    if (c->fd >= 0) RAW1(close, c->fd);
    if (c->interpreter_fd >= 0) RAW1(close, c->interpreter_fd);
    c->fd = c->interpreter_fd = -1;
}

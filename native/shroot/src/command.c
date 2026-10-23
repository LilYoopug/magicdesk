#define _GNU_SOURCE
#include "command.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int md_command_arguments(struct md_command *c, const char *program, char *const argv[]) {
    c->fd=c->interpreter_fd=c->execfd=-1;
    md_arguments_init(&c->args);
    long r=md_read_string(c->path,sizeof(c->path),program);
    if (r<0) return (int)r;
    r=md_arguments_read(&c->args,argv);
    if (r<0) { md_command_close(c); return (int)r; }
    if (!c->args.count) c->args.values[c->args.count++]="";
    c->args.values[c->args.count]=NULL;
    return 0;
}
int md_command_apply_recipe(struct md_command *c, const struct md_command_recipe *recipe) {
    if (recipe->redirects>MD_SCRIPT_DEPTH || recipe->loader>1 || recipe->execfd>1
            || recipe->image.path[PATH_MAX-1] || recipe->image.object[32]) return -EPROTO;
    int error=md_arguments_reserve(&c->args,c->args.count+2*recipe->redirects+1);
    if (error) return error;
    for (unsigned depth=0;depth<recipe->redirects;++depth) {
        const struct md_command_redirect *redirect=&recipe->redirect[depth];
        if (redirect->kind>MD_REDIRECT_PRESERVE || redirect->text[sizeof(redirect->text)-1]) return -EPROTO;
        md_copy(c->scripts[depth],PATH_MAX,c->path);
        memcpy(c->lines[depth],redirect->text,sizeof(redirect->text));
        char *name=c->lines[depth], *option="";
        int error=redirect->kind==MD_REDIRECT_SCRIPT ? md_command_script(c->lines[depth],&name,&option) : 0;
        if (error) return error;
        unsigned preserve=redirect->kind==MD_REDIRECT_PRESERVE;
        unsigned shift=*option || preserve ? 2 : 1;
        unsigned skip=preserve ? 0 : 1;
        memmove(c->args.values+skip+shift,c->args.values+skip,(c->args.count+1-skip)*sizeof(char *));
        c->args.values[0]=name;
        if (*option) c->args.values[1]=option;
        c->args.values[*option ? 2 : 1]=c->scripts[depth];
        c->args.count+=shift;
        md_copy(c->path,sizeof(c->path),name);
    }
    md_copy(c->path,sizeof(c->path),recipe->image.path);
    memcpy(c->object,recipe->image.object,sizeof(c->object));
    return 0;
}
static long acquire(void *context, const char *path, struct md_program *program, enum md_command_file kind) {
    if (kind==MD_COMMAND_INTERPRETER) return md_program_interpreter(context,path,program);
    return md_program_acquire(context,AT_FDCWD,path,0,program);
}
int md_command_prepare(const struct md_fs *fs, struct md_command *c, const char *program, char *const argv[],
        const struct md_program *input, int inaccessible) {
    int error=md_command_arguments(c,program,argv);
    if (error) return error;
    struct md_program first;
    if (!input) {
        error=(int)acquire((void *)fs,c->path,&first,MD_COMMAND_EXECUTABLE);
        if (error) { md_command_close(c); return error; }
        input=&first;
    }
    struct md_command_recipe recipe;
    struct md_command_images images;
    error=md_command_images_prepare(&recipe,&images,input,inaccessible,acquire,(void *)fs);
    if (input==&first) RAW1(close,first.fd);
    if (!error) {
        c->fd=images.program; c->interpreter_fd=images.loader;
        error=md_command_apply_recipe(c,&recipe);
    }
    if (error) md_command_close(c);
    return error;
}
void md_command_close(struct md_command *c) {
    if (c->fd >= 0) RAW1(close, c->fd);
    if (c->interpreter_fd >= 0) RAW1(close, c->interpreter_fd);
    if (c->execfd >= 0) RAW1(close, c->execfd);
    c->fd = c->interpreter_fd = c->execfd = -1;
    md_arguments_close(&c->args);
}

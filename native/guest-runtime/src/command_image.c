#define _GNU_SOURCE
#include "command_image.h"
#include "elf.h"
#include "linux_abi.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int md_command_script(char header[MD_SCRIPT_HEADER], char **name, char **argument) {
    char *line=header+2, *limit=header+MD_SCRIPT_HEADER, *end=line;
    while (end<limit && *end!='\n') ++end;
    if (end==limit) {
        /* A truncated option is valid, a truncated interpreter name is not. */
        char *p=line;
        while (p<limit && (*p==' ' || *p=='\t')) ++p;
        while (p<limit && *p && *p!=' ' && *p!='\t') ++p;
        if (p==limit) return -ENOEXEC;
        end=limit-1;
    }
    *end=0;
    while (end>line && (end[-1]==' ' || end[-1]=='\t')) *--end=0;
    while (*line==' ' || *line=='\t') ++line;
    char *option=line;
    while (*option && *option!=' ' && *option!='\t') ++option;
    if (*option) *option++=0;
    while (*option==' ' || *option=='\t') ++option;
    if (!*line) return -ENOEXEC;
    *name=line; *argument=option; return 0;
}
void md_command_images_close(struct md_command_images *images) {
    if (images->program>=0) RAW1(close,images->program);
    if (images->loader>=0) RAW1(close,images->loader);
    *images=(struct md_command_images){-1,-1};
}
static long readable(int input) {
    struct stat st;
    long r=RAW2(fstat,input,&st);
    if (r<0) return r;
    if (S_ISLNK(st.st_mode)) return -ELOOP;
    long flags=RAW2(fcntl,input,F_GETFL);
    if (flags<0) return flags;
    /* Do not reopen readable sealed memfds through proc: Android may deny it. */
    if (!(flags&O_PATH) && (flags&O_ACCMODE)!=O_WRONLY)
        return RAW3(fcntl,input,F_DUPFD_CLOEXEC,0);
    char path[64]="/proc/thread-self/fd/";
    md_decimal(path+md_length(path),(unsigned)input);
    return RAW4(openat,AT_FDCWD,path,O_RDONLY|O_CLOEXEC,0);
}
int md_command_images_prepare(struct md_command_recipe *recipe, struct md_command_images *images,
        const struct md_program *first, int inaccessible, md_command_acquire acquire, void *context) {
    *images=(struct md_command_images){-1,-1};
    memset(recipe,0,sizeof(*recipe));
    struct md_program current=*first;
    long r=readable(first->fd);
    if (r<0) return (int)r;
    current.fd=(int)r;
    for (;;) {
        images->program=current.fd;
        r=RAW4(faccessat2,current.fd,"",X_OK,AT_EMPTY_PATH|MD_AT_EACCESS);
        struct stat st;
        if (!r) r=RAW2(fstat,current.fd,&st);
        if (!r && (!S_ISREG(st.st_mode) || (st.st_mode&(S_ISUID|S_ISGID)))) r=-EACCES;
        char header[MD_SCRIPT_HEADER]={0};
        if (!r) r=RAW4(pread64,current.fd,header,sizeof(header),0);
        if (r<0) break;
        if (r<2 || header[0]!='#' || header[1]!='!') {
            char interpreter[MD_INTERPRETER_MAX];
            r=md_elf_interpreter(current.fd,interpreter);
            if (!r && *interpreter) {
                struct md_program loader;
                r=acquire(context,interpreter,&loader);
                if (!r) {
                    images->loader=loader.fd;
                    r=RAW4(faccessat2,loader.fd,"",X_OK,AT_EMPTY_PATH|MD_AT_EACCESS);
                    if (!r) r=md_elf_validate(loader.fd,1);
                }
            }
            if (!r) {
                md_copy(recipe->image.path,sizeof(recipe->image.path),current.identity.path);
                memcpy(recipe->image.object,current.identity.object,sizeof(recipe->image.object));
                recipe->loader=images->loader>=0;
                return 0;
            }
            break;
        }
        if (!recipe->scripts && inaccessible) { r=-ENOENT; break; }
        if (recipe->scripts==MD_SCRIPT_DEPTH) { r=-ELOOP; break; }
        memcpy(recipe->lines[recipe->scripts++],header,sizeof(header));
        char *name, *option;
        r=md_command_script(header,&name,&option);
        if (r<0) break;
        RAW1(close,images->program); images->program=-1;
        r=acquire(context,name,&current);
        if (r<0) break;
    }
    md_command_images_close(images);
    return (int)r;
}

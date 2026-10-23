#define _GNU_SOURCE
#include "command_image.h"
#include "elf.h"
#include "linux_abi.h"
#include "mount_policy.h"
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
    if (images->execfd>=0) RAW1(close,images->execfd);
    *images=(struct md_command_images)MD_COMMAND_IMAGES_EMPTY;
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
    *images=(struct md_command_images)MD_COMMAND_IMAGES_EMPTY;
    memset(recipe,0,sizeof(*recipe));
    struct md_program current=*first;
    long r=readable(first->fd);
    if (r<0) return (int)r;
    current.fd=(int)r;
    enum md_command_file kind=MD_COMMAND_EXECUTABLE;
    for (;;) {
        char next[MD_INTERPRETER_MAX];
        r=md_command_images_step(recipe,images,&current,kind,inaccessible,next,NULL,NULL);
        if (r<=0) return (int)r;
        kind=(enum md_command_file)(r-1);
        r=acquire(context,next,&current,kind);
        if (r<0) { md_command_images_close(images); return (int)r; }
    }
}
int md_command_images_step(struct md_command_recipe *recipe,struct md_command_images *images,
        struct md_program *current,enum md_command_file kind,int inaccessible,char next[MD_INTERPRETER_MAX],
        md_command_format format,void *context) {
    int fd=current->fd; current->fd=-1;
    if (kind==MD_COMMAND_INTERPRETER) images->loader=fd;
    else {
        if (images->program>=0) RAW1(close,images->program);
        images->program=fd;
    }
    long r=current->mount_flags&MD_MOUNT_NOEXEC ? -EACCES
        : RAW4(faccessat2,fd,"",X_OK,AT_EMPTY_PATH|MD_AT_EACCESS);
    if (kind==MD_COMMAND_INTERPRETER) {
        if (!r) r=md_elf_validate(fd,1);
        if (!r) { recipe->loader=1; return 0; }
    } else {
        struct stat st;
        if (!r) r=RAW2(fstat,fd,&st);
        if (!r && (!S_ISREG(st.st_mode) || (st.st_mode&(S_ISUID|S_ISGID)))) r=-EACCES;
        char header[MD_SCRIPT_HEADER]={0};
        if (!r) r=RAW4(pread64,fd,header,sizeof(header),0);
        if (r>=0 && format) {
            int matched=format(context,current,header,(size_t)r,next);
            if (matched>0) return MD_COMMAND_EXECUTABLE+1;
            if (matched<0) r=matched;
        }
        if (r>=0 && (r<2 || header[0]!='#' || header[1]!='!')) {
            r=md_elf_interpreter(fd,next);
            if (!r) {
                recipe->image=current->identity;
                images->mount_flags=current->mount_flags;
                images->anonymous=!current->identity.object[0];
                return *next ? MD_COMMAND_INTERPRETER+1 : 0;
            }
        } else if (r>=0) {
            if (!recipe->redirects && inaccessible) r=-ENOENT;
            else if (recipe->redirects==MD_SCRIPT_DEPTH) r=-ELOOP;
            else {
                struct md_command_redirect *redirect=&recipe->redirect[recipe->redirects++];
                redirect->kind=MD_REDIRECT_SCRIPT;
                memcpy(redirect->text,header,sizeof(header));
                char *name,*option;
                r=md_command_script(header,&name,&option);
                if (!r) r=md_copy(next,MD_INTERPRETER_MAX,name);
                if (!r) return MD_COMMAND_EXECUTABLE+1;
            }
        }
    }
    md_command_images_close(images);
    return (int)r;
}

#ifndef MD_CONTROL_FILE_H
#define MD_CONTROL_FILE_H
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
struct md_identity;
struct md_task_resources;
struct md_control_actor {
    int pid;
    const struct md_identity *identity;
    const struct md_task_resources *resources;
};
struct md_control_file {
    const struct md_control_file_ops *ops;
    void *context;
};
/* A virtual control inode supplies content, not a second IO/cursor manager.
 * The descriptor host serializes each open description and owns copy/commit. */
struct md_control_file_ops {
    void *(*retain)(void *);
    void (*release)(void *);
    int (*stat)(void *,struct stat *);
    long (*read)(void *,const struct md_control_actor *,void *,size_t,int64_t);
    long (*write)(void *,const struct md_control_actor *,const void *,size_t);
    unsigned long filesystem;
    int (*access)(void *,const struct md_identity *,unsigned);
    int nonseekable;
    /* Optional real backing for a controlled view. IO/cursors remain owned by
     * the descriptor host; the returned CLOEXEC descriptor is transferred. */
    int (*descriptor)(void *,int flags);
    int (*seals)(void *);
    int mappable;
};
#endif

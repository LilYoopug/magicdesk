#ifndef MD_CONTROL_FILE_H
#define MD_CONTROL_FILE_H
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
struct md_identity;
struct md_task_resources;
struct md_namespace_reference;
struct md_fs_anchor;
struct md_control_actor {
    int pid;
    const struct md_identity *identity;
    const struct md_task_resources *resources;
};
struct md_control_file {
    const struct md_control_file_ops *ops;
    void *context;
};
/* Typed ioctl marshalling. Providers never dereference guest addresses. Some
 * Linux requests (notably EVIOCSFF) return data despite an _IOW encoding. */
enum { MD_CONTROL_IN=1, MD_CONTROL_OUT=2, MD_CONTROL_STRING=4, MD_CONTROL_IOCTL_MAX=16384 };
struct md_control_ioctl { unsigned size, direction; };
/* Provider-owned asynchronous request. resume never blocks: EINPROGRESS means
 * an external completion will signal the descriptor wakeup. dispose cancels
 * an unfinished request and releases it exactly once. deadline is monotonic. */
struct md_control_pending {
    long (*resume)(struct md_control_pending *,void *data,size_t);
    void (*dispose)(struct md_control_pending *);
    int64_t deadline;
};
/* A virtual inode supplies typed semantics, not a second IO/cursor manager.
 * The descriptor host serializes each open description and owns copy/commit. */
struct md_control_file_ops {
    void *(*retain)(void *);
    void (*release)(void *);
    int (*stat)(void *,struct stat *);
    long (*read)(void *,const struct md_control_actor *,void *,size_t,int64_t);
    long (*write)(void *,const struct md_control_actor *,const void *,size_t,int64_t);
    unsigned long filesystem;
    int (*access)(void *,const struct md_identity *,unsigned);
    int nonseekable;
    /* Optional real backing for a controlled view. IO/cursors remain owned by
     * the descriptor host; the returned CLOEXEC descriptor is transferred. */
    int (*descriptor)(void *,int flags);
    int (*seals)(void *);
    int mappable;
    /* Typed single-file mounts retain their authority, not the carrier inode.
     * at() returns an owned context at the supplied placement; NULL detaches
     * any previous placement before the mount itself retains the provider. */
    const struct md_namespace_reference *(*namespace_reference)(void *);
    void *(*at)(void *,struct md_fs_anchor *);
    /* Borrowed placement, distinct from the native descriptor carrier. */
    struct md_fs_anchor *(*origin)(void *);
    /* Optional independent per-open state; dup/fork retain the same context. */
    void *(*open)(void *,int flags);
    int (*ioctl_spec)(void *,unsigned command,struct md_control_ioctl *);
    long (*ioctl)(void *,const struct md_control_actor *,unsigned command,
        unsigned long value,void *data,size_t size);
    long (*ioctl_async)(void *,const struct md_control_actor *,unsigned command,
        unsigned long value,void *data,size_t size,struct md_control_pending **);
    /* Event sources signal the descriptor owner's wakeup after publication.
     * readable also returns true for terminal errors (disconnect/revoke). */
    int (*readable)(void *);
    void (*read_commit)(void *,size_t copied);
    /* Optional virtual readiness. The wake FD is only a transport hint; it is
     * not the file's application-visible event mask. poll consumes provider
     * state, independently of reads. poll_descriptor returns zero and a
     * borrowed FD, or -1 in the output for a source without notifications.
     * Negative return values are errors, never application event masks. */
    int (*poll_descriptor)(void *,int *descriptor);
    long (*poll)(void *);
    /* True when the original application descriptor now supplies equivalent
     * native readiness. Existing virtual epoll subscriptions remain valid. */
    int (*poll_native)(void *);
};
static inline struct md_control_file md_control_file_retain(struct md_control_file f) {
    if (f.ops) f.context=f.ops->retain(f.context);
    return f;
}
static inline void md_control_file_release(struct md_control_file f) {
    if (f.ops) f.ops->release(f.context);
}
#endif

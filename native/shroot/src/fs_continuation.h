#ifndef MD_FS_CONTINUATION_H
#define MD_FS_CONTINUATION_H
#include "fs_operation.h"
struct md_filesystem;
/* Allocated only by asynchronous providers. Admission owns all operands before
 * the original call returns. No store lock, worker identity or borrowed output
 * pointer survives suspension. resume advances a saved stage, never replays a
 * committed filesystem mutation. The transport retains the task context. */
struct md_fs_continuation {
    struct md_fs_request request;
    void *arguments;
    int (*ready)(struct md_fs_continuation *);
    void (*resume)(struct md_fs_continuation *,struct md_filesystem *,
        struct md_fs_result *,const struct md_fs_output *);
    void (*destroy)(struct md_fs_continuation *);
};
int md_fs_continuation_capture(struct md_fs_continuation *,const struct md_fs_request *);
/* Releases captured operands; the concrete destroy callback frees its owner. */
void md_fs_continuation_clear(struct md_fs_continuation *);
/* Transfers the previous stage to its successor, or destroys it on completion.
 * A suspended operation must not also publish a partial result. */
int md_fs_continuation_pending(struct md_fs_continuation *previous,
    struct md_fs_continuation **next,struct md_fs_result *);
/* Compose a view operation with its next stage. The callback borrows the
 * intermediate result/origin; consume a returned FD by setting it to -1.
 * Only suspension allocates a chain or copies the outer request. */
typedef void (*md_fs_next_stage)(struct md_filesystem *,const struct md_fs_request *,
    struct md_fs_result *,struct md_fs_anchor **,struct md_fs_result *,const struct md_fs_output *);
typedef void (*md_fs_stage)(struct md_filesystem *,const struct md_fs_request *,
    struct md_fs_result *,const struct md_fs_output *);
void md_fs_then(struct md_filesystem *,const struct md_fs_request *outer,
    const struct md_fs_request *step,md_fs_stage,struct md_fs_result *,const struct md_fs_output *,md_fs_next_stage);
void md_fs_view_then(struct md_filesystem *,const struct md_fs_request *outer,
    const struct md_fs_request *step,struct md_fs_result *,const struct md_fs_output *,md_fs_next_stage);
#endif

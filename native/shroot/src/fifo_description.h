#ifndef MD_FIFO_DESCRIPTION_H
#define MD_FIFO_DESCRIPTION_H
#include "fs_anchor.h"
#include <stdint.h>
/* An initial nonblocking FIFO reader has per-open readiness, not new IO
 * semantics. The object retains provenance and observation, never the reader. */
struct md_fd_object *md_fifo_description_new(struct md_fs_anchor *,int endpoint,int control,uint32_t writers);
int md_fifo_description_is(const struct md_fd_object *);
int md_fifo_description_state(const struct md_fd_object *,uint32_t *writers);
#endif

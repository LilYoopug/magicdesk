#ifndef MD_FIFO_READINESS_H
#define MD_FIFO_READINESS_H
#include "control_file.h"
#include <stdint.h>

/* Per-open reader readiness, independent of path identity and data custody.
 * Native epoll interests observe the endpoint without retaining a reader.
 * The channel generation is retained across independent-supervisor transfer. */
struct md_fifo_readiness;
struct md_fifo_readiness *md_fifo_readiness_new(int control,uint32_t writers);
void md_fifo_readiness_free(struct md_fifo_readiness *);
int md_fifo_readiness_attach(struct md_fifo_readiness *,int endpoint);
struct md_control_file md_fifo_readiness_control(struct md_fifo_readiness *);
int md_fifo_readiness_state(const struct md_fifo_readiness *,uint32_t *writers);
#endif

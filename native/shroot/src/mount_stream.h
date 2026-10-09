#ifndef MD_MOUNT_STREAM_H
#define MD_MOUNT_STREAM_H
#include <stdint.h>

/* Single-writer publication. Receivers only peek; the queued snapshot and all
 * its rights survive writer exit. Neither a service thread nor a pathname owns
 * the namespace. The stream itself must never be stored inside its snapshot. */
int md_mount_stream_new(int *reader, int *writer);
int md_mount_stream_publish(int reader, int writer, uint64_t previous,
        const int *rights, unsigned count);
int md_mount_stream_revision(int reader, uint64_t *);
int md_mount_stream_read(int reader, uint64_t *, int **rights, unsigned *count);
#endif

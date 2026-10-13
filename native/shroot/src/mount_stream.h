#ifndef MD_MOUNT_STREAM_H
#define MD_MOUNT_STREAM_H
#include <stdint.h>

/* Single-writer publication. Receivers only peek; the queued snapshot and all
 * its rights survive writer exit. Neither a service thread nor a pathname owns
 * the namespace. The stream itself must never be stored inside its snapshot. */
int md_mount_stream_new(int *reader, int *writer);
int md_mount_stream_publish(int reader, int writer, uint64_t previous,
        const int *rights, unsigned count);
struct md_mount_stream_change {
    int reader, writer;
    uint64_t previous;
    const int *rights;
    unsigned count;
};
/* One decision covers every prepared stream. Failed staging leaves all old
 * snapshots selected; queued candidate rights retire with the next publication
 * or the final reader. Requires one writer per stream. */
int md_mount_stream_publish_many(const struct md_mount_stream_change *, unsigned);
/* Physical sequence also advances for an aborted publication. */
int md_mount_stream_revision(int reader, uint64_t *);
/* Returns the selected logical revision. An undecided publication selects its
 * previous snapshot and must not be cached as the final physical sequence. */
int md_mount_stream_read(int reader, uint64_t *, int **rights, unsigned *count, int *settled);
#endif

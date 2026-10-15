#define _GNU_SOURCE
#include "inode_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/inotify.h>
#include <unistd.h>

int mdi_watch_marker(struct md_inode_store *s,const char *name) {
    if (unlinkat(s->lifetime->root,name,0) && errno!=ENOENT) return -errno;
    int fd=openat(s->lifetime->root,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (fd<0) return -errno;
    close(fd);
    return unlinkat(s->lifetime->root,name,0) ? -errno : 0;
}
int mdi_events_committed(struct md_inode_store *s) {
    if (!s->event_sequence) return 0;
    char name[64]; snprintf(name,sizeof(name),"events.%" PRId64,(int64_t)s->event_sequence);
    return mdi_watch_marker(s,name);
}

int mdi_event(struct md_inode_store *s, const char *parent, const struct mdi_node *node,
        const char *name, unsigned mask, unsigned *cookie) {
    if (!s->recording || node->native) return 0;
    sqlite3_stmt *q = NULL;
    int r = mdi_query_acquire(s, MDI_EVENT, &q);
    if (!r) r = mdi_bind_id(q, 1, parent ? parent : "");
    if (!r) r = mdi_bind_id(q, 2, node->id);
    if (!r) r = mdi_bind_name(q, 3, name ? name : "");
    if (!r) r = mdi_sql_error(sqlite3_bind_int64(q, 4, mask | (node->kind == S_IFDIR ? IN_ISDIR : 0)));
    if (!r) r = mdi_sql_error(sqlite3_bind_int64(q, 5, cookie ? *cookie : 0));
    if (!r) r = mdi_sql_error(mdi_step(s, q));
    r = mdi_query_release(q, r);
    sqlite3_int64 sequence = sqlite3_last_insert_rowid(s->db);
    if (!r) s->event_sequence=sequence;
    /* The FROM row's sequence defines its pair, including across launches. */
    if (!r && cookie && !*cookie) *cookie = (unsigned)((sequence - 1) % UINT32_MAX + 1);
    if (!r && !(sequence & 255)) {
        q = NULL;
        r = mdi_query_acquire(s, MDI_EVENT_TRIM, &q);
        if (!r) r = mdi_sql_error(sqlite3_bind_int64(q, 1, sequence));
        if (!r) r = mdi_sql_error(mdi_step(s, q));
        r = mdi_query_release(q, r);
    }
    return r;
}

int mdi_removed_event(struct md_inode_store *s, const struct mdi_location *loc, int parent_event) {
    int r = parent_event ? mdi_event(s, loc->parent.id, &loc->node, loc->name, IN_DELETE, NULL) : 0;
    if (!r) r = mdi_event(s, NULL, &loc->node, NULL, IN_ATTRIB, NULL);
    if (!r && (loc->node.kind == S_IFDIR || loc->node.links == 1))
        r = mdi_event(s, NULL, &loc->node, NULL, IN_DELETE_SELF, NULL);
    return r;
}

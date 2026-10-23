#define _GNU_SOURCE
#include "inode_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
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

static int directory_changed(struct md_inode_store *s, const char *id) {
    struct mdi_node parent;
    int r=mdi_node(s,id,&parent);
    if (!r && parent.kind!=S_IFDIR) r=-ENOTDIR;
    if (!r) r=mdi_copy_up(s,&parent);
    int directory=r ? -1 : mdi_backing_directory(s,&parent);
    if (!r && directory<0) r=directory;
    const struct timespec times[2]={{.tv_nsec=UTIME_OMIT},{.tv_nsec=UTIME_NOW}};
    if (!r && utimensat(directory,parent.backing,times,AT_SYMLINK_NOFOLLOW)) r=-errno;
    return r;
}

int mdi_event(struct md_inode_store *s, const char *parent, const struct mdi_node *node,
        const char *name, unsigned mask, unsigned *cookie) {
    /* Catalogue names do not change the physical parent. Match native namespace
     * timestamps even without watchers; import/promotion are not guest changes.
     * Like explicit utimens and native IO, backing times are not SQL state. */
    if (parent && !node->native && (mask&(IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO))) {
        int r=directory_changed(s,parent);
        if (r) return r;
    }
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
    if (!r && !parent && node->kind==S_IFDIR && (mask&IN_ATTRIB)) {
        /* Physical directory notifications also include internal timestamp
         * updates. Publish explicit attributes to the named parent here. */
        q=NULL;
        r=mdi_query_acquire(s,MDI_DIRECTORY_NAME,&q);
        if (!r) r=mdi_bind_id(q,1,node->parent);
        if (!r) r=mdi_bind_id(q,2,node->id);
        char entry[NAME_MAX+1]={0};
        if (!r) {
            int rc=mdi_step(s,q);
            if (rc==SQLITE_ROW) {
                int size=sqlite3_column_bytes(q,0);
                if (size<1 || size>NAME_MAX) r=-EIO;
                else memcpy(entry,sqlite3_column_blob(q,0),(size_t)size);
            } else if (rc!=SQLITE_DONE) r=mdi_sql_failure(rc);
        }
        r=mdi_query_release(q,r);
        if (!r && *entry) r=mdi_event(s,node->parent,node,entry,IN_ATTRIB,NULL);
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

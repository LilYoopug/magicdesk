#define _GNU_SOURCE
#include "inode_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int mdi_discard_untracked_backings(struct md_inode_store *s) {
    int fd=openat(s->objects,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if (fd<0) return -errno;
    DIR *dir=fdopendir(fd);
    if (!dir) { int r=-errno; close(fd); return r; }
    sqlite3_stmt *q=NULL;
    /* Cleanup spans all scopes. Index its snapshot once rather than scanning
     * the scope-keyed backing table for every native directory entry. */
    int r=mdi_sql(s,"CREATE TEMP TABLE maintenance_backings(backing TEXT PRIMARY KEY) WITHOUT ROWID;"
        "INSERT OR IGNORE INTO maintenance_backings SELECT backing FROM backings WHERE source=0");
    if (!r) r=mdi_prepare(s,"SELECT 1 FROM temp.maintenance_backings WHERE backing=?1",&q);
    while (!r) {
        errno=0;
        struct dirent *entry=readdir(dir);
        if (!entry) { if (errno) r=-errno; break; }
        if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        if (strlen(entry->d_name)!=32 || strspn(entry->d_name,"0123456789abcdef")!=32) { r=-EIO; break; }
        r=mdi_bind_id(q,1,entry->d_name);
        int next=r ? SQLITE_ERROR : mdi_step(s,q);
        if (!r && next==SQLITE_DONE) {
            struct stat st;
            if (fstatat(fd,entry->d_name,&st,AT_SYMLINK_NOFOLLOW)
                    || unlinkat(fd,entry->d_name,S_ISDIR(st.st_mode) ? AT_REMOVEDIR : 0)) r=-errno;
        } else if (!r && next!=SQLITE_ROW) r=mdi_sql_failure(next);
        int reset=mdi_sql_error(sqlite3_reset(q));
        if (!r) r=reset;
    }
    sqlite3_finalize(q); closedir(dir);
    int drop=mdi_sql(s,"DROP TABLE IF EXISTS temp.maintenance_backings");
    if (!r) r=drop;
    if (!r && fsync(s->objects)) r=-errno;
    return r;
}

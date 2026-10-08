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
    int r=mdi_prepare(s,"SELECT 1 FROM backings WHERE backing=?1 AND source=0 LIMIT 1",&q);
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
    if (!r && fsync(s->objects)) r=-errno;
    return r;
}

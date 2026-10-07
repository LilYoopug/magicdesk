#define _GNU_SOURCE
#include "inode_internal.h"
#include <pthread.h>
#include <stdio.h>
#include <string.h>

static sqlite3_vfs anchored;
static pthread_once_t initialized=PTHREAD_ONCE_INIT;
static int status=SQLITE_ERROR;
static int full_path(sqlite3_vfs *vfs, const char *path, int capacity, char *out) {
    (void)vfs;
    /* This private VFS accepts only runtime-constructed database paths. Keep
     * the retained directory FD instead of SQLite's pathname canonicalization.
     * The stock Unix VFS still owns IO, journaling, locks and O_NOFOLLOW opens. */
    static const char prefix[]="/proc/self/fd/";
    if (strncmp(path,prefix,sizeof(prefix)-1)) return SQLITE_CANTOPEN;
    const char *p=path+sizeof(prefix)-1, *number=p;
    while (*p>='0' && *p<='9') ++p;
    if (p==number || strcmp(p,"/namespace.db")) return SQLITE_CANTOPEN;
    size_t n=strlen(path);
    if (capacity<=0 || n>=(size_t)capacity) return SQLITE_CANTOPEN;
    memcpy(out,path,n+1); return SQLITE_OK;
}
static void initialize(void) {
    sqlite3_vfs *unix=sqlite3_vfs_find("unix");
    if (!unix) return;
    anchored=*unix;
    anchored.zName="shroot-retained-directory";
    anchored.pNext=NULL; anchored.xFullPathname=full_path;
    status=sqlite3_vfs_register(&anchored,0);
}
int mdi_sqlite_reconnect(int root, sqlite3 **out) {
    pthread_once(&initialized,initialize);
    if (status!=SQLITE_OK) return mdi_sql_failure(status);
    char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d/namespace.db",root);
    return mdi_sql_error(sqlite3_open_v2(path,out,
        SQLITE_OPEN_READWRITE|SQLITE_OPEN_NOMUTEX|SQLITE_OPEN_NOFOLLOW,anchored.zName));
}

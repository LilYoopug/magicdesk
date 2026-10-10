#define _GNU_SOURCE
#include "inode_internal.h"
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static sqlite3_vfs anchored;
static pthread_once_t initialized=PTHREAD_ONCE_INIT;
static int status=SQLITE_ERROR;
static int retained_path(const char *path, const char **name) {
    static const char prefix[]="/proc/self/fd/";
    if (strncmp(path,prefix,sizeof(prefix)-1)) return -1;
    const char *p=path+sizeof(prefix)-1, *first=p;
    unsigned fd=0;
    while (*p>='0' && *p<='9') {
        unsigned digit=(unsigned)(*p++-'0');
        if (fd>((unsigned)INT_MAX-digit)/10) return -1;
        fd=fd*10+digit;
    }
    if (p==first || *p++!='/') return -1;
    if (strcmp(p,"namespace.db") && strcmp(p,"namespace.db-journal")
            && strcmp(p,"namespace.db-wal") && strcmp(p,"namespace.db-shm")) return -1;
    *name=p; return (int)fd;
}
static int access_path(sqlite3_vfs *vfs,const char *path,int flags,int *result) {
    (void)vfs;
    const char *name;
    int root=retained_path(path,&name);
    if (root<0) return SQLITE_IOERR_ACCESS;
    /* Keep Unix VFS existence semantics, including empty regular files.
     * Use the already-retained directory, not a repeated procfs path walk.
     * Never cache journal presence: another writer or recovery can change it. */
    if (flags==SQLITE_ACCESS_EXISTS) {
        struct stat st;
        *result=!fstatat(root,name,&st,0) && (!S_ISREG(st.st_mode) || st.st_size>0);
    } else if (flags==SQLITE_ACCESS_READ || flags==SQLITE_ACCESS_READWRITE) {
        *result=!faccessat(root,name,R_OK|(flags==SQLITE_ACCESS_READWRITE ? W_OK : 0),0);
    } else return SQLITE_IOERR_ACCESS;
    return SQLITE_OK;
}
static int full_path(sqlite3_vfs *vfs, const char *path, int capacity, char *out) {
    (void)vfs;
    /* This private VFS accepts only runtime-constructed database paths. Keep
     * the retained directory FD instead of SQLite's pathname canonicalization.
     * The stock Unix VFS still owns IO, journaling, locks and O_NOFOLLOW opens. */
    const char *name;
    if (retained_path(path,&name)<0 || strcmp(name,"namespace.db")) return SQLITE_CANTOPEN;
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
    anchored.xAccess=access_path;
    status=sqlite3_vfs_register(&anchored,0);
}
int mdi_sqlite_open(int root, int create, sqlite3 **out) {
    pthread_once(&initialized,initialize);
    if (status!=SQLITE_OK) return mdi_sql_failure(status);
    char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d/namespace.db",root);
    return mdi_sql_error(sqlite3_open_v2(path,out,
        SQLITE_OPEN_READWRITE|SQLITE_OPEN_NOMUTEX|SQLITE_OPEN_NOFOLLOW
            | (create ? SQLITE_OPEN_CREATE : 0),anchored.zName));
}

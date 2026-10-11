#define _GNU_SOURCE
#include "ipc_database.h"
#include "ipc_storage.h"
#include "storage_database.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <unistd.h>

int md_ipc_database_sql(int r) { return md_database_result(r); }
int md_ipc_database_exec(struct md_ipc_database *d,const char *text) {
    return md_ipc_database_sql(sqlite3_exec(d->handle,text,NULL,NULL,NULL));
}
int md_ipc_database_query(struct md_ipc_database *d,const char *text,sqlite3_stmt **q) {
    return md_ipc_database_sql(sqlite3_prepare_v2(d->handle,text,-1,q,NULL));
}
static void owner_name(char name[64],int64_t id) { snprintf(name,64,"owner-%016llx",(long long)id); }
static int lock(struct md_ipc_database *d) {
    if (d->locked) return -EBUSY;
    /* EVENT_WAIT: the preceding authority releases its transaction gate;
     * interruption fails admission, and process death releases kernel locks. */
    if (flock(d->gate,LOCK_EX)) return -errno;
    d->locked=1; return 0;
}
void md_ipc_database_unlock(struct md_ipc_database *d) {
    if (d->locked) { flock(d->gate,LOCK_UN); d->locked=0; }
}
int md_ipc_database_begin(struct md_ipc_database *d) {
    int r=lock(d);
    if (r) return r;
    r=md_ipc_database_exec(d,"BEGIN IMMEDIATE");
    if (r) md_ipc_database_unlock(d);
    return r;
}
int md_ipc_database_commit(struct md_ipc_database *d,int error) {
    if (!error) error=md_ipc_database_exec(d,"COMMIT");
    if (error) md_ipc_database_exec(d,"ROLLBACK");
    return error;
}
int md_ipc_database_open(struct md_ipc_database *d,const char *store,const char *kind,const char *name) {
    *d=(struct md_ipc_database){.directory=-1,.gate=-1,.lease=-1};
    if (!name || !*name || strchr(name,'/') || !strcmp(name,".") || !strcmp(name,"..")) return -EINVAL;
    d->directory=md_ipc_storage_open(store,kind);
    int r=d->directory<0 ? d->directory : 0;
    if (!r && (d->gate=openat(d->directory,"gate",O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600))<0) r=-errno;
    if (!r) {
        ssize_t n=getrandom(&d->owner,sizeof(d->owner),0);
        if (n!=sizeof(d->owner)) r=n<0 ? -errno : -EIO;
        d->owner&=INT64_MAX;
    }
    char lease[64]; owner_name(lease,d->owner);
    if (!r && (d->lease=openat(d->directory,lease,O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600))<0) r=-errno;
    if (!r && flock(d->lease,LOCK_EX|LOCK_NB)) r=-errno;
    if (!r) r=lock(d);
    if (!r) r=md_database_open(d->directory,name,1,&d->handle);
    if (!r) r=md_ipc_database_exec(d,"PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;"
        "CREATE TABLE IF NOT EXISTS metadata(name TEXT PRIMARY KEY,value TEXT);");
    if (r) md_ipc_database_close(d);
    return r;
}
void md_ipc_database_close(struct md_ipc_database *d) {
    if (d->handle) sqlite3_close(d->handle);
    md_ipc_database_unlock(d);
    if (d->lease>=0) {
        char name[64]; owner_name(name,d->owner);
        unlinkat(d->directory,name,0); close(d->lease);
    }
    if (d->gate>=0) close(d->gate);
    if (d->directory>=0) close(d->directory);
    *d=(struct md_ipc_database){.directory=-1,.gate=-1,.lease=-1};
}
int md_ipc_database_boot(struct md_ipc_database *d,const char *reset) {
    char boot[64];
    int fd=open("/proc/sys/kernel/random/boot_id",O_RDONLY|O_CLOEXEC);
    if (fd<0) return -errno;
    ssize_t n;
    do { n=read(fd,boot,sizeof(boot)-1); } while (n<0 && errno==EINTR);
    int r=n<0 ? -errno : n==0 || n==sizeof(boot)-1 ? -EIO : 0;
    close(fd);
    if (r) return r;
    boot[n]=0;
    sqlite3_stmt *q=NULL; int changed=1;
    r=md_ipc_database_query(d,"SELECT value FROM metadata WHERE name='boot'",&q);
    if (!r) {
        int step=sqlite3_step(q);
        if (step==SQLITE_ROW) {
            const char *old=(const char *)sqlite3_column_text(q,0);
            if (!old) r=-EIO; else changed=strcmp(old,boot)!=0;
        } else if (step!=SQLITE_DONE) r=-EIO;
    }
    sqlite3_finalize(q); q=NULL;
    if (!r && changed) {
        r=md_ipc_database_exec(d,reset);
        if (!r) r=md_ipc_database_query(d,"INSERT OR REPLACE INTO metadata VALUES('boot',?1)",&q);
        if (!r) r=md_ipc_database_sql(sqlite3_bind_text(q,1,boot,-1,SQLITE_STATIC));
        if (!r) r=md_ipc_database_sql(sqlite3_step(q));
        sqlite3_finalize(q);
    }
    return r;
}
int md_ipc_database_reap(struct md_ipc_database *d,const char *select,
        int (*remove)(void *,int64_t),void *context) {
    sqlite3_stmt *q=NULL;
    int r=md_ipc_database_query(d,select,&q);
    if (!r) {
        int step;
        while ((step=sqlite3_step(q))==SQLITE_ROW) {
            int64_t owner=sqlite3_column_int64(q,0);
            if (owner==d->owner) continue;
            char name[64]; owner_name(name,owner);
            int fd=openat(d->directory,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
            int dead=fd<0 && errno==ENOENT;
            if (fd>=0) { dead=!flock(fd,LOCK_EX|LOCK_NB); if (!dead && errno!=EWOULDBLOCK) r=-errno; }
            else if (!dead) r=-errno;
            if (!r && dead) {
                r=remove(context,owner);
                if (!r) unlinkat(d->directory,name,0);
            }
            if (fd>=0) close(fd);
            if (r) break;
        }
        if (!r && step!=SQLITE_DONE) r=-EIO;
    }
    sqlite3_finalize(q); return r;
}

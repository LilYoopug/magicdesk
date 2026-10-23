#define _GNU_SOURCE
#include "inode_internal.h"
#include "inode_leaf.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int mdi_super_refresh(struct md_inode_store *s,sqlite3_int64 version) {
    if (!s->lifetime->temporary || (s->super_checked && s->super_version==version)) return 0;
    sqlite3_stmt *q=NULL;
    int r=mdi_prepare(s,"SELECT coalesce((SELECT value FROM properties WHERE key='runtime_readonly'),0)",&q);
    if (!r) {
        int rc=mdi_step(s,q);
        if (rc!=SQLITE_ROW) r=mdi_sql_failure(rc);
        else {
            s->super_readonly=sqlite3_column_int(q,0)!=0;
            s->super_version=version; s->super_checked=1;
        }
    }
    sqlite3_finalize(q); return r;
}
int md_inode_store_readonly(struct md_inode_store *s) {
    if (!s->lifetime->temporary) return s->readonly;
    int r=mdi_begin(s,0);
    if (r) return r;
    int value=mdi_readonly(s);
    r=mdi_finish(s,0); return r ? r : value;
}

static int writer_check(int directory,const char *name,pid_t tid) {
    struct stat st;
    if (fstatat(directory,name,&st,AT_SYMLINK_NOFOLLOW)) return -errno;
    if (!S_ISREG(st.st_mode)) return 0;
    int fd=openat(directory,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if (fd<0) return -errno;
    struct f_owner_ex owner={.type=F_OWNER_TID,.pid=tid};
    int r=fcntl(fd,F_SETOWN_EX,&owner) ? -errno : 0;
    if (!r && fcntl(fd,F_SETLEASE,F_RDLCK)) r=errno==EAGAIN ? -EBUSY : -errno;
    /* Closing this private open description releases the probe lease. Guest
     * opens remain excluded by the store gate, not by persistent file leases. */
    if (close(fd) && !r) r=-errno;
    return r;
}
static int directory_writers(int parent,const char *name,pid_t tid,unsigned depth) {
    int fd=openat(parent,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (fd<0) return -errno;
    DIR *directory=fdopendir(fd);
    if (!directory) { int r=-errno; close(fd); return r; }
    int r=0;
    while (!r) {
        errno=0;
        struct dirent *entry=readdir(directory);
        if (!entry) { r=-errno; break; }
        if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        struct stat st;
        if (fstatat(fd,entry->d_name,&st,AT_SYMLINK_NOFOLLOW)) r=-errno;
        else if (S_ISDIR(st.st_mode)) {
            /* Native leaves live one level below object directories, not in
             * the flat promoted-object catalogue. The same gate owns both. */
            r=depth ? -EIO : directory_writers(fd,entry->d_name,tid,depth+1);
        } else r=writer_check(fd,entry->d_name,tid);
    }
    if (closedir(directory) && !r) r=-errno;
    return r;
}
static int writers_check(struct md_inode_store *s,const char *backing) {
    sigset_t signals,previous,pending;
    sigemptyset(&signals); sigaddset(&signals,SIGIO);
    int error=pthread_sigmask(SIG_BLOCK,&signals,&previous);
    if (error) return -error;
    int r=sigpending(&pending) ? -errno : 0;
    /* Do not consume another owner's pending signal. Leases target this worker
     * TID only; a native caller outside the guest gate cannot kill the service. */
    if (!r && sigismember(&pending,SIGIO)) r=-EBUSY;
    int drain=!r;
    pid_t tid=(pid_t)syscall(SYS_gettid);
    if (!r) r=backing ? writer_check(s->objects,backing,tid) : directory_writers(s->objects,".",tid,0);
    if (drain) {
        /* Nonblocking consumption after all leases are closed. A break attempt
         * means the backing escaped the gate; do not publish read-only then. */
        struct timespec zero={0};
        if (sigtimedwait(&signals,NULL,&zero)>=0 && !r) r=-EBUSY;
    }
    error=pthread_sigmask(SIG_SETMASK,&previous,NULL);
    return r ? r : -error;
}
int mdi_super_preserve_writer(struct md_inode_store *s,struct mdi_node *node) {
    if (!node->native || !s->lifetime->temporary || s->lifetime->filesystem_kind!=MD_FILESYSTEM_TMPFS) return 0;
    /* Only tmpfs superblocks can be reconfigured. Keep a writer's final
     * backing reachable by that rare scan, including after rename-overwrite.
     * Persistent files and unreferenced tmpfs leaves keep native deletion. */
    int r=writers_check(s,node->backing);
    return r==-EBUSY ? mdi_leaf_promote(s,node) : r;
}
int md_inode_store_reconfigure(struct md_inode_store *s,int readonly) {
    if (!s->lifetime->temporary || s->lifetime->filesystem_kind!=MD_FILESYSTEM_TMPFS
            || strcmp(s->lifetime->scope,MDI_ROOT)) {
        /* Picking an existing filesystem is also used to confirm its current
         * mode. A sealed source cannot become writable; a writable persistent
         * store still cannot acquire tmpfs's superblock-wide writer tracking. */
        if (s->readonly) return readonly ? 0 : -EROFS;
        return readonly ? -EOPNOTSUPP : 0;
    }
    if (s->readonly) return -EROFS;
    int r=mdi_begin(s,0);
    if (r) return r;
    if (readonly && !s->super_readonly) r=writers_check(s,NULL);
    /* Policy is metadata, not a guest write: changing it back to writable must
     * be possible under the same gate even while ordinary mutations are denied.
     * Retained and unlinked bodies remain until exclusive store maintenance. */
    if (!r) r=mdi_sql(s,readonly
        ? "INSERT INTO properties VALUES('runtime_readonly',1) ON CONFLICT(key) DO UPDATE SET value=1"
        : "INSERT INTO properties VALUES('runtime_readonly',0) ON CONFLICT(key) DO UPDATE SET value=0");
    r=mdi_finish(s,r);
    s->super_checked=0;
    return r;
}

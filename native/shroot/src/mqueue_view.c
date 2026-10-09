#define _GNU_SOURCE
#include "mqueue_view.h"
#include "temporary_directory.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

/* Directory-only capability until POSIX queue IO is implemented. No ordinary
 * file creation may bypass the queue authority through this filesystem. */
struct md_mqueue_view {
    int storage,root;
    struct stat identity;
};
struct md_mqueue_view *md_mqueue_view_new(int parent,const struct md_user_namespace *owner) {
    struct md_mqueue_view *v=calloc(1,sizeof(*v));
    if (!v) return NULL;
    v->storage=v->root=-1;
    v->storage=md_temporary_directory_new(parent);
    if (v->storage<0) { errno=-v->storage; goto failed; }
    if (mkdirat(v->storage,"mqueue",0700)) goto failed;
    v->root=openat(v->storage,"mqueue",O_PATH|O_DIRECTORY|O_CLOEXEC);
    if (v->root<0 || fstat(v->root,&v->identity)) goto failed;
    v->identity.st_uid=md_user_namespace_into(owner,0,0);
    v->identity.st_gid=md_user_namespace_into(owner,1,0);
    v->identity.st_mode=S_IFDIR|01777;
    v->identity.st_size=40; v->identity.st_blocks=0; v->identity.st_blksize=4096;
    return v;
failed:;
    int error=errno; md_mqueue_view_free(v); errno=error; return NULL;
}
void md_mqueue_view_free(struct md_mqueue_view *v) {
    if (!v) return;
    if (v->root>=0) close(v->root);
    if (v->storage>=0) md_temporary_directory_release(v->storage);
    free(v);
}
int md_mqueue_root(const struct md_mqueue_view *v) { return v->root; }
int md_mqueue_stat(const struct md_mqueue_view *v,int fd,struct stat *st) {
    if (fd<0) return -ENOENT;
    struct stat native;
    if (fstat(fd,&native)) return -errno;
    if (native.st_dev!=v->identity.st_dev || native.st_ino!=v->identity.st_ino) return -ESTALE;
    *st=v->identity; return 0;
}
int md_mqueue_chmod(struct md_mqueue_view *v,int fd,mode_t mode,const struct md_identity *id) {
    struct stat st; int r=md_mqueue_stat(v,fd,&st);
    if (r) return r;
    if (id->uid.fs!=st.st_uid && !md_identity_file_capable(id,st.st_uid,st.st_gid,CAP_FOWNER)) return -EPERM;
    v->identity.st_mode=S_IFDIR|(mode&07777);
    if (!md_identity_in_group(id,st.st_gid) && !md_identity_file_capable(id,st.st_uid,st.st_gid,CAP_FSETID))
        v->identity.st_mode&=~S_ISGID;
    clock_gettime(CLOCK_REALTIME,&v->identity.st_ctim); return 0;
}
int md_mqueue_chown(struct md_mqueue_view *v,int fd,uint32_t uid,uint32_t gid,const struct md_identity *id) {
    struct stat st; int r=md_mqueue_stat(v,fd,&st);
    if (r) return r;
    if (uid==UINT32_MAX) uid=st.st_uid;
    if (gid==UINT32_MAX) gid=st.st_gid;
    if (!md_identity_file_capable(id,st.st_uid,st.st_gid,CAP_CHOWN)
            && !(id->uid.fs==st.st_uid && uid==st.st_uid && (gid==st.st_gid || md_identity_in_group(id,gid)))) return -EPERM;
    v->identity.st_uid=uid; v->identity.st_gid=gid;
    clock_gettime(CLOCK_REALTIME,&v->identity.st_ctim); return 0;
}

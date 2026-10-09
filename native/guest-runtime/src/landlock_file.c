#define _GNU_SOURCE
#include "landlock_policy.h"
#include "guest_identity.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

struct opened { atomic_uint refs; struct md_landlock_ruleset *rules; struct stat stat; };
static void *retain(void *data) { struct opened *o=data; atomic_fetch_add(&o->refs,1); return o; }
static void release(void *data) {
    struct opened *o=data;
    if (atomic_fetch_sub(&o->refs,1)==1) { md_landlock_ruleset_release(o->rules); free(o); }
}
static int stat_file(void *data,struct stat *st) { *st=((struct opened *)data)->stat; return 0; }
static int access_file(void *data,const struct md_identity *id,unsigned mode) {
    const struct stat *st=&((struct opened *)data)->stat;
    if (mode&X_OK) return -EACCES;
    return !mode || id->uid.fs==st->st_uid
        || md_identity_file_capable(id,st->st_uid,st->st_gid,CAP_DAC_OVERRIDE) ? 0 : -EACCES;
}
static long read_file(void *data,const struct md_control_actor *actor,void *out,size_t size,int64_t off) {
    (void)data; (void)actor; (void)out; (void)size; (void)off; return -EINVAL;
}
static long write_file(void *data,const struct md_control_actor *actor,const void *in,size_t size,int64_t off) {
    (void)data; (void)actor; (void)in; (void)size; (void)off; return -EINVAL;
}
static const struct md_control_file_ops ops={.retain=retain,.release=release,
    .stat=stat_file,.access=access_file,.read=read_file,.write=write_file,.filesystem=ANON_INODE_FS_MAGIC,.nonseekable=1};
struct md_landlock_ruleset *md_landlock_ruleset_control(struct md_control_file file) {
    return file.ops==&ops ? ((struct opened *)file.context)->rules : NULL;
}
int md_landlock_ruleset_open(struct md_landlock_ruleset *rules,const struct md_identity *id,
        const struct md_control_file_ops **operations,void **context) {
    struct opened *o=calloc(1,sizeof(*o));
    if (!o) return -ENOMEM;
    atomic_init(&o->refs,1); o->rules=md_landlock_ruleset_retain(rules);
    int fd=memfd_create("landlock-ruleset",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    int r=fd<0 ? -errno : fstat(fd,&o->stat) ? -errno : 0;
    if (!r && fcntl(fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)) r=-errno;
    o->stat.st_mode=0600; o->stat.st_uid=id->uid.fs; o->stat.st_gid=id->gid.fs;
    if (r) { if (fd>=0) close(fd); release(o); return r; }
    *operations=&ops; *context=o; return fd;
}

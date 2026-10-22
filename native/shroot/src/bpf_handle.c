#define _GNU_SOURCE
#include "bpf_handle.h"
#include "guest_identity.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

struct handle {
    atomic_uint refs;
    const struct md_bpf_handle_type *type;
    void *object;
    struct stat stat;
};
static void *retain(void *data) { struct handle *h=data; atomic_fetch_add(&h->refs,1); return h; }
static void release(void *data) {
    struct handle *h=data;
    if (atomic_fetch_sub(&h->refs,1)==1) { h->type->release(h->object); free(h); }
}
static int stat_handle(void *data,struct stat *st) { *st=((struct handle *)data)->stat; return 0; }
static int access_handle(void *data,const struct md_identity *id,unsigned mode) {
    const struct stat *st=&((struct handle *)data)->stat;
    if (mode&X_OK) return -EACCES;
    return !mode || id->uid.fs==st->st_uid
        || md_identity_file_capable(id,st->st_uid,st->st_gid,CAP_DAC_OVERRIDE) ? 0 : -EACCES;
}
static long read_handle(void *data,const struct md_control_actor *actor,void *out,size_t size,int64_t off) {
    (void)data; (void)actor; (void)out; (void)size; (void)off; return -EINVAL;
}
static long write_handle(void *data,const struct md_control_actor *actor,const void *in,size_t size,int64_t off) {
    (void)data; (void)actor; (void)in; (void)size; (void)off; return -EINVAL;
}
static const struct md_control_file_ops ops={.retain=retain,.release=release,
    .access=access_handle,.stat=stat_handle,.read=read_handle,.write=write_handle,
    .filesystem=ANON_INODE_FS_MAGIC,.nonseekable=1};
void *md_bpf_handle_object(struct md_control_file file,const struct md_bpf_handle_type *type) {
    if (file.ops!=&ops) return NULL;
    struct handle *h=file.context;
    return h->type==type ? h->object : NULL;
}
int md_bpf_handle_open(const struct md_bpf_handle_type *type,void *object,const struct md_identity *id,
        const struct md_control_file_ops **operations,void **context) {
    struct handle *h=calloc(1,sizeof(*h));
    if (!h) return -ENOMEM;
    atomic_init(&h->refs,1); h->type=type; h->object=type->retain(object);
    int fd=memfd_create("bpf-object",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    int r=fd<0 ? -errno : fstat(fd,&h->stat) ? -errno : 0;
    if (!r && fcntl(fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)) r=-errno;
    h->stat.st_mode=S_IFREG|0600; h->stat.st_uid=id->uid.fs; h->stat.st_gid=id->gid.fs;
    if (r) { if (fd>=0) close(fd); release(h); return r; }
    *operations=&ops; *context=h; return fd;
}

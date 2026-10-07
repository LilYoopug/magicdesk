#define _GNU_SOURCE
#include "inode_custody.h"
#include "inode_internal.h"
#include "sealed_manifest.h"
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>

enum { MAGIC=0x4d444943U, VERSION=1 };
struct entry { uint32_t source, reserved; struct md_fd_identity objects, lease; };
struct manifest {
    uint32_t magic, version, count, reserved;
    struct md_fd_identity root;
    struct entry entries[MDI_SOURCES-1];
};
_Static_assert(MD_INODE_CUSTODY_FDS==2*MDI_SOURCES,"custody descriptor bound");
_Static_assert(sizeof(struct entry)==40 && sizeof(struct manifest)==32+40*(MDI_SOURCES-1),
    "inode custody wire layout");
static size_t manifest_size(unsigned count) {
    return offsetof(struct manifest,entries)+count*sizeof(struct entry);
}
unsigned md_inode_custody_rights(const struct md_inode_lifetime *owner) {
    unsigned count=2;
    for (unsigned i=1;i<MDI_SOURCES;++i)
        if (owner->sources[i]>=0 || owner->source_leases[i]>=0) count+=2;
    return count;
}
void md_inode_custody_parcel_close(struct md_inode_custody_parcel *p) {
    if (!p) return;
    unsigned n=p->count>MD_INODE_CUSTODY_FDS ? MD_INODE_CUSTODY_FDS : p->count;
    for (unsigned i=0;i<n;++i) {
        if (p->fd[i]<0) continue;
        for (unsigned j=i+1;j<n;++j) if (p->fd[i]==p->fd[j]) p->fd[j]=-1;
        close(p->fd[i]); p->fd[i]=-1;
    }
    p->count=0;
}
static int directory(int fd, struct stat *st) {
    int flags=fcntl(fd,F_GETFL);
    if (flags<0) return -errno;
    if ((flags&O_PATH) || (flags&O_ACCMODE)!=O_RDONLY) return -EPROTO;
    if (fstat(fd,st)) return -errno;
    return S_ISDIR(st->st_mode) ? 0 : -EPROTO;
}
static int lower(int objects, int lease, struct entry *entry) {
    struct stat st, root, named;
    int r=directory(objects,&st);
    if (!r) r=directory(lease,&root);
    if (!r && fstatat(lease,"objects",&named,AT_SYMLINK_NOFOLLOW)) r=-errno;
    if (!r && !md_fd_identity_same(md_fd_identity(&st),md_fd_identity(&named))) r=-ESTALE;
    if (!r) { entry->objects=md_fd_identity(&st); entry->lease=md_fd_identity(&root); }
    return r;
}
int md_inode_custody_export(const struct md_inode_lifetime *owner, struct md_inode_custody_parcel *out) {
    if (!owner || !out || out->count) return -EINVAL;
    struct manifest data={.magic=MAGIC,.version=VERSION};
    struct stat root;
    int r=directory(owner->root,&root);
    if (r) return r;
    data.root=md_fd_identity(&root);
    if (data.root.device!=(uint64_t)owner->device || data.root.inode!=(uint64_t)owner->inode) return -ESTALE;
    int fds[MD_INODE_CUSTODY_FDS]; fds[1]=owner->root;
    for (unsigned i=1;i<MDI_SOURCES;++i) {
        int objects=owner->sources[i], lease=owner->source_leases[i];
        if (objects<0 && lease<0) continue;
        if (objects<0 || lease<0) return -ESTALE;
        struct entry *e=&data.entries[data.count]; e->source=i;
        r=lower(objects,lease,e);
        if (r) return r;
        fds[2+2*data.count]=objects; fds[3+2*data.count]=lease; ++data.count;
    }
    struct md_inode_custody_parcel candidate={0}; struct md_fd_identity id;
    int manifest=md_sealed_manifest_create("shroot-inode-custody",&data,manifest_size(data.count),&id);
    if (manifest<0) return manifest;
    candidate.fd[candidate.count++]=manifest;
    for (unsigned i=1;i<2+2*data.count;++i) {
        int fd=fcntl(fds[i],F_DUPFD_CLOEXEC,3);
        if (fd<0) { r=-errno; break; }
        candidate.fd[candidate.count++]=fd;
    }
    if (r) md_inode_custody_parcel_close(&candidate);
    else *out=candidate;
    return r;
}
static int take(struct md_inode_custody_parcel *p, unsigned index) {
    int fd=p->fd[index]; p->fd[index]=-1; return fd;
}
static int import(struct md_inode_custody_parcel *p, int expected, struct md_inode_lifetime **out) {
    if (!out || *out || p->count<2 || p->count>MD_INODE_CUSTODY_FDS) return -EINVAL;
    for (unsigned i=0;i<p->count;++i) {
        int flags=fcntl(p->fd[i],F_GETFD);
        if (flags<0) return -errno;
        if (!(flags&FD_CLOEXEC)) return -EINVAL;
        for (unsigned j=0;j<i;++j) if (p->fd[i]==p->fd[j]) return -EPROTO;
    }
    struct manifest data; struct md_fd_identity id; size_t bytes;
    int r=md_sealed_manifest_read(p->fd[0],&data,sizeof(data),&bytes,&id);
    if (r) return r;
    if (bytes<manifest_size(0) || data.magic!=MAGIC || data.version!=VERSION || data.reserved
            || data.count>=MDI_SOURCES || bytes!=manifest_size(data.count)
            || p->count!=2+2*data.count) return -EPROTO;
    struct stat root, scope;
    r=directory(p->fd[1],&root);
    if (r) return r;
    if (!md_fd_identity_same(data.root,md_fd_identity(&root))) return -EPROTO;
    if (fstat(expected,&scope)) return -errno;
    if (!S_ISDIR(scope.st_mode) || !md_fd_identity_same(data.root,md_fd_identity(&scope))) return -ESTALE;
    unsigned previous=0;
    for (unsigned i=0;i<data.count;++i) {
        struct entry *e=&data.entries[i], actual={0};
        if (e->reserved || e->source<=previous || e->source>=MDI_SOURCES) return -EPROTO;
        previous=e->source;
        r=lower(p->fd[2+2*i],p->fd[3+2*i],&actual);
        if (r) return r;
        if (!md_fd_identity_same(actual.objects,e->objects) || !md_fd_identity_same(actual.lease,e->lease)) return -EPROTO;
    }
    struct md_inode_lifetime *owner=mdi_lifetime_new(p->fd[1],&root);
    if (!owner) return -ENOMEM;
    take(p,1);
    for (unsigned i=0;i<data.count;++i) {
        unsigned source=data.entries[i].source;
        owner->sources[source]=take(p,2+2*i); owner->source_leases[source]=take(p,3+2*i);
    }
    *out=owner; return 0;
}
int md_inode_custody_import(struct md_inode_custody_parcel *p, int expected, struct md_inode_lifetime **out) {
    if (!p) return -EINVAL;
    int r=import(p,expected,out); md_inode_custody_parcel_close(p); return r;
}

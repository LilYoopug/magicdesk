#define _GNU_SOURCE
#include "descriptor_parcel.h"
#include "descriptor_inode.h"
#include "fifo_description.h"
#include "sealed_manifest.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { MAGIC=0x4d444450U, VERSION=2, MAX=MD_FD_RECEIPT_MAX, INODE=1, FIFO=2 };
struct entry { uint32_t index,kind,writers; };
struct manifest { uint32_t magic,version,count,files,inodes; struct entry index[MAX]; };
static size_t manifest_size(const struct manifest *m) {
    return offsetof(struct manifest,index)+m->count*sizeof(*m->index);
}
int md_descriptor_parcel_export(const struct md_fd_message *message, const int *data,
        struct md_fs_origin_parcel *out) {
    if (!message || !data || !out || out->fd || out->count) return -EINVAL;
    struct manifest m={.magic=MAGIC,.version=VERSION,.count=md_fd_message_count(message)};
    if (!m.count || m.count>MAX) return -EINVAL;
    struct md_fd_object *const *objects=md_fd_message_origins(message);
    struct md_fd_object *files[MAX], *nodes[MAX];
    unsigned sources[MAX];
    for (unsigned i=0;i<m.count;++i) {
        files[i]=objects[i];
        unsigned kind=md_descriptor_inode_is(objects[i]) ? INODE : md_fifo_description_is(objects[i]) ? FIFO : 0;
        if (!kind) continue;
        if (kind==INODE) files[i]=NULL;
        unsigned j=0; while (j<m.inodes && nodes[j]!=objects[i]) ++j;
        if (j==m.inodes) { nodes[m.inodes++]=objects[i]; sources[j]=i; }
        m.index[i]=(struct entry){.index=j+1,.kind=kind};
        if (kind==FIFO && md_fifo_description_state(objects[i],&m.index[i].writers)<0) return -EINVAL;
    }
    if (!m.inodes) return -EINVAL;
    struct md_fs_origin_parcel fs={0}, candidate={0};
    int error=md_fs_origin_export_entries(message,files,&fs);
    if (!error) {
        m.files=fs.count; candidate.count=1+m.files+m.inodes;
        candidate.fd=malloc(candidate.count*sizeof(int));
        if (!candidate.fd) error=-ENOMEM;
        else {
            for (unsigned i=0;i<candidate.count;++i) candidate.fd[i]=-1;
            memcpy(candidate.fd+1,fs.fd,fs.count*sizeof(int)); fs.count=0;
        }
    }
    for (unsigned i=0;!error && i<m.inodes;++i) {
        int *out=&candidate.fd[1+m.files+i];
        if (m.index[sources[i]].kind==INODE)
            error=md_descriptor_inode_export(nodes[i],data[sources[i]],md_fd_message_store_root(message),out);
        else {
            uint32_t writers;
            int fd=md_fifo_description_state(nodes[i],&writers);
            if (fd<0) error=fd;
            else if ((*out=fcntl(fd,F_DUPFD_CLOEXEC,0))<0) error=-errno;
        }
    }
    if (!error) {
        struct md_fd_identity identity;
        int fd=md_sealed_manifest_create("shroot-descriptor-origins",&m,manifest_size(&m),&identity);
        if (fd<0) error=fd; else candidate.fd[0]=fd;
    }
    md_fs_origin_parcel_close(&fs);
    if (error) md_fs_origin_parcel_close(&candidate); else *out=candidate;
    return error;
}
int md_descriptor_parcel_import(struct md_fs_origin_imports *imports, const struct md_fd_message_route *route,
        struct md_fs_origin_parcel *parcel, struct md_received_fds *received) {
    if (!imports || !route || !parcel || !parcel->fd || parcel->count<3
            || parcel->count>MD_FS_ORIGIN_MAX_RIGHTS || !received) return -EINVAL;
    struct manifest m={0}; size_t size=0; struct md_fd_identity identity;
    int error=md_sealed_manifest_read(parcel->fd[0],&m,sizeof(m),&size,&identity);
    if (error) return error;
    if (size<offsetof(struct manifest,index) || m.magic!=MAGIC || m.version!=VERSION
            || !m.count || m.count>MAX || size!=manifest_size(&m)
            || m.count!=route->count || m.count!=received->count
            || !m.inodes || m.inodes>m.count
            || !m.files || m.files>MD_FS_ORIGIN_MAX_RIGHTS
            || parcel->count!=1+m.files+m.inodes) return -EPROTO;
    unsigned seen=0;
    for (unsigned i=0;i<m.count;++i) {
        struct entry e=m.index[i];
        if (e.index>m.inodes || e.index>seen+1 || e.kind>FIFO || !!e.kind!=!!e.index
                || (e.kind!=FIFO && e.writers)) return -EPROTO;
        if (e.index==seen+1) ++seen;
        for (unsigned j=0;j<i;++j) if (e.index && e.index==m.index[j].index
                && (e.kind!=m.index[j].kind || e.writers!=m.index[j].writers)) return -EPROTO;
    }
    if (seen!=m.inodes) return -EPROTO;
    struct md_fs_origin_parcel fs={0};
    fs.fd=malloc(m.files*sizeof(int)); if (!fs.fd) return -ENOMEM;
    fs.count=m.files;
    for (unsigned i=0;i<m.files;++i) { fs.fd[i]=parcel->fd[i+1]; parcel->fd[i+1]=-1; }
    struct md_fs_origin_vector *vector=NULL;
    if (!error) error=md_fs_origin_import(imports,route,&fs,&vector);
    if (!error && md_fs_origin_vector_count(vector)!=m.count) error=-EPROTO;
    struct md_fs_anchor *const *entries=md_fs_origin_vector_entries(vector);
    struct md_fd_object *objects[MAX]={0};
    for (unsigned i=0;!error && i<m.count;++i) {
        struct entry e=m.index[i];
        if (e.kind==INODE) {
            if (entries[i]) { error=-EPROTO; break; }
            error=md_descriptor_inode_import(parcel->fd[m.files+e.index],received->fds[i],&objects[i]);
        } else if (e.kind==FIFO) {
            if (!entries[i]) { error=-EPROTO; break; }
            error=md_fs_anchor_check_fd(entries[i],received->fds[i]);
            if (!error) {
                unsigned j=0; while (j<i && m.index[j].index!=e.index) ++j;
                objects[i]=j<i ? md_fd_object_retain(objects[j])
                    : md_fifo_description_new(entries[i],received->fds[i],parcel->fd[m.files+e.index],e.writers);
                if (!objects[i]) error=-errno;
            }
        } else {
            objects[i]=md_fd_object_retain(md_fs_anchor_object(entries[i]));
            if (entries[i]) error=md_fs_anchor_check_fd(entries[i],received->fds[i]);
        }
    }
    if (!error) error=md_received_fds_annotate(received,objects,m.count);
    for (unsigned i=0;i<m.count;++i) md_fd_object_release(objects[i]);
    md_fs_origin_vector_free(vector); md_fs_origin_parcel_close(&fs);
    return error;
}

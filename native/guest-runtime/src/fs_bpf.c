#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include "cgroup_program.h"
#include "bpf_request.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static int publish(struct md_cgroup_program *p,const struct md_identity *id,const struct md_fs_output *out) {
    if (!out || !out->control) return -EOPNOTSUPP;
    const struct md_control_file_ops *ops=NULL; void *context=NULL;
    int fd=md_cgroup_program_open(p,id,&ops,&context);
    if (fd<0) return fd;
    int r=out->control(out->control_context,ops,context,id,O_RDWR|O_CLOEXEC);
    ops->release(context);
    if (r) { close(fd); return r; } return fd;
}
void md_fs_bpf(struct md_filesystem *fs,const struct md_fs_request *q,
        struct md_fs_result *result,const struct md_fs_output *out) {
    *result=(struct md_fs_result){.fd=-1};
    const struct md_identity *id=fs->store->identity;
    if (!fs->actor || !fs->actor->cgroup || !id
            || !md_identity_capable_in(id,id->user_namespace,CAP_SYS_ADMIN)) {
        result->error=-EPERM; return;
    }
    struct md_bpf_request input; memcpy(&input,q->value,sizeof(input));
    struct md_cgroup_member *member=fs->actor->cgroup;
    struct md_cgroup_program *p=NULL;
    int r=0;
    if (md_bpf_opens(q->mode)) {
        struct md_cgroup_programs *registry=md_cgroup_program_registry(member,q->mode==BPF_PROG_LOAD);
        if (q->mode==BPF_PROG_LOAD) {
            if (!registry) r=-errno;
            else {
                p=md_cgroup_program_new(registry,input.type,
                    (const void *)((const char *)q->value+sizeof(input)),input.count,input.name);
                if (!p) r=-errno;
            }
        } else { p=md_cgroup_program_find(registry,input.id); if (!p) r=-ENOENT; }
        md_cgroup_programs_release(registry);
        if (!r) {
            int fd=publish(p,id,out);
            if (fd<0) r=fd; else result->fd=fd;
        }
        md_cgroup_program_release(p);
    } else if (q->mode==BPF_OBJ_GET_INFO_BY_FD) {
        p=md_cgroup_program_control(q->control);
        if (!p) r=-EINVAL;
        else if (!out || out->capacity<sizeof(struct bpf_prog_info)) r=-ENOSPC;
        else { md_cgroup_program_info(p,out->data); result->size=sizeof(struct bpf_prog_info); }
    } else {
        unsigned target=q->mode==BPF_PROG_QUERY ? 0 : 1;
        const struct md_fs_anchor *origin=q->origin[target];
        struct md_view_mount *mount=origin ? origin->mount : NULL;
        if (!mount || !mount->cgroup) r=-EINVAL;
        else if ((r=md_fs_anchor_check_fd(origin,q->directory[target]))) { }
        else if (q->mode==BPF_PROG_QUERY) {
            struct md_bpf_query info;
            unsigned capacity=(q->capacity-sizeof(info))/sizeof(uint32_t);
            if (!out || out->capacity<q->capacity) r=-ENOSPC;
            else {
                r=md_cgroup_program_query(mount->cgroup,q->directory[target],member,id,input.flags,
                    (uint32_t *)((char *)out->data+sizeof(info)),capacity,&info.count,&info.flags);
                if (!r) {
                    memcpy(out->data,&info,sizeof(info));
                    result->size=sizeof(info)+(info.count<capacity ? info.count : capacity)*sizeof(uint32_t);
                }
            }
        } else if (md_view_readonly(mount)) r=-EROFS;
        else if (!(p=md_cgroup_program_control(q->control))) r=-EINVAL;
        else r=md_cgroup_program_attach(mount->cgroup,q->directory[target],member,id,p,input.flags,q->mode==BPF_PROG_DETACH);
    }
    result->error=r;
}

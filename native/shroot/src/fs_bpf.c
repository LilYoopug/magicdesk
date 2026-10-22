#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "fs_control.h"
#include "inode_internal.h"
#include "cgroup_program.h"
#include "bpf_request.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static int publish(struct md_cgroup_program *p,struct md_bpf_map *m,const struct md_identity *id,
        struct md_fs_result *result,const struct md_fs_output *out) {
    if (!out || !out->control) return -EOPNOTSUPP;
    const struct md_control_file_ops *ops=NULL; void *context=NULL;
    int fd=p ? md_cgroup_program_open(p,id,&ops,&context) : md_bpf_map_open(m,id,&ops,&context);
    if (fd<0) return fd;
    struct md_control_file file={ops,context};
    int r=md_fs_control_publish(fd,file,NULL,id,O_RDWR|O_CLOEXEC,result,out);
    md_control_file_release(file); return r;
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
    struct md_bpf_map *map=NULL;
    int r=0;
    if (md_bpf_opens(q->mode)) {
        struct md_cgroup_programs *registry=md_cgroup_program_registry(member,
            q->mode==BPF_PROG_LOAD || q->mode==BPF_MAP_CREATE);
        if (q->mode==BPF_MAP_CREATE || q->mode==BPF_MAP_GET_FD_BY_ID) {
            struct md_bpf_maps *maps=md_cgroup_program_maps(registry,q->mode==BPF_MAP_CREATE);
            if (q->mode==BPF_MAP_CREATE) {
                struct bpf_map_info info={.type=input.type,.key_size=input.key_size,
                    .value_size=input.value_size,.max_entries=input.count,.map_flags=input.flags};
                memcpy(info.name,input.name,sizeof(info.name));
                if (!maps) r=-ENOMEM;
                else if (!(map=md_bpf_map_new(maps,&info))) r=-errno;
            } else if (!(map=md_bpf_map_find(maps,input.id))) r=-ENOENT;
            md_bpf_maps_release(maps);
        } else if (q->mode==BPF_PROG_LOAD) {
            if (!registry) r=-errno;
            else {
                p=md_cgroup_program_new(registry,input.type,
                    (const void *)((const char *)q->value+sizeof(input)),input.count,input.name);
                if (!p) r=-errno;
            }
        } else { p=md_cgroup_program_find(registry,input.id); if (!p) r=-ENOENT; }
        md_cgroup_programs_release(registry);
        if (!r) r=publish(p,map,id,result,out);
        md_cgroup_program_release(p);
        md_bpf_map_release(map);
    } else if (q->mode==BPF_OBJ_GET_INFO_BY_FD) {
        p=md_cgroup_program_control(q->control);
        map=md_bpf_map_control(q->control);
        if (!p && !map) r=-EINVAL;
        else if (!out || out->capacity<q->capacity) r=-ENOSPC;
        else {
            struct md_bpf_info info={.kind=p ? MD_BPF_INFO_PROGRAM : MD_BPF_INFO_MAP};
            if (p) { md_cgroup_program_info(p,&info.value.program); md_cgroup_program_map_ids(p,info.maps); }
            else md_bpf_map_info(map,&info.value.map);
            memcpy(out->data,&info,sizeof(info)); result->size=sizeof(info);
            if (p) result->size+=md_cgroup_program_instructions(p,(char *)out->data+sizeof(info),
                q->capacity-sizeof(info));
        }
    } else if (md_bpf_element(q->mode)) {
        map=md_bpf_map_control(q->control);
        if (!map) r=-EINVAL;
        else {
            struct bpf_map_info info; md_bpf_map_info(map,&info);
            if (input.key_size!=info.key_size || input.value_size!=info.value_size) r=-EINVAL;
            else if (q->capacity && (!out || out->capacity<q->capacity)) r=-ENOSPC;
            else {
                const char *key=(const char *)q->value+sizeof(input);
                r=md_bpf_map_element(map,q->mode,input.count ? key : NULL,
                    key+(input.count ? input.key_size : 0),input.flags,out ? out->data : NULL);
                if (!r) result->size=q->capacity;
            }
        }
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

#include "namespace_internal.h"
#include "bpf_request.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>

struct delivery { unsigned command; uintptr_t address; const union bpf_attr *attr; };
static int deliver(void *context,const void *data,size_t size) {
    struct delivery *d=context;
    const union bpf_attr *attr=d->attr;
    long r;
    if (d->command==BPF_PROG_QUERY) {
        struct md_bpf_query info; memcpy(&info,data,sizeof(info));
        r=md_write_memory((void *)(d->address+offsetof(union bpf_attr,query.attach_flags)),&info.flags,sizeof(info.flags));
        if (r>=0) r=md_write_memory((void *)(d->address+offsetof(union bpf_attr,query.prog_cnt)),&info.count,sizeof(info.count));
        if (r>=0 && attr->query.prog_ids && size>sizeof(info))
            r=md_write_memory((void *)(uintptr_t)attr->query.prog_ids,(const char *)data+sizeof(info),size-sizeof(info));
        if (r>=0 && attr->query.prog_ids && attr->query.prog_cnt<info.count) r=-ENOSPC;
    } else {
        unsigned length=sizeof(struct bpf_prog_info);
        r=md_write_memory((void *)(uintptr_t)attr->info.info,data,attr->info.info_len<length ? attr->info.info_len : length);
        if (r>=0) r=md_write_memory((void *)(d->address+offsetof(union bpf_attr,info.info_len)),&length,sizeof(length));
    }
    return r<0 ? (int)r : 0;
}
long md_namespace_bpf(const struct md_fs *fs,const unsigned long *a) {
    unsigned command=(unsigned)a[0];
    union bpf_attr attr={0}; size_t known=0;
    switch (command) {
    case BPF_PROG_LOAD: known=offsetof(union bpf_attr,expected_attach_type)+sizeof(attr.expected_attach_type); break;
    case BPF_PROG_QUERY: known=offsetof(union bpf_attr,query.prog_cnt)+sizeof(attr.query.prog_cnt); break;
    case BPF_PROG_ATTACH: case BPF_PROG_DETACH:
        known=offsetof(union bpf_attr,replace_bpf_fd)+sizeof(attr.replace_bpf_fd); break;
    case BPF_PROG_GET_FD_BY_ID: known=offsetof(union bpf_attr,open_flags)+sizeof(attr.open_flags); break;
    case BPF_OBJ_GET_INFO_BY_FD: known=sizeof(attr.info); break;
    /* Linux reports an unavailable bpf command as EINVAL. Optional feature
     * probes (including BTF) must distinguish absence from execution failure. */
    default: return -EINVAL;
    }
    /* bpf_attr, unlike mount_attr, zero-extends short ABI versions. */
    long r=a[2]<known ? md_read_memory(&attr,(const void *)a[1],a[2])
        : md_read_struct(&attr,known,(const void *)a[1],a[2]);
    if (r<0) return r;
    struct { struct md_bpf_request header; struct bpf_insn instructions[MD_BPF_INSTRUCTIONS_MAX]; } input;
    _Static_assert(offsetof(__typeof__(input),instructions)==sizeof(input.header),"BPF input layout");
    memset(&input.header,0,sizeof(input.header));
    struct md_fs_request q={.operation=MD_FS_BPF,.mode=command,.directory={-1,-1},
        .value=&input,.value_size=sizeof(input.header)};
    if (command==BPF_PROG_LOAD) {
        if (!md_bpf_program_type(attr.prog_type)) return -EOPNOTSUPP;
        if (attr.prog_flags || attr.kern_version || attr.prog_ifindex
                || (attr.prog_type==BPF_PROG_TYPE_CGROUP_DEVICE
                    ? attr.expected_attach_type && attr.expected_attach_type!=BPF_CGROUP_DEVICE
                    : attr.expected_attach_type!=BPF_CGROUP_INET_INGRESS
                        && attr.expected_attach_type!=BPF_CGROUP_INET_EGRESS)) return -EOPNOTSUPP;
        if (!attr.insn_cnt || attr.insn_cnt>MD_BPF_INSTRUCTIONS_MAX) return -E2BIG;
        char license[128];
        r=md_read_string(license,sizeof(license),(const void *)(uintptr_t)attr.license);
        if (r<0) return r;
        if (attr.log_level) {
            if (!attr.log_buf || !attr.log_size) return -EINVAL;
            r=md_write_memory((void *)(uintptr_t)attr.log_buf,"",1); if (r<0) return r;
        }
        input.header.count=attr.insn_cnt; input.header.type=attr.prog_type;
        memcpy(input.header.name,attr.prog_name,sizeof(input.header.name));
        size_t bytes=attr.insn_cnt*sizeof(struct bpf_insn);
        r=md_read_memory(input.instructions,(const void *)(uintptr_t)attr.insns,bytes);
        if (r<0) return r;
        q.value_size+=bytes; q.flags=O_RDWR|O_CLOEXEC;
    } else if (command==BPF_PROG_GET_FD_BY_ID) {
        if (attr.next_id || attr.open_flags) return -EINVAL;
        input.header.id=attr.prog_id; q.flags=O_RDWR|O_CLOEXEC;
    } else if (command==BPF_OBJ_GET_INFO_BY_FD) {
        struct bpf_prog_info info={0};
        r=md_read_memory(&info,(const void *)(uintptr_t)attr.info.info,
            attr.info.info_len<sizeof(info) ? attr.info.info_len : sizeof(info));
        if (r<0) return r;
        /* Instruction/JIT/BTF exports are separate features, not host-memory
         * pointers for the filesystem worker to follow. */
        if (info.jited_prog_insns || info.xlated_prog_insns || info.map_ids || info.jited_ksyms
                || info.jited_func_lens || info.func_info || info.line_info || info.jited_line_info) return -EOPNOTSUPP;
        q.directory[0]=(int)attr.info.bpf_fd; q.capacity=sizeof(info);
    } else {
        unsigned type=command==BPF_PROG_QUERY ? attr.query.attach_type : attr.attach_type;
        if (type!=BPF_CGROUP_DEVICE) return -EOPNOTSUPP;
        if (command==BPF_PROG_QUERY) {
            input.header.flags=attr.query.query_flags; q.directory[0]=(int)attr.query.target_fd;
            if (input.header.flags&~BPF_F_QUERY_EFFECTIVE) return -EINVAL;
            unsigned count=attr.query.prog_ids ? attr.query.prog_cnt : 0;
            if (count>MD_BPF_QUERY_MAX) return -E2BIG;
            q.capacity=sizeof(struct md_bpf_query)+count*sizeof(uint32_t);
        } else {
            input.header.flags=attr.attach_flags;
            if (attr.attach_flags&~BPF_F_ALLOW_MULTI || attr.replace_bpf_fd
                    || (command==BPF_PROG_DETACH && attr.attach_flags)) return -EINVAL;
            q.directory[0]=(int)attr.attach_bpf_fd; q.directory[1]=(int)attr.target_fd;
        }
    }
    if ((!md_bpf_opens(command) && q.directory[0]<0)
            || ((command==BPF_PROG_ATTACH || command==BPF_PROG_DETACH) && q.directory[1]<0)) return -EBADF;
    struct md_fs_response out;
    struct delivery d={command,a[1],&attr};
    r=md_fs_call_deliver(fs->endpoint,5000,&q,&out,q.capacity ? deliver : NULL,&d);
    if (r>=0) r=out.result.error;
    if (r<0) return r;
    if (md_bpf_opens(command)) return md_namespace_open_result(&out.result,O_RDWR|O_CLOEXEC);
    return r<0 ? r : 0;
}

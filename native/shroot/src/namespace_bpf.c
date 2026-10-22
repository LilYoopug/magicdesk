#include "namespace_internal.h"
#include "bpf_request.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>

struct delivery {
    unsigned command;
    uintptr_t address;
    const union bpf_attr *attr;
    struct bpf_prog_info wanted;
};
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
    } else if (d->command==BPF_OBJ_GET_INFO_BY_FD) {
        struct md_bpf_info info; memcpy(&info,data,sizeof(info));
        unsigned length=info.kind==MD_BPF_INFO_MAP ? sizeof(struct bpf_map_info) : sizeof(struct bpf_prog_info);
        if (info.kind==MD_BPF_INFO_PROGRAM) {
            struct bpf_prog_info wanted=d->wanted;
            if (wanted.jited_prog_insns || wanted.jited_ksyms
                    || wanted.jited_func_lens || wanted.func_info || wanted.line_info || wanted.jited_line_info) return -EOPNOTSUPP;
            unsigned count=wanted.nr_map_ids<info.value.program.nr_map_ids ? wanted.nr_map_ids : info.value.program.nr_map_ids;
            if (count) {
                r=md_write_memory((void *)(uintptr_t)wanted.map_ids,info.maps,count*sizeof(uint32_t));
                if (r<0) return (int)r;
            }
            info.value.program.map_ids=wanted.map_ids;
            if (size>sizeof(info)) {
                r=md_write_memory((void *)(uintptr_t)wanted.xlated_prog_insns,
                    (const char *)data+sizeof(info),size-sizeof(info));
                if (r<0) return (int)r;
            }
            info.value.program.xlated_prog_insns=wanted.xlated_prog_insns;
        }
        if (length>attr->info.info_len) length=attr->info.info_len;
        r=md_write_memory((void *)(uintptr_t)attr->info.info,&info.value,length);
        if (r>=0) r=md_write_memory((void *)(d->address+offsetof(union bpf_attr,info.info_len)),&length,sizeof(length));
    } else r=md_write_memory((void *)(uintptr_t)attr->value,data,size);
    return r<0 ? (int)r : 0;
}
static int copy_info(void *target,const void *data,size_t size) {
    if (size!=sizeof(struct md_bpf_info)) return -EPROTO;
    memcpy(target,data,size); return 0;
}
static long object_info(const struct md_fs *fs,int fd,struct md_bpf_info *info) {
    if (fd<0) return -EBADF;
    struct md_bpf_request input={0};
    struct md_fs_request q={.operation=MD_FS_BPF,.mode=BPF_OBJ_GET_INFO_BY_FD,.directory={fd,-1},
        .value=&input,.value_size=sizeof(input),.capacity=sizeof(*info)};
    struct md_fs_response out;
    long r=md_fs_call_deliver(fs->endpoint,5000,&q,&out,copy_info,info);
    return r<0 ? r : out.result.error;
}
static long resolve_maps(const struct md_fs *fs,struct bpf_insn *insns,unsigned count) {
    struct { int fd; uint32_t id; } maps[MD_BPF_MAPS_PER_PROGRAM];
    unsigned used=0;
    for (unsigned i=0;i<count;++i) if (insns[i].code==(BPF_LD|BPF_IMM|BPF_DW)) {
        if (insns[i].src_reg==BPF_PSEUDO_MAP_FD) {
            unsigned j=0; while (j<used && maps[j].fd!=insns[i].imm) ++j;
            if (j==used) {
                if (used==MD_BPF_MAPS_PER_PROGRAM) return -E2BIG;
                struct md_bpf_info info;
                long r=object_info(fs,insns[i].imm,&info);
                if (r<0) return r;
                if (info.kind!=MD_BPF_INFO_MAP) return -EINVAL;
                maps[used].fd=insns[i].imm; maps[used++].id=info.value.map.id;
            }
            insns[i].imm=(int)maps[j].id;
        }
        ++i;
    }
    return 0;
}
long md_namespace_bpf(const struct md_fs *fs,const unsigned long *a) {
    unsigned command=(unsigned)a[0];
    union bpf_attr attr={0}; size_t known=0;
    switch (command) {
    case BPF_MAP_CREATE: known=offsetof(union bpf_attr,map_name)+sizeof(attr.map_name); break;
    case BPF_MAP_LOOKUP_ELEM: case BPF_MAP_UPDATE_ELEM: case BPF_MAP_DELETE_ELEM: case BPF_MAP_GET_NEXT_KEY:
        known=offsetof(union bpf_attr,flags)+sizeof(attr.flags); break;
    case BPF_PROG_LOAD: known=offsetof(union bpf_attr,expected_attach_type)+sizeof(attr.expected_attach_type); break;
    case BPF_PROG_QUERY: known=offsetof(union bpf_attr,query.prog_cnt)+sizeof(attr.query.prog_cnt); break;
    case BPF_PROG_ATTACH: case BPF_PROG_DETACH:
        known=offsetof(union bpf_attr,replace_bpf_fd)+sizeof(attr.replace_bpf_fd); break;
    case BPF_PROG_GET_FD_BY_ID: case BPF_MAP_GET_FD_BY_ID:
        known=offsetof(union bpf_attr,open_flags)+sizeof(attr.open_flags); break;
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
    struct delivery d={.command=command,.address=a[1],.attr=&attr};
    if (command==BPF_MAP_CREATE) {
        if (attr.inner_map_fd || attr.numa_node) return -EOPNOTSUPP;
        input.header.type=attr.map_type; input.header.key_size=attr.key_size;
        input.header.value_size=attr.value_size; input.header.count=attr.max_entries;
        input.header.flags=attr.map_flags; memcpy(input.header.name,attr.map_name,sizeof(attr.map_name));
        q.flags=O_RDWR|O_CLOEXEC;
    } else if (md_bpf_element(command)) {
        struct md_bpf_info info;
        r=object_info(fs,(int)attr.map_fd,&info); if (r<0) return r;
        if (info.kind!=MD_BPF_INFO_MAP) return -EINVAL;
        if (attr.flags && (command!=BPF_MAP_UPDATE_ELEM || attr.flags>BPF_EXIST)) return -EINVAL;
        input.header.flags=(uint32_t)attr.flags;
        input.header.key_size=info.value.map.key_size; input.header.value_size=info.value.map.value_size;
        if (input.header.key_size>MD_BPF_MAP_KEY_MAX || input.header.value_size>MD_BPF_MAP_VALUE_MAX) return -EPROTO;
        unsigned char *bytes=(void *)input.instructions;
        if (attr.key || command!=BPF_MAP_GET_NEXT_KEY) {
            r=md_read_memory(bytes,(const void *)(uintptr_t)attr.key,input.header.key_size); if (r<0) return r;
            input.header.count=1; q.value_size+=input.header.key_size;
        }
        if (command==BPF_MAP_UPDATE_ELEM) {
            r=md_read_memory(bytes+input.header.key_size,(const void *)(uintptr_t)attr.value,input.header.value_size);
            if (r<0) return r;
            q.value_size+=input.header.value_size;
        }
        q.capacity=command==BPF_MAP_LOOKUP_ELEM ? input.header.value_size
            : command==BPF_MAP_GET_NEXT_KEY ? input.header.key_size : 0;
        q.directory[0]=(int)attr.map_fd;
    } else if (command==BPF_PROG_LOAD) {
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
        r=resolve_maps(fs,input.instructions,attr.insn_cnt); if (r<0) return r;
        q.value_size+=bytes; q.flags=O_RDWR|O_CLOEXEC;
    } else if (command==BPF_PROG_GET_FD_BY_ID || command==BPF_MAP_GET_FD_BY_ID) {
        if (attr.next_id || attr.open_flags) return -EINVAL;
        input.header.id=attr.prog_id; q.flags=O_RDWR|O_CLOEXEC;
    } else if (command==BPF_OBJ_GET_INFO_BY_FD) {
        r=md_read_memory(&d.wanted,(const void *)(uintptr_t)attr.info.info,
            attr.info.info_len<sizeof(d.wanted) ? attr.info.info_len : sizeof(d.wanted));
        if (r<0) return r;
        size_t bytes=d.wanted.xlated_prog_len;
        if (bytes>MD_BPF_INSTRUCTIONS_MAX*sizeof(struct bpf_insn)) bytes=MD_BPF_INSTRUCTIONS_MAX*sizeof(struct bpf_insn);
        q.directory[0]=(int)attr.info.bpf_fd; q.capacity=sizeof(struct md_bpf_info);
        q.capacity+=bytes;
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
    r=md_fs_call_deliver(fs->endpoint,5000,&q,&out,q.capacity ? deliver : NULL,&d);
    if (r>=0) r=out.result.error;
    if (r<0) return r;
    if (md_bpf_opens(command)) return md_namespace_open_result(&out.result,O_RDWR|O_CLOEXEC);
    return r<0 ? r : 0;
}

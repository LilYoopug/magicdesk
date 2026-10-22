#ifndef MD_BPF_REQUEST_H
#define MD_BPF_REQUEST_H
#include <linux/bpf.h>
#include <stdint.h>
enum { MD_BPF_INSTRUCTIONS_MAX=4096, MD_BPF_QUERY_MAX=4096,
    MD_BPF_MAP_KEY_MAX=512, MD_BPF_MAP_VALUE_MAX=4096, MD_BPF_MAPS_PER_PROGRAM=64 };
struct md_bpf_request { uint32_t flags,id,count,type,key_size,value_size; char name[BPF_OBJ_NAME_LEN]; };
struct md_bpf_query { uint32_t count,flags; };
enum { MD_BPF_INFO_PROGRAM=1, MD_BPF_INFO_MAP=2 };
struct md_bpf_info {
    uint32_t kind;
    union { struct bpf_prog_info program; struct bpf_map_info map; } value;
    uint32_t maps[MD_BPF_MAPS_PER_PROGRAM];
};
static inline int md_bpf_opens(unsigned command) {
    return command==BPF_PROG_LOAD || command==BPF_PROG_GET_FD_BY_ID
        || command==BPF_MAP_CREATE || command==BPF_MAP_GET_FD_BY_ID;
}
static inline int md_bpf_element(unsigned command) {
    return command==BPF_MAP_LOOKUP_ELEM || command==BPF_MAP_UPDATE_ELEM
        || command==BPF_MAP_DELETE_ELEM || command==BPF_MAP_GET_NEXT_KEY;
}
static inline int md_bpf_program_type(unsigned type) {
    return type==BPF_PROG_TYPE_CGROUP_DEVICE || type==BPF_PROG_TYPE_CGROUP_SKB;
}
#endif

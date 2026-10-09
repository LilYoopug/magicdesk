#ifndef MD_BPF_REQUEST_H
#define MD_BPF_REQUEST_H
#include <linux/bpf.h>
#include <stdint.h>
enum { MD_BPF_INSTRUCTIONS_MAX=4096, MD_BPF_QUERY_MAX=4096 };
struct md_bpf_request { uint32_t flags,id,count,type; char name[BPF_OBJ_NAME_LEN]; };
struct md_bpf_query { uint32_t count,flags; };
static inline int md_bpf_opens(unsigned command) {
    return command==BPF_PROG_LOAD || command==BPF_PROG_GET_FD_BY_ID;
}
static inline int md_bpf_program_type(unsigned type) {
    return type==BPF_PROG_TYPE_CGROUP_DEVICE || type==BPF_PROG_TYPE_CGROUP_SKB;
}
#endif

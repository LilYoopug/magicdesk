#ifndef MD_BPF_HANDLE_H
#define MD_BPF_HANDLE_H
#include "control_file.h"

struct md_bpf_handle_type { void *(*retain)(void *); void (*release)(void *); };
int md_bpf_handle_open(const struct md_bpf_handle_type *,void *,const struct md_identity *,
    const struct md_control_file_ops **,void **);
void *md_bpf_handle_object(struct md_control_file,const struct md_bpf_handle_type *);
#endif

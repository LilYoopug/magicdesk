#ifndef MD_CGROUP_PROGRAM_H
#define MD_CGROUP_PROGRAM_H
#include "control_file.h"
#include "bpf_request.h"

/* Logical device programs in the permissive cgroup provider. No host BPF
 * program is loaded and no resource or device restriction is enforced. */
enum { MD_CGROUP_PROGRAM_ATTACHMENTS=64 };
struct md_cgroup_programs;
struct md_cgroup_program;
struct md_cgroup_programs *md_cgroup_programs_new(void);
struct md_cgroup_programs *md_cgroup_programs_retain(struct md_cgroup_programs *);
void md_cgroup_programs_release(struct md_cgroup_programs *);
struct md_cgroup_program *md_cgroup_program_new(struct md_cgroup_programs *,
    unsigned,const struct bpf_insn *,unsigned,const char *);
struct md_cgroup_program *md_cgroup_program_retain(struct md_cgroup_program *);
void md_cgroup_program_release(struct md_cgroup_program *);
struct md_cgroup_program *md_cgroup_program_find(struct md_cgroup_programs *,uint32_t);
uint32_t md_cgroup_program_id(const struct md_cgroup_program *);
unsigned md_cgroup_program_type(const struct md_cgroup_program *);
int md_cgroup_program_belongs(const struct md_cgroup_program *,const struct md_cgroup_programs *);
void md_cgroup_program_info(const struct md_cgroup_program *,struct bpf_prog_info *);
struct md_cgroup_program *md_cgroup_program_control(struct md_control_file);
int md_cgroup_program_open(struct md_cgroup_program *,const struct md_identity *,
    const struct md_control_file_ops **,void **);
#endif

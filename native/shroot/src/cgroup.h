#ifndef MD_CGROUP_H
#define MD_CGROUP_H
#include "control_file.h"
#include "pid_namespace.h"
#include "fs_anchor.h"
struct md_cgroup_member;
struct md_cgroup_view;
struct md_cgroup_namespace;
struct md_cgroup_programs;
struct md_cgroup_program;
struct md_cgroup_programs *md_cgroup_program_registry(struct md_cgroup_member *,int create);
int md_cgroup_program_query(struct md_cgroup_view *,int,struct md_cgroup_member *,
    const struct md_identity *,unsigned,uint32_t *,unsigned,unsigned *,unsigned *);
int md_cgroup_program_attach(struct md_cgroup_view *,int,struct md_cgroup_member *,
    const struct md_identity *,struct md_cgroup_program *,unsigned,int detach);
struct md_cgroup_namespace *md_cgroup_namespace_new(struct md_cgroup_member *,struct md_user_namespace *);
struct md_cgroup_namespace *md_cgroup_namespace_retain(struct md_cgroup_namespace *);
void md_cgroup_namespace_release(struct md_cgroup_namespace *);
uint64_t md_cgroup_namespace_inode(const struct md_cgroup_namespace *);
const struct md_user_namespace *md_cgroup_namespace_owner(const struct md_cgroup_namespace *);
struct md_cgroup_member *md_cgroup_member_new(void);
struct md_cgroup_member *md_cgroup_member_fork(struct md_cgroup_member *);
struct md_cgroup_member *md_cgroup_member_retain(struct md_cgroup_member *);
void md_cgroup_member_release(struct md_cgroup_member *);
void md_cgroup_member_publish(struct md_cgroup_member *,pid_t,pid_t,struct md_pid_identity *,struct md_pid_identity *);
void md_cgroup_member_depart(struct md_cgroup_member *,pid_t);
/* One hierarchy of each kind per launch; mounts and open files retain it.
 * devices=0 is cgroup v2 with logical, non-enforcing pids policy, devices=1 is the
 * permissive v1 devices hierarchy. Android cgroups are never opened. */
struct md_cgroup_view *md_cgroup_mount(struct md_cgroup_member *,int parent,int devices,
    const struct md_identity *);
struct md_cgroup_view *md_cgroup_retain(struct md_cgroup_view *);
void md_cgroup_release(struct md_cgroup_view *);
/* Returns an owned O_PATH root, selected under the hierarchy lock. */
int md_cgroup_open_root(struct md_cgroup_view *,const struct md_cgroup_namespace *);
int md_cgroup_devices(const struct md_cgroup_view *);
unsigned long md_cgroup_filesystem(struct md_cgroup_view *);
int md_cgroup_stat(struct md_cgroup_view *,int,struct stat *);
int md_cgroup_mkdir(struct md_cgroup_view *,int,const char *,const struct md_identity *);
int md_cgroup_rmdir(struct md_cgroup_view *,int,const char *,const struct md_identity *);
int md_cgroup_open(struct md_cgroup_view *,int,int,const struct md_identity *,struct md_fs_anchor *,
    const struct md_control_file_ops **,void **);
long md_cgroup_member_text(struct md_cgroup_member *,const struct md_cgroup_namespace *,char *,size_t);
long md_cgroup_controllers_text(struct md_cgroup_member *,char *,size_t);
#endif

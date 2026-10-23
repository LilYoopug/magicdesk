#ifndef MD_DEVPTS_VIEW_H
#define MD_DEVPTS_VIEW_H
#include "guest_identity.h"
#include "mount_policy.h"
#include <sys/stat.h>
struct md_devpts;
struct md_devpts *md_devpts_new(int parent,const char *,const struct md_identity *);
struct md_user_namespace *md_devpts_owner(struct md_devpts *);
struct md_mount_policy *md_devpts_super_policy(struct md_devpts *);
int md_devpts_reconfigure(struct md_devpts *,const char *,const struct md_identity *);
int md_devpts_root(struct md_devpts *);
int md_devpts_name(struct md_devpts *,int fd,char *,size_t);
struct md_devpts *md_devpts_retain(struct md_devpts *);
void md_devpts_release(struct md_devpts *);
int md_devpts_step(struct md_devpts *,int directory,const char *);
int md_devpts_open(struct md_devpts *,int fd,int flags,const struct md_identity *);
int md_devpts_stat(struct md_devpts *,int fd,struct stat *);
int md_devpts_access(struct md_devpts *,int fd,int mode,const struct md_identity *);
int md_devpts_chmod(struct md_devpts *,int fd,mode_t,const struct md_identity *);
int md_devpts_chown(struct md_devpts *,int fd,uint32_t,uint32_t,const struct md_identity *);
ssize_t md_devpts_getdents(struct md_devpts *,int fd,void *,size_t);
#endif

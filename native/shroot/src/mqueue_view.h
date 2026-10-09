#ifndef MD_MQUEUE_VIEW_H
#define MD_MQUEUE_VIEW_H
#include "guest_identity.h"
#include <sys/stat.h>
struct md_mqueue_view;
struct md_mqueue_view *md_mqueue_view_new(int,const struct md_user_namespace *);
void md_mqueue_view_free(struct md_mqueue_view *);
int md_mqueue_root(const struct md_mqueue_view *);
int md_mqueue_stat(const struct md_mqueue_view *,int,struct stat *);
int md_mqueue_chmod(struct md_mqueue_view *,int,mode_t,const struct md_identity *);
int md_mqueue_chown(struct md_mqueue_view *,int,uint32_t,uint32_t,const struct md_identity *);
#endif

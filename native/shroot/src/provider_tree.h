#ifndef MD_PROVIDER_TREE_H
#define MD_PROVIDER_TREE_H
#include "control_file.h"
#include <sys/types.h>
struct md_provider_tree;
struct md_provider_tree_ops {
    void *(*retain)(void *);
    void (*release)(void *);
    /* Return 1 with an owned control, 0 for an ordinary node, or -errno. */
    int (*control)(void *,int fd,struct md_control_file *);
    unsigned long filesystem;
};
/* A retained private provider over a read-through host tree. Only declared
 * opaque subtrees hide host entries. All other lookup remains live, including
 * sysfs entries added by Android after launch. No host file is modified. */
struct md_provider_tree *md_provider_tree_new(int parent,int lower,const char *const *opaque,
    unsigned opaque_count,const struct md_provider_tree_ops *,void *);
struct md_provider_tree *md_provider_tree_retain(struct md_provider_tree *);
void md_provider_tree_release(struct md_provider_tree *);
int md_provider_tree_root(struct md_provider_tree *);
int md_provider_tree_step(struct md_provider_tree *,int directory,const char *);
int md_provider_tree_path(struct md_provider_tree *,int fd,char *,size_t);
ssize_t md_provider_tree_getdents(struct md_provider_tree *,int fd,void *,size_t);
int md_provider_tree_control(struct md_provider_tree *,int fd,struct md_control_file *);
int md_provider_tree_private(struct md_provider_tree *,int fd);
unsigned long md_provider_tree_filesystem(struct md_provider_tree *);
#endif

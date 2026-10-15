#ifndef MD_INODE_LEAF_H
#define MD_INODE_LEAF_H
#include <sys/stat.h>
struct md_inode_store;
struct mdi_node;
void mdi_leaf_id(const struct stat *,char out[33]);
int mdi_leaf_lookup(struct md_inode_store *,const char *parent,const char *name,struct mdi_node *);
int mdi_leaf_descriptor(struct md_inode_store *,int,const struct stat *,struct mdi_node *);
int mdi_leaf_promote(struct md_inode_store *,struct mdi_node *);
ssize_t mdi_leaf_attribute(struct md_inode_store *,const struct mdi_node *,int capability,void *,size_t);
int mdi_leaf_attribute_set(struct md_inode_store *,const struct mdi_node *,int capability,const void *,size_t,mode_t);
int mdi_leaf_import_attributes(struct md_inode_store *,const struct mdi_node *,int fd);
int mdi_leaf_list(struct md_inode_store *,const struct mdi_node *,int (*)(const char *,void *),void *);
int mdi_leaf_materialize(struct md_inode_store *);
void mdi_leaf_admit(struct md_inode_store *);
int mdi_leaf_create(struct md_inode_store *,const struct mdi_node *,const char *,int flags,mode_t);
#endif

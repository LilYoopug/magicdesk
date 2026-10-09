#ifndef MD_PRIVATE_TREE_H
#define MD_PRIVATE_TREE_H
/* Caller owns a private or exclusively detached tree. Never follows symlinks. */
int md_private_tree_discard(int parent, const char *name);
#endif

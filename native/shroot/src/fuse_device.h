#ifndef MD_FUSE_DEVICE_H
#define MD_FUSE_DEVICE_H
#include "control_file.h"
struct md_fuse_connection;
int md_fuse_device_node(struct md_control_file *);
int md_fuse_device_is_node(struct md_control_file);
/* Borrowed connection only from a captured typed open description. Never infer
 * it from a guest FD number, path string or the anonymous carrier's inode. */
struct md_fuse_connection *md_fuse_device_connection(struct md_control_file);
#endif

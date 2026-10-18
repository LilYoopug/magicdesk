#ifndef MD_DEVICE_TREE_H
#define MD_DEVICE_TREE_H
#include "control_file.h"
struct md_provider_tree;
/* Shared /dev projection. Device producers publish typed nodes; the registry
 * owns their carrier identities and does not implement device protocols. */
struct md_provider_tree *md_device_tree_new(int parent,int hide_native_input);
/* Only the stateless FUSE device template is reconstructible. Live input or
 * open-device authorities remain process-local and are never serialized. */
int md_device_tree_portable(const struct md_provider_tree *);
struct md_provider_tree *md_device_tree_import(int upper);
int md_device_tree_publish(struct md_provider_tree *,const char *,struct md_control_file);
/* Returns 1 removed, 0 absent, or -errno. Existing open descriptions survive. */
int md_device_tree_remove(struct md_provider_tree *,const char *);
struct md_filesystem;
int md_fs_devices_prepare(struct md_filesystem *,int hide_native_input,struct md_provider_tree **);
#endif

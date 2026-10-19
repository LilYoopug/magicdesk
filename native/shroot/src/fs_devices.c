#define _GNU_SOURCE
#include "device_tree.h"
#include "fuse_device.h"
#include "render_device.h"
#include "fs_mount_internal.h"
#include "inode_lifetime.h"
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

int md_fs_devices_prepare(struct md_filesystem *fs,int hide_native_input,struct md_provider_tree **out) {
    *out=NULL;
    int initial=md_mount_namespace_initial_boundary(fs->mounts)!=NULL;
    int parent=md_fs_private_mounts_parent(fs->store);
    if (parent<0) return parent;
    struct md_provider_tree *dev=md_device_tree_new(parent,hide_native_input);
    int error=dev ? 0 : -errno; close(parent);
    struct md_control_file fuse={0};
    if (!error) error=md_fuse_device_node(&fuse);
    if (!error) error=md_device_tree_publish(dev,"fuse",fuse);
    md_control_file_release(fuse);
    if (!error && fs->render_device.ops) {
        char path[32]; snprintf(path,sizeof(path),"dri/renderD%u",md_render_device_minor(fs->render_device));
        if (mkdirat(md_provider_tree_root(dev),"dri",0755)) error=-errno;
        if (!error) error=md_device_tree_publish(dev,path,fs->render_device);
    }
    /* /dev/shm keeps its inode namespace, independently of device discovery. */
    struct md_view_location shm={.fd=-1,.parent=-1},target={.fd=-1,.parent=-1};
    if (!error) error=md_view_walk(fs,-1,NULL,"/dev/shm",1,0,0,&shm);
    if (!error && !md_view_inode(shm.mount)) error=-EOPNOTSUPP;
    struct md_mount_source source={.fd=shm.fd,.backing=MD_MOUNT_INODE,
        .storage=shm.mount && shm.mount->storage ? shm.mount->storage : md_inode_store_lifetime(fs->store)};
    if (!error) error=md_fs_provider_mount(fs,dev,"/dev");
    if (!error) error=md_view_walk(fs,-1,NULL,"/dev/shm",1,0,MD_VIEW_MOUNT_TARGET,&target);
    if (!error) error=md_view_attach_source(fs,&source,&target,NULL);
    if (!error && initial) error=md_fs_initial_boundaries_capture(fs);
    md_view_location_close(&target); md_view_location_close(&shm);
    if (error) md_provider_tree_release(dev); else *out=dev;
    return error;
}

#define _GNU_SOURCE
#include "host_fs_view.h"
#include "provider_tree.h"
#include "sysfs_view.h"
#include "device_tree.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <unistd.h>

static const struct md_provider_tree_ops sys_ops={.filesystem=SYSFS_MAGIC,
    .lower_visible=md_sysfs_host_visible,.readonly=1};
static const struct md_provider_tree_ops dev_ops={.filesystem=TMPFS_MAGIC};
enum md_host_fs_view md_host_fs_kind(const struct md_provider_tree *tree) {
    return md_provider_tree_matches(tree,&sys_ops) ? MD_HOST_FS_SYS
        : md_provider_tree_matches(tree,&dev_ops) ? MD_HOST_FS_DEV
        : md_device_tree_portable(tree) ? MD_HOST_FS_DEVICES : MD_HOST_FS_NONE;
}
static struct md_provider_tree *create(int parent,int upper,enum md_host_fs_view kind) {
    if (kind!=MD_HOST_FS_SYS && kind!=MD_HOST_FS_DEV) { errno=EINVAL; return NULL; }
    int lower=open(kind==MD_HOST_FS_SYS ? "/sys" : "/dev",O_PATH|O_DIRECTORY|O_CLOEXEC);
    const struct md_provider_tree_ops *ops=kind==MD_HOST_FS_SYS ? &sys_ops : &dev_ops;
    struct md_provider_tree *tree=upper>=0 ? md_provider_tree_import(upper,lower,ops)
        : md_provider_tree_new(parent,lower,NULL,0,ops,NULL);
    int saved=errno; if (lower>=0) close(lower); errno=saved;
    return tree;
}
struct md_provider_tree *md_host_fs_import(int upper,enum md_host_fs_view kind) {
    if (kind==MD_HOST_FS_DEVICES) return md_device_tree_import(upper);
    return create(-1,upper,kind);
}
struct md_provider_tree *md_host_fs_new(int parent,enum md_host_fs_view kind) {
    struct md_provider_tree *tree=create(parent,-1,kind);
    if (!tree) return NULL;
    const char *sys[]={"block","bus","class","devices","dev","dev/block","dev/char","fs","fs/cgroup"};
    /* Stable guest mountpoints avoid exporting restricted Android directory
     * handles. The provider still merges native pts children until covered. */
    const char *dev[]={"shm","pts"};
    const char **dirs=kind==MD_HOST_FS_SYS ? sys : dev;
    unsigned count=kind==MD_HOST_FS_SYS ? sizeof(sys)/sizeof(*sys) : sizeof(dev)/sizeof(*dev);
    for (unsigned i=0;i<count;++i) if (mkdirat(md_provider_tree_root(tree),dirs[i],0755)) {
        int error=errno; md_provider_tree_release(tree); errno=error; return NULL;
    }
    return tree;
}

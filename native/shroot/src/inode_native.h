#ifndef MD_INODE_NATIVE_H
#define MD_INODE_NATIVE_H
#include <stdint.h>
#include <sys/stat.h>

/* Native leaves belong to an admitted private directory, never an arbitrary
 * host bind. Callers own namespace locking, permissions and watch publication.
 * Regular root-owned files use their native mode without an attribute lookup.
 * A sticky physical mode selects the private metadata record; guest sticky and
 * set-ID bits are values in that record, never kernel privileges. */
#define MDI_NATIVE_METADATA "user.shroot.metadata"
int mdi_native_private_attribute(const char *);
int mdi_native_eligible(uint32_t uid, uint32_t gid, mode_t mode);
/* The process umask is zero; mode already includes the guest creation mask.
 * Ineligible requests have no side effects and use the catalogue allocator. */
int mdi_native_create(int directory, const char *name, int flags,
        uint32_t uid, uint32_t gid, mode_t mode);
int mdi_native_create_in(int objects,const char *parent,const char *name,int flags,
        uint32_t uid,uint32_t gid,mode_t mode);
/* Unpublished ordinary regular file, without a data-open effect. Returns an
 * owned O_PATH pin; EOPNOTSUPP leaves no name and permits prepare/open fallback. */
int mdi_native_pin_create(int directory,const char *name,uint32_t uid,uint32_t gid,mode_t mode);
/* Prepare exceptional metadata under a private, unpublished staging name.
 * The caller publishes by rename only after this succeeds. */
int mdi_native_prepare(int objects,const char *name,int flags,
        uint32_t uid,uint32_t gid,mode_t mode);
/* Borrow a validated leaf FD, including O_PATH and unlinked descriptions. */
int mdi_native_stat(int fd, struct stat *);
int mdi_native_info(int fd, struct stat *, unsigned *acl);
/* Fresh fstat observation of the same retained FD, under the store owner.
 * Reads mutable metadata without a second fstat or pathname resolution. */
int mdi_native_project(int fd, struct stat *, unsigned *acl);
int mdi_native_metadata(int fd, uint32_t uid, uint32_t gid, mode_t mode);
int mdi_native_chown(int fd, uint32_t uid, uint32_t gid, mode_t mode);
ssize_t mdi_native_attribute(int fd, int capability, void *, size_t);
int mdi_native_attribute_set(int fd, int capability, const void *, size_t, mode_t);
#endif

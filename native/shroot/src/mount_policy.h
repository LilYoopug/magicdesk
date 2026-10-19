#ifndef MD_MOUNT_POLICY_H
#define MD_MOUNT_POLICY_H

enum { MD_MOUNT_READONLY=1U, MD_MOUNT_NOSUID=2U, MD_MOUNT_NODEV=4U, MD_MOUNT_NOEXEC=8U,
    MD_MOUNT_NOSYMFOLLOW=16U,
    MD_MOUNT_FLAGS=MD_MOUNT_READONLY|MD_MOUNT_NOSUID|MD_MOUNT_NODEV|MD_MOUNT_NOEXEC|MD_MOUNT_NOSYMFOLLOW,
    MD_MOUNT_LOCK_SHIFT=16,
    MD_MOUNT_LOCK_READONLY=MD_MOUNT_READONLY<<MD_MOUNT_LOCK_SHIFT,
    MD_MOUNT_LOCK_NOSUID=MD_MOUNT_NOSUID<<MD_MOUNT_LOCK_SHIFT,
    MD_MOUNT_LOCK_NODEV=MD_MOUNT_NODEV<<MD_MOUNT_LOCK_SHIFT,
    MD_MOUNT_LOCK_NOEXEC=MD_MOUNT_NOEXEC<<MD_MOUNT_LOCK_SHIFT,
    MD_MOUNT_LOCKABLE=MD_MOUNT_READONLY|MD_MOUNT_NOSUID|MD_MOUNT_NODEV|MD_MOUNT_NOEXEC,
    MD_MOUNT_LOCKS=MD_MOUNT_LOCKABLE<<MD_MOUNT_LOCK_SHIFT,
    MD_MOUNT_POLICY_MASK=MD_MOUNT_FLAGS|MD_MOUNT_LOCKS };
struct md_mount_policy_page;
/* Capture native constraints before adopting an already admitted descriptor. */
int md_mount_native_policy(int fd, unsigned *flags);
/* Owned by one mount. Local until explicitly shared; imported mappings are
 * read-only observers, not authority to remount. Never copy this by assignment. */
struct md_mount_policy {
    unsigned local;
    struct md_mount_policy_page *page;
    int fd, writer;
};
unsigned md_mount_policy_shared_flags(const struct md_mount_policy *);
static inline unsigned md_mount_policy_flags(const struct md_mount_policy *p) {
    return p->page ? md_mount_policy_shared_flags(p) : p->local;
}
int md_mount_policy_set(struct md_mount_policy *, unsigned flags);
/* Worker-only preflight; neither allocates nor changes policy. */
int md_mount_policy_check(const struct md_mount_policy *, unsigned flags);
int md_mount_policy_lock(struct md_mount_policy *);
/* Worker-only, lazy publication. Returns a borrowed CLOEXEC FD, retained by
 * this policy until close. Send only over a verified private channel. Failure
 * preserves local ownership; ordinary reads never create this descriptor. */
int md_mount_policy_share(struct md_mount_policy *);
/* Consumes a captured descriptor only on success, into an empty policy.
 * Validates the bounded, size/write-sealed layout before exposing its flags.
 * The mapping follows updates from its original writer and outlives that writer.
 * This checks layout/rights, not which mount or store the policy belongs to. */
int md_mount_policy_import(struct md_mount_policy *, int fd);
void md_mount_policy_close(struct md_mount_policy *);
#endif

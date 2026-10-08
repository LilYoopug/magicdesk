#ifndef MD_IDENTITY_SNAPSHOT_H
#define MD_IDENTITY_SNAPSHOT_H
#include "guest_identity.h"

/* Cold authenticated custody transport. The immutable credential snapshot
 * references a separately retained user-namespace policy, never a live task. */
int md_identity_snapshot_export(const struct md_identity *);
int md_identity_snapshot_import(int fd, struct md_user_namespace *, struct md_identity *out);
#endif

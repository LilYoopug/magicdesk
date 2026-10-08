#ifndef MD_NAMESPACE_IDENTITY_H
#define MD_NAMESPACE_IDENTITY_H
#include <stdint.h>

/* Namespace creation is a cold resource boundary. Random nonzero identities
 * remain independent across supervisors and survive custody import. */
int md_namespace_identity_new(uint64_t *);
#endif

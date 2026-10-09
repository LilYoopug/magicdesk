#ifndef MD_FS_LOCATION_H
#define MD_FS_LOCATION_H
#include <stdint.h>

/* Mount instance plus backend object identity, never a pathname. Mount
 * zero selects the inode store; an empty object selects its initial root. */
struct md_fs_location { uint32_t mount; char object[33]; };
#endif

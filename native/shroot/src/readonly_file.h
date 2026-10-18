#ifndef MD_READONLY_FILE_H
#define MD_READONLY_FILE_H
#include "control_file.h"
/* Live, read-only view of an already readable anonymous kernel file. The
 * backing never leaves the provider; the guest carrier has O_PATH authority. */
struct md_control_file md_readonly_file_new(int fd);
#endif

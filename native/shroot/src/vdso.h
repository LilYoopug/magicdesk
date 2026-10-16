#ifndef MD_VDSO_H
#define MD_VDSO_H
#include <stddef.h>
#include <time.h>

typedef int (*md_vdso_clock_fn)(clockid_t,struct timespec *);
/* Only the kernel-provided AT_SYSINFO_EHDR mapping, not an untrusted ELF file.
 * Unsupported layouts or symbol versions select the ordinary syscall fallback. */
md_vdso_clock_fn md_vdso_clock(const void *image,size_t first_page);
#endif

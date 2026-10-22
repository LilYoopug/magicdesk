#ifndef MD_DESCRIPTOR_CALLS_H
#define MD_DESCRIPTOR_CALLS_H
struct md_fs;
enum { MD_DESCRIPTOR_ANONYMOUS=0x10000, MD_DESCRIPTOR_FILESYSTEM };
long md_descriptor_kind(int fd);
/* Interception requirements come from the typed owner, not its proc kind. */
long md_descriptor_duplicate(const struct md_fs *, long nr, const unsigned long *);
long md_descriptor_pair(long nr, const unsigned long *);
long md_descriptor_metadata(const struct md_fs *, int fd, long nr, const unsigned long *);
#endif

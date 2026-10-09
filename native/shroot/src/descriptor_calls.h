#ifndef MD_DESCRIPTOR_CALLS_H
#define MD_DESCRIPTOR_CALLS_H
enum { MD_DESCRIPTOR_ANONYMOUS=0x10000 };
long md_descriptor_kind(int fd);
long md_descriptor_pair(long nr, const unsigned long *);
long md_descriptor_metadata(int fd, long nr, const unsigned long *);
#endif

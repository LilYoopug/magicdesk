#ifndef MD_FILE_CALLS_H
#define MD_FILE_CALLS_H
#include "fs.h"

#include "syscall_catalog.h"

long md_file_call(const struct md_fs *, const char *, long, const unsigned long *);
#endif

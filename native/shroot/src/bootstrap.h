#ifndef MD_BOOTSTRAP_H
#define MD_BOOTSTRAP_H
#include "fs.h"
#include "elf.h"
#include "program_files.h"
#include "host_identity.h"
#include "command.h"
extern struct md_fs md_files;
extern char md_bootstrap[PATH_MAX];
extern char md_executable[PATH_MAX];
long md_guest_execat(const struct md_fs *, int, const char *, char *const [], char *const [], int, unsigned long);
#endif

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
extern char md_hostname[MD_HOSTNAME_SIZE];
long md_guest_exec(const struct md_fs *, const char *, char *const [], char *const []);
long md_guest_execat(const struct md_fs *, int, const char *, char *const [], char *const [], int);
#endif

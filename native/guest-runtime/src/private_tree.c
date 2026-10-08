#define _GNU_SOURCE
#include "private_tree.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int md_private_tree_discard(int parent, const char *name) {
    int ref=openat(parent,name,O_PATH|O_NOFOLLOW|O_CLOEXEC);
    if (ref<0) return errno==ENOENT ? 0 : -errno;
    struct stat st;
    if (fstat(ref,&st)) { int r=-errno; close(ref); return r; }
    if (!S_ISDIR(st.st_mode)) { close(ref); return unlinkat(parent,name,0) ? -errno : 0; }
    char proc[64]; snprintf(proc,sizeof(proc),"/proc/self/fd/%d",ref);
    /* Mode-000 directories still belong to the exclusively retained tree. */
    if (chmod(proc,0700)) { int r=-errno; close(ref); return r; }
    int fd=openat(ref,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC); close(ref);
    if (fd<0) return -errno;
    DIR *dir=fdopendir(fd);
    if (!dir) { int r=-errno; close(fd); return r; }
    int r=0;
    while (!r) {
        errno=0; struct dirent *entry=readdir(dir);
        if (!entry) { if (errno) r=-errno; break; }
        if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        r=md_private_tree_discard(fd,entry->d_name);
    }
    closedir(dir);
    if (!r && unlinkat(parent,name,AT_REMOVEDIR)) r=-errno;
    return r;
}

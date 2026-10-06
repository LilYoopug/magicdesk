#define _GNU_SOURCE
#include "mapping_observation.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

int md_mapping_source(int fd, struct md_mapping_source *source) {
    if (!source) return -EINVAL;
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    *source=(struct md_mapping_source){.device=st.st_dev,.inode=st.st_ino};
    return 0;
}
int md_mapping_observe(int fd, const struct md_mapping_source *source, uintptr_t address,
        size_t size, uint64_t offset) {
    if (fd<0 || !source || !size || address>UINTPTR_MAX-size || offset>UINT64_MAX-size) return -EINVAL;
    if (lseek(fd,0,SEEK_SET)<0) return -errno;
    uintptr_t cursor=address, end=address+size;
    char chunk[4096], line[256]; size_t used=0; int truncated=0;
    for (;;) {
        ssize_t n=read(fd,chunk,sizeof(chunk));
        if (n<0 && errno==EINTR) continue;
        if (n<0) return -errno;
        if (!n) return used ? -EPROTO : 0;
        for (ssize_t i=0;i<n;++i) {
            if (chunk[i]!='\n') {
                if (used+1<sizeof(line)) line[used++]=chunk[i]; else truncated=1;
                continue;
            }
            line[used]=0;
            unsigned long long first,last,position,inode;
            unsigned major_number,minor_number; char permissions[5]; int consumed=0;
            int fields=sscanf(line,"%llx-%llx %4s %llx %x:%x %llu%n",
                &first,&last,permissions,&position,&major_number,&minor_number,&inode,&consumed);
            if (fields!=7 || first>=last || strlen(permissions)!=4
                    || (truncated && consumed==(int)used)) return -EPROTO;
            used=0; truncated=0;
            if (first>cursor) return 0;
            if (last<=cursor) continue;
            uint64_t displacement=cursor-first;
            if (inode!=source->inode || makedev(major_number,minor_number)!=source->device
                    || permissions[3]!='s' || position>UINT64_MAX-displacement
                    || position+displacement!=offset+cursor-address) return 0;
            if (last>=end) return 1;
            cursor=last;
        }
    }
}

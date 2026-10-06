#define _GNU_SOURCE
#include "task_status.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>

long md_task_umask(int tid) {
    if (tid<=0) return -EINVAL;
    char path[64]="/proc/";
    md_decimal(path+md_length(path),(unsigned)tid);
    md_copy(path+md_length(path),sizeof(path)-md_length(path),"/status");
    long fd=RAW4(openat,AT_FDCWD,path,O_RDONLY|O_CLOEXEC,0);
    if (fd<0) return fd;
    char text[1024]; size_t size=0;
    long error=0;
    while (size<sizeof(text)-1) {
        long n=RAW3(read,fd,text+size,sizeof(text)-1-size);
        if (n==-EINTR) continue;
        if (n<0) { error=n; break; }
        if (!n) break;
        size+=(size_t)n;
    }
    RAW1(close,fd);
    if (error) return error;
    text[size]=0;
    for (char *p=text;*p;++p) {
        if ((p!=text && p[-1]!='\n') || !md_prefix(p,"Umask:")) continue;
        p+=6;
        while (*p==' ' || *p=='\t') ++p;
        unsigned mask=0,digits=0;
        while (*p>='0' && *p<='7') {
            if (++digits>4) return -EIO;
            mask=8*mask+(unsigned)(*p++-'0');
        }
        return !digits || *p!='\n' || mask>0777 ? -EIO : (long)mask;
    }
    return -ENOTSUP;
}

#define _GNU_SOURCE
#include "task_status.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>

static long task_status(int tid,char *text,size_t capacity) {
    if (tid<=0) return -EINVAL;
    char path[64]="/proc/";
    md_decimal(path+md_length(path),(unsigned)tid);
    md_copy(path+md_length(path),sizeof(path)-md_length(path),"/status");
    long fd=RAW4(openat,AT_FDCWD,path,O_RDONLY|O_CLOEXEC,0);
    if (fd<0) return fd;
    size_t size=0;
    long error=0;
    while (size<capacity-1) {
        long n=RAW3(read,fd,text+size,capacity-1-size);
        if (n==-EINTR) continue;
        if (n<0) { error=n; break; }
        if (!n) break;
        size+=(size_t)n;
    }
    RAW1(close,fd);
    if (error) return error;
    text[size]=0;
    return (long)size;
}
long md_task_umask(int tid) {
    char text[1024];
    long result=task_status(tid,text,sizeof(text));
    if (result<0) return result;
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
long md_task_parent(int tid) {
    char text[1024];
    long result=task_status(tid,text,sizeof(text));
    if (result<0) return result;
    for (char *p=text;*p;++p) {
        if ((p!=text && p[-1]!='\n') || !md_prefix(p,"PPid:")) continue;
        p+=5;
        while (*p==' ' || *p=='\t') ++p;
        unsigned value=0,digits=0;
        while (*p>='0' && *p<='9') {
            if (++digits>9) return -EIO;
            value=10*value+(unsigned)(*p++-'0');
        }
        return !digits || *p!='\n' ? -EIO : (long)value;
    }
    return -ENOTSUP;
}
long md_task_signal_handlers(int tid,uint64_t *caught) {
    char text[8192];
    long result=task_status(tid,text,sizeof(text));
    if (result<0) return result;
    for (char *p=text;*p;++p) {
        if ((p!=text && p[-1]!='\n') || !md_prefix(p,"SigCgt:")) continue;
        p+=7;
        while (*p==' ' || *p=='\t') ++p;
        uint64_t value=0; unsigned digits=0;
        while (*p && *p!='\n') {
            unsigned digit=*p>='0' && *p<='9' ? (unsigned)(*p-'0')
                : *p>='a' && *p<='f' ? (unsigned)(*p-'a'+10) : 16;
            if (digit>=16 || ++digits>16) return -EIO;
            value=(value<<4)|digit; ++p;
        }
        if (!digits || *p!='\n') return -EIO;
        *caught=value; return 0;
    }
    return -ENOTSUP;
}

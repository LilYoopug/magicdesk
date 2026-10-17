#define _GNU_SOURCE
#include "task_status.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>

long md_task_status_open(int tid) {
    if (tid<=0) return -EINVAL;
    char path[64]="/proc/";
    md_decimal(path+md_length(path),(unsigned)tid);
    md_copy(path+md_length(path),sizeof(path)-md_length(path),"/status");
    return RAW4(openat,AT_FDCWD,path,O_RDONLY|O_CLOEXEC,0);
}
static long read_status(int fd,char *text,size_t capacity) {
    size_t size=0;
    long error=0;
    while (size<capacity-1) {
        long n=RAW4(pread64,fd,text+size,capacity-1-size,size);
        if (n==-EINTR) continue;
        if (n<0) { error=n; break; }
        if (!n) break;
        size+=(size_t)n;
    }
    if (error) return error;
    text[size]=0;
    return (long)size;
}
static long task_status(int tid,char *text,size_t capacity) {
    long fd=md_task_status_open(tid);
    if (fd<0) return fd;
    long result=read_status((int)fd,text,capacity);
    RAW1(close,fd);
    return result;
}
long md_task_umask_fd(int fd) {
    char text[1024];
    long result=read_status(fd,text,sizeof(text));
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
long md_task_umask(int tid) {
    long fd=md_task_status_open(tid);
    if (fd<0) return fd;
    long result=md_task_umask_fd((int)fd);
    RAW1(close,fd);
    return result;
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

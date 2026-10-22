#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    int fd=(int)syscall(SYS_pidfd_open,getpid(),0);
    if (fd<0) { perror("pidfd_open"); return 1; }
    struct stat st={0};
    struct statfs fs={0};
    int r=fstat(fd,&st);
    printf("fstat=%d errno=%d device=%llu inode=%llu mode=%o\n",r,r ? errno : 0,
        (unsigned long long)st.st_dev,(unsigned long long)st.st_ino,st.st_mode);
    r=fstatfs(fd,&fs);
    printf("fstatfs=%d errno=%d type=%lx block=%lu name=%lu flags=%lu\n",r,r ? errno : 0,
        r ? 0 : (unsigned long)fs.f_type,r ? 0 : (unsigned long)fs.f_bsize,
        r ? 0 : (unsigned long)fs.f_namelen,r ? 0 : (unsigned long)fs.f_flags);
    char path[64],text[1024];
    snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
    ssize_t n=readlink(path,text,sizeof(text)-1);
    if (n>=0) { text[n]=0; printf("link=%s\n",text); } else perror("readlink");
    close(fd);
    return r ? 1 : 0;
}

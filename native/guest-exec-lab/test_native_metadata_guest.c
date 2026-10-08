#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <linux/stat.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
int test_native_metadata_guest(void) {
    int fd=syscall(SYS_memfd_create,"metadata",MFD_CLOEXEC|MFD_ALLOW_SEALING); assert(fd>=0);
    assert(!ftruncate(fd,6));
    struct stat st; assert(!fstat(fd,&st));
    for (unsigned i=0;i<2;++i) {
        struct statx x={0}; unsigned mask=STATX_ALL|(i ? STATX_MNT_ID : 0);
        int r=syscall(SYS_statx,fd,"",AT_EMPTY_PATH,mask,&x);
        printf("memfd statx mask=%x result=%d errno=%d returned=%x mount=%llu\n",mask,r,errno,x.stx_mask,(unsigned long long)x.stx_mnt_id);
        fflush(stdout); assert(!r && x.stx_size==6 && x.stx_ino==st.st_ino);
    }
    close(fd); puts("PASS native metadata: anonymous memfd statx"); return 0;
}

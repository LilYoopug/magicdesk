#define _GNU_SOURCE
#include "cooperative_entry.h"
#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc,char **argv) {
    assert(argc==2);
    unsigned (*abi)(void)=dlsym(RTLD_DEFAULT,"shroot_libc_entry_abi");
    if (!strcmp(argv[1],"base")) assert(!abi);
    else {
        assert(abi && abi()==MD_ENTRY_VERSION);
        assert(md_entry_api_valid((const void *)getauxval(MD_AT_COOPERATIVE)));
    }
    int fd=open("/tmp/libc-probe",O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600); assert(fd>=0);
    struct stat st;
    assert(write(fd,"ok",2)==2 && !fstat(fd,&st) && st.st_size==2);
    assert(!close(fd) && !rename("/tmp/libc-probe","/tmp/libc-moved") && !unlink("/tmp/libc-moved"));
    printf("PASS libc selection: %s\n",argv[1]); return 0;
}

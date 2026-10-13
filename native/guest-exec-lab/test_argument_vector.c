#define _GNU_SOURCE
#include "arguments.h"
#include "raw.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    md_page_size=(size_t)sysconf(_SC_PAGESIZE);
    struct md_arguments a;
    md_arguments_init(&a);
    assert(!md_arguments_read(&a,NULL) && !a.count && a.values==a.local);
    char *small[]={"program","", "last",NULL};
    assert(!md_arguments_read(&a,small) && a.count==3 && a.values==a.local);
    assert(!memcmp(a.values,small,sizeof(small)));
    md_arguments_close(&a);
    size_t count=16384;
    char **many=calloc(count+1,sizeof(*many)); assert(many);
    for (size_t i=0;i<count;++i) many[i]=i%2 ? "" : "value";
    assert(!md_arguments_read(&a,many) && a.count==count && a.values!=a.local);
    assert(!memcmp(a.values,many,(count+1)*sizeof(*many)));
    assert(md_arguments_reserve(&a,MD_EXEC_POINTERS+1)==-E2BIG);
    assert(a.count==count && !memcmp(a.values,many,(count+1)*sizeof(*many)));
    md_arguments_close(&a); md_arguments_close(&a); free(many);
    char *pages=mmap(NULL,2*md_page_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(pages!=MAP_FAILED && !mprotect(pages+md_page_size,md_page_size,PROT_NONE));
    /* Read up to a NULL at the last readable byte, including unaligned argv. */
    for (unsigned skew=0;skew<sizeof(char *);++skew) {
        char *end=pages+md_page_size-skew;
        memcpy(end-sizeof(small),small,sizeof(small));
        assert(!md_arguments_read(&a,(char **)(end-sizeof(small))) && a.count==3);
        md_arguments_close(&a);
    }
    memset(pages,1,md_page_size);
    assert(md_arguments_read(&a,(char **)pages)==-EFAULT);
    assert(a.count && a.values!=a.local);
    md_arguments_close(&a);
    assert(!munmap(pages,2*md_page_size));
    puts("PASS argument vector: inline, growth, ceiling, page boundary, EFAULT and idempotent cleanup");
}

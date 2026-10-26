#define _GNU_SOURCE
#include "interception_memory.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static int fail_malloc;
void *__real_malloc(size_t);
void *__wrap_malloc(size_t size) {
    if (fail_malloc) { errno=ENOMEM; return NULL; }
    return __real_malloc(size);
}
static void file_custody(void) {
    int fd=memfd_create("mapping-fork",MFD_CLOEXEC);
    assert(fd>=0 && !ftruncate(fd,4096));
    struct md_interception_memory *parent=md_memory_new();
    struct md_mapping_change change={0};
    assert(parent);
    assert(!md_memory_mapping_prepare(parent,&change,MD_MAPPING_MAP,0x10000,4096,0,MAP_PRIVATE,0));
    assert(!md_memory_mapping_backing(parent,&change,fd,0));
    md_memory_mapping_finish(parent,&change,0x10000);
    close(fd);
    fail_malloc=1;
    assert(!md_memory_fork(parent,0));
    fail_malloc=0;
    uint64_t offset=UINT64_MAX;
    assert(md_memory_file_view(parent,0x10000,4096,&fd,&offset)==1 && offset==0);
    struct md_interception_memory *child=md_memory_fork(parent,0);
    assert(child);
    md_memory_release(parent);
    assert(md_memory_file_view(child,0x10000,4096,&fd,&offset)==1 && offset==0);
    struct stat st;
    assert(!fstat(fd,&st) && st.st_size==4096);
    md_memory_release(child);
}
static void backing_reuse(void) {
    char temporary[]="/data/local/tmp/mapping-reuse-XXXXXX";
    int fd=mkstemp(temporary);
    char denied[]="/data/local/tmp/mapping-denied-XXXXXX";
    int other=mkstemp(denied);
    size_t page=(size_t)getpagesize();
    assert(fd>=0 && other>=0 && !ftruncate(fd,2*page) && !unlink(temporary));
    assert(!unlink(denied));
    char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
    int pin=open(path,O_PATH|O_CLOEXEC);
    assert(pin>=0);
    struct md_interception_memory *memory=md_memory_new();
    struct md_mapping_change first={0},next={0};
    assert(memory && !md_memory_mapping_prepare(memory,&first,MD_MAPPING_MAP,0x10000,page,0,MAP_PRIVATE,0));
    int vacant=fcntl(pin,F_DUPFD_CLOEXEC,0);
    assert(vacant>=0 && !close(vacant));
    fail_malloc=1;
    int failed=md_memory_mapping_pin(memory,&first,pin,0);
    fail_malloc=0;
    assert(failed==-ENOMEM && !first.backing);
    int available=fcntl(pin,F_DUPFD_CLOEXEC,0);
    assert(available==vacant && !close(available));
    assert(md_memory_mapping_pin(memory,&first,pin,0)==1 && first.backing);
    md_memory_mapping_finish(memory,&first,0x10000);
    int source=-1; uint64_t source_offset=UINT64_MAX;
    assert(md_memory_file_view(memory,0x10000,page,&source,&source_offset)==1 && !source_offset);
    assert(!fcntl(fd,F_SETFL,O_APPEND) && lseek(fd,17,SEEK_SET)==17);
    assert((fcntl(source,F_GETFL)&(O_ACCMODE|O_APPEND))==O_RDONLY);
    assert(fcntl(source,F_GETFD)&FD_CLOEXEC);
    assert(lseek(source,0,SEEK_CUR)==0 && lseek(fd,0,SEEK_CUR)==17);
    close(fd);
    assert(!md_memory_mapping_prepare(memory,&next,MD_MAPPING_MAP,0x20000,page,0,MAP_PRIVATE,0));
    assert(md_memory_mapping_pin(memory,&next,pin,1)==-EINVAL && !next.backing);
    int reused=md_memory_mapping_pin(memory,&next,pin,page);
    if (reused!=1) fprintf(stderr,"mapping reuse result=%d\n",reused);
    assert(reused==1 && next.backing);
    /* Native failure releases its provisional reference without removing the
     * first mapping's source or publishing the rejected mapping. */
    md_memory_mapping_finish(memory,&next,-EACCES);
    uint64_t offset;
    assert(!md_memory_file_view(memory,0x20000,page,&fd,&offset));
    assert(md_memory_file_view(memory,0x10000,page,&fd,&offset)==1 && !offset);
    assert(!md_memory_mapping_prepare(memory,&next,MD_MAPPING_MAP,0x20000,page,0,MAP_PRIVATE,0));
    assert(md_memory_mapping_pin(memory,&next,pin,page)==1);
    md_memory_mapping_finish(memory,&next,0x20000);
    assert(!md_memory_mapping_prepare(memory,&first,MD_MAPPING_UNMAP,0x10000,page,0,0,0));
    md_memory_mapping_finish(memory,&first,0);
    assert(md_memory_file_view(memory,0x20000,page,&fd,&offset)==1 && offset==page);
    assert(!md_memory_mapping_prepare(memory,&next,MD_MAPPING_UNMAP,0x20000,page,0,0,0));
    md_memory_mapping_finish(memory,&next,0);
    assert(!md_memory_mapping_prepare(memory,&next,MD_MAPPING_MAP,0x30000,page,0,MAP_PRIVATE,0));
    /* The final mapping releases its source. The independent pin still
     * authenticates the unlinked inode for a new capture. */
    assert(md_memory_mapping_pin(memory,&next,pin,0)==1);
    md_memory_mapping_finish(memory,&next,-ECANCELED);
    assert(!md_memory_mapping_prepare(memory,&next,MD_MAPPING_MAP,0x30000,page,0,MAP_PRIVATE,0));
    assert(!fchmod(other,0));
    assert(md_memory_mapping_pin(memory,&next,other,0)==-EACCES && !next.backing);
    /* A denied reopen does not prevent use of a previously opened source. */
    assert(!md_memory_mapping_backing(memory,&next,other,0) && next.backing);
    md_memory_mapping_finish(memory,&next,-ECANCELED);
    close(pin); close(other); md_memory_release(memory);
    puts("PASS mapping backing pin: unlinked identity, denied access fallback, failure, offsets and final retirement");
    puts("PASS mapping source ownership: independent read-only description and allocation-failure cleanup");
}

int main(void) {
    file_custody();
    backing_reuse();
    struct md_interception_memory *parent = md_memory_new();
    assert(parent && !md_memory_stack_take(parent));
    assert(!md_memory_stack_add(parent, 0x10000));
    struct md_interception_memory *thread = md_memory_fork(parent, 1);
    assert(thread == parent && !md_memory_stack_take(thread));
    assert(!md_memory_stack_add(thread, 0x20000));
    struct md_interception_memory *child = md_memory_fork(parent, 0);
    assert(child && child != parent);
    assert(md_memory_stack_take(child) == 0x10000 && md_memory_stack_take(child) == 0x20000);
    assert(!md_memory_stack_take(child) && !md_memory_stack_take(parent));
    md_memory_stack_return(thread, 0x20000);
    for (unsigned i = 0; i < 10000; i++) {
        assert(md_memory_stack_take(parent) == 0x20000 && !md_memory_stack_take(thread));
        md_memory_stack_return(parent, 0x20000);
    }
    md_memory_release(child);
    md_memory_release(thread);
    md_memory_stack_return(parent, 0x10000);
    assert(md_memory_stack_take(parent) == 0x20000 && md_memory_stack_take(parent) == 0x10000);
    md_memory_release(parent);
    puts("PASS adapter stacks: shared VM, independent fork, concurrent leases and bounded reuse");
    return 0;
}

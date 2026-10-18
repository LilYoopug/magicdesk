#define _GNU_SOURCE
#include "task_mapping.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

void test_task_mapping(void) {
    assert(!md_task_mapping_safe(-1));
    int fd=open("/proc/self/exe",O_RDONLY|O_CLOEXEC); assert(fd>=0);
    assert(md_task_mapping_safe(fd)); close(fd);
    fd=open("/proc/self/exe",O_PATH|O_CLOEXEC); assert(fd>=0);
    assert(!md_task_mapping_safe(fd)); close(fd);
    fd=open("/dev/null",O_RDONLY|O_CLOEXEC); assert(fd>=0);
    assert(!md_task_mapping_safe(fd)); close(fd);
    int pipefd[2]; assert(!pipe(pipefd));
    assert(!md_task_mapping_safe(pipefd[0])); close(pipefd[0]); close(pipefd[1]);
    for (int seal=F_SEAL_WRITE;seal<=F_SEAL_FUTURE_WRITE;seal*=2) {
        if (seal!=F_SEAL_WRITE && seal!=F_SEAL_FUTURE_WRITE) continue;
        fd=(int)syscall(SYS_memfd_create,"mapping-test",MFD_CLOEXEC|MFD_ALLOW_SEALING); assert(fd>=0);
        assert(!ftruncate(fd,4096) && !md_task_mapping_safe(fd));
        assert(!fcntl(fd,F_ADD_SEALS,seal) && !md_task_mapping_safe(fd));
        assert(!fcntl(fd,F_ADD_SEALS,F_SEAL_GROW) && !md_task_mapping_safe(fd));
        assert(!fcntl(fd,F_ADD_SEALS,F_SEAL_SHRINK) && md_task_mapping_safe(fd));
        close(fd);
    }
    puts("PASS task mapping: readonly regular files, immutable sealed authority, reject devices/pipes/paths/mutable files");
}

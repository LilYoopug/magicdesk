#include "interception_memory.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
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

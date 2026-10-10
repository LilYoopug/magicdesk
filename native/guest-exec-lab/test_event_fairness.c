#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static _Atomic unsigned *state;
static void expired(int signal) {
    (void)signal;
    atomic_store(state, 2);
}

int main(void) {
    enum { WORKERS = 16 };
    state = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    assert(state != MAP_FAILED);
    atomic_init(state, 0);
    struct sigaction action = {.sa_handler = expired};
    assert(!sigaction(SIGALRM, &action, NULL));
    int gate[2];
    assert(!pipe2(gate, O_CLOEXEC));
    pid_t children[WORKERS];
    for (unsigned i = 0; i < WORKERS; ++i) {
        children[i] = fork();
        assert(children[i] >= 0);
        if (!children[i]) {
            close(gate[1]);
            char byte;
            /* EVENT_WAIT: parent starts the syscall producers together;
             * the runner's outer deadline cancels failed setup. */
            assert(read(gate[0], &byte, 1) == 1);
            close(gate[0]);
            alarm(10);
            while (!atomic_load(state)) {
                uid_t real, effective, saved;
                assert(!syscall(SYS_getresuid, &real, &effective, &saved));
            }
            _exit(0);
        }
    }
    close(gate[0]);
    char bytes[WORKERS] = {0};
    assert(write(gate[1], bytes, sizeof(bytes)) == sizeof(bytes));
    close(gate[1]);
    /* These task-affine proc opens need worker completion, unlike the hot
     * identity calls. Neither stream may wait for the other to become idle. */
    for (unsigned i = 0; i < 32; ++i) {
        int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
        assert(fd >= 0);
        char buffer[1024];
        assert(read(fd, buffer, sizeof(buffer)) > 0);
        assert(!close(fd));
    }
    unsigned previous = atomic_exchange(state, 1);
    for (unsigned i = 0; i < WORKERS; ++i) {
        int status;
        /* EVENT_WAIT: every owned producer exits; outer deadline bounds cleanup. */
        assert(waitpid(children[i], &status, 0) == children[i]);
        assert(WIFEXITED(status) && !WEXITSTATUS(status));
    }
    assert(previous == 0);
    assert(!munmap(state, 4096));
    puts("PASS worker completions under continuous ptrace stops");
    return 0;
}

#define _GNU_SOURCE
#include <assert.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Two allow-all controls distinguish entering seccomp from losing its
 * arch/syscall allow cache. Neither filter sends a request to userspace. */
static void filter(const char *mode) {
    if (!strcmp(mode, "none")) return;
    assert(!strcmp(mode, "number") || !strcmp(mode, "address"));
    unsigned offset = !strcmp(mode, "number") ? offsetof(struct seccomp_data, nr)
        : offsetof(struct seccomp_data, instruction_pointer);
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offset),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program = {sizeof(code) / sizeof(*code), code};
    assert(!prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    assert(!prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program));
}
static double now(void) {
    struct timespec t;
    assert(!clock_gettime(CLOCK_MONOTONIC, &t));
    return t.tv_sec + t.tv_nsec * 1e-9;
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "child")) return 0;
    assert(argc == 4 || argc == 5);
    const char *workload = argv[1], *policy = argv[3];
    unsigned count = strtoul(argv[2], NULL, 10);
    assert(count && count <= 10000000);
    int fork_only = !strcmp(workload, "fork"), execute = !strcmp(workload, "exec");
    int epoll = !strcmp(workload, "epoll"), poll = !strcmp(workload, "poll");
    assert(fork_only || execute || epoll || poll);
    assert(!execute || argc == 5);
    filter(policy);
    int fd = -1, queue = -1;
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = 42}, received;
    struct pollfd item = {.events = POLLIN};
    if (poll || epoll) {
        fd = eventfd(1, EFD_CLOEXEC | EFD_NONBLOCK);
        assert(fd >= 0);
        item.fd = fd;
        if (epoll) {
            queue = epoll_create1(EPOLL_CLOEXEC);
            assert(queue >= 0 && !epoll_ctl(queue, EPOLL_CTL_ADD, fd, &event));
        }
    }
    double start = now();
    for (unsigned i = 0; i < count; ++i) {
        if (fork_only || execute) {
            pid_t child = fork();
            assert(child >= 0);
            if (!child) {
                if (execute) { execl(argv[4], argv[4], "child", NULL); _exit(127); }
                _exit(0);
            }
            int status;
            /* EVENT_WAIT: exact child exit; caller's deadline bounds the run. */
            assert(waitpid(child, &status, 0) == child);
            assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        } else if (epoll) {
            assert(epoll_wait(queue, &received, 1, 0) == 1);
            assert(received.events == EPOLLIN && received.data.u64 == 42);
        } else {
            struct timespec timeout = {0};
            assert(ppoll(&item, 1, &timeout, NULL) == 1 && item.revents == POLLIN);
        }
    }
    double elapsed = now() - start;
    printf("DISPATCH_BENCH workload=%s count=%u filter=%s seconds=%.9f\n",
        workload, count, policy, elapsed);
    if (queue >= 0) assert(!close(queue));
    if (fd >= 0) assert(!close(fd));
    return 0;
}

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "launch_identity.h"

enum { NO_ADDFD=-1, NO_PRIVATE_CLONE=-2 };
static int execute(const char *supervisor, const char *bootstrap, int denied, int error) {
    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) {
        if (denied) {
            unsigned nr=denied==NO_ADDFD ? SYS_ioctl : denied==NO_PRIVATE_CLONE ? SYS_clone : (unsigned)denied;
            struct sock_filter rules[] = {
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 5),
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_IOCTL_NOTIF_ADDFD, 2, denied==NO_ADDFD ? 3 : 0),
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
                BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_THREAD, 0, denied==NO_PRIVATE_CLONE ? 1 : 0),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (unsigned)error),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            };
            struct sock_fprog program = {sizeof(rules) / sizeof(*rules), rules};
            assert(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
            assert(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) == 0);
        }
        if (bootstrap) execl(supervisor, supervisor, "--deadline-seconds", "10", bootstrap, "--probe", NULL);
        else execl("/system/bin/sh", "sh", "-c", "printf 'independent shell works\\n'", NULL);
        _exit(126);
    }
    int status;
    /* EVENT_WAIT: bounded externally by the fixture timeout; failure never becomes readiness. */
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status));
    return WEXITSTATUS(status);
}

int main(int argc, char **argv) {
    assert(argc == 3 && md_launch_identity(getuid(), geteuid(), getgid(), getegid()));
    assert(md_launch_identity(0, 0, 0, 0));
    assert(md_launch_identity(2000, 2000, 2000, 2000));
    assert(!md_launch_identity(2000, 0, 2000, 0));
    assert(!md_launch_identity(10000, 10000, 10000, 10000));
    const int missing[] = {SYS_pidfd_open, SYS_faccessat2, SYS_seccomp,SYS_close_range,NO_ADDFD,NO_PRIVATE_CLONE};
    for (unsigned i = 0; i < sizeof(missing)/sizeof(*missing); ++i) {
        assert(execute(argv[1], argv[2], missing[i], ENOSYS) == 126);
        assert(execute(NULL, NULL, missing[i], ENOSYS) == 0);
    }
    const int publication_errors[]={EINVAL,EACCES};
    for (unsigned i=0;i<sizeof(publication_errors)/sizeof(*publication_errors);++i) {
        assert(execute(argv[1],argv[2],NO_ADDFD,publication_errors[i])==126);
        assert(execute(NULL,NULL,NO_ADDFD,publication_errors[i])==0);
    }
    assert(execute(argv[1], argv[2], SYS_ptrace, ENOSYS) == 125);
    assert(execute(NULL, NULL, SYS_ptrace, ENOSYS) == 0);
    assert(execute(argv[1], argv[2], 0, 0) == 0);
    puts("PASS capability isolation: unavailable kernel calls reject guest only; parent and shell unaffected");
    return 0;
}

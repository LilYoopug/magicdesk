#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* Minimal init for an isolated QEMU kernel contract, never a guest launcher. */
int main(void) {
    if (getpid() != 1 || getuid() != 0) return 2;
    assert(!mount("devtmpfs", "/dev", "devtmpfs", 0, NULL));
    int console = open("/dev/console", O_RDWR); assert(console >= 0);
    for (int i = 0; i < 3; ++i) assert(dup2(console, i) == i);
    if (console > 2) close(console);
    setvbuf(stdout, NULL, _IONBF, 0);
    assert(!mount("proc", "/proc", "proc", 0, NULL));
    int fd = open("/proc/cmdline", O_RDONLY); assert(fd >= 0);
    char command[1024]; ssize_t n = read(fd, command, sizeof(command)-1); assert(n > 0);
    command[n] = 0; close(fd);
    assert(strstr(command, "magicdesk.kernel_fixture=1"));
    assert(!chown("/work", 1000, 1000));
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        assert(!setgroups(0, NULL)); assert(!setresgid(1000, 1000, 1000));
        assert(!setresuid(1000, 1000, 1000));
        execl("/contract", "kernel-contract", "/work", NULL);
        perror("fixture exec"); _exit(90);
    }
    int status = -1;
    /* EVENT_WAIT: exact contract child exit; host VM deadline bounds a hang. */
    pid_t result;
    do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
    int ok = result == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    printf("%s kernel contract in VM status=%d\n", ok ? "PASS" : "FAIL", status);
    sync(); reboot(RB_POWER_OFF);
    return 1;
}

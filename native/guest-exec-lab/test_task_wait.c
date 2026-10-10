#define _GNU_SOURCE
#include "task_wait.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>

struct call { pid_t selected, result; int error; };
static struct call calls[32];
static unsigned queued, taken;
static struct rusage *expected_usage;
static void expect(pid_t selected, pid_t result, int error) {
    assert(queued < sizeof(calls)/sizeof(*calls));
    calls[queued++] = (struct call){selected, result, error};
}
pid_t __wrap_wait4(pid_t selected, int *status, int options, struct rusage *usage) {
    assert(taken < queued);
    struct call call = calls[taken++];
    assert(call.selected == selected && options == (__WALL | WNOHANG));
    assert(usage == expected_usage);
    if (call.result > 0) {
        *status = 0x7057f;
        if (usage) usage->ru_utime.tv_usec = 1234;
    }
    errno = call.error;
    return call.result;
}
static void done(void) { assert(taken == queued); taken = queued = 0; }

int main(void) {
    int status;
    struct md_task_wait w = {0};
    expect(-1, 10, 0);
    assert(md_task_wait_ready(&w, &status, NULL) == 10 && status == 0x7057f);
    done();

    struct rusage usage = {0};
    expected_usage = &usage;
    md_task_wait_hint(&w, 11);
    expect(11, 11, 0);
    assert(md_task_wait_ready(&w, &status, &usage) == 11 && usage.ru_utime.tv_usec == 1234);
    done(); expected_usage = NULL;

    /* Duplicate/coalesced notifications do not manufacture another event. */
    md_task_wait_hint(&w, 11); md_task_wait_hint(&w, 12);
    expect(11, 0, 0); expect(-1, 12, 0);
    assert(md_task_wait_ready(&w, &status, NULL) == 12);
    done();
    md_task_wait_hint(&w, 11);
    expect(11, -1, ECHILD); expect(-1, 13, 0);
    assert(md_task_wait_ready(&w, &status, NULL) == 13);
    done();
    md_task_wait_hint(&w, 11);
    expect(11, -1, ESRCH); expect(-1, 14, 0);
    assert(md_task_wait_ready(&w, &status, NULL) == 14);
    done();

    /* Interruptions retain the normal caller retry contract. */
    md_task_wait_hint(&w, 15);
    expect(15, -1, EINTR);
    assert(md_task_wait_ready(&w, &status, NULL) == -1 && errno == EINTR);
    done();
    expect(-1, 15, 0);
    assert(md_task_wait_ready(&w, &status, NULL) == 15);
    done();
    md_task_wait_hint(&w, 0); md_task_wait_hint(&w, -1);
    expect(-1, -1, ECHILD);
    assert(md_task_wait_ready(&w, &status, NULL) == -1 && errno == ECHILD);
    done();

    /* An older unnotified stop gets service despite a perpetually hot TID. */
    for (unsigned i = 0; i < 8; ++i) {
        md_task_wait_hint(&w, 16);
        expect(16, 16, 0);
        assert(md_task_wait_ready(&w, &status, NULL) == 16);
        done();
    }
    md_task_wait_hint(&w, 16);
    expect(-1, 17, 0);
    assert(md_task_wait_ready(&w, &status, NULL) == 17);
    done();
    expect(16, 16, 0);
    assert(md_task_wait_ready(&w, &status, NULL) == 16);
    done();

    expect(-1, 0, 0);
    assert(md_task_wait_ready(&w, &status, NULL) == 0);
    done();
    /* Worker/socket completions cannot create a ptrace status. No syscall is
     * needed until the next SIGCHLD, including an invalid/stale caller hint. */
    for (unsigned i=0;i<1024;i++) {
        md_task_wait_hint(&w, i&1 ? 0 : -1);
        assert(md_task_wait_ready(&w, &status, NULL) == 0);
    }
    done();
    md_task_wait_hint(&w,18);
    expect(18,0,0); expect(-1,19,0);
    assert(md_task_wait_ready(&w,&status,NULL)==19);
    done();
    expect(-1,0,0);
    assert(!md_task_wait_ready(&w,&status,NULL));
    done();
    md_task_wait_hint(&w,20);
    expect(20,20,0);
    assert(md_task_wait_ready(&w,&status,NULL)==20);
    done();
    puts("PASS task event selection");
    return 0;
}

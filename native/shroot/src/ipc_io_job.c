#define _GNU_SOURCE
#include "ipc_io_job.h"
#include "event_signal.h"
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <ucontext.h>
#include <unistd.h>

extern long md_ipc_io_syscall(long, long, long, long, long, long, const atomic_int *);
extern char md_ipc_io_begin[], md_ipc_io_end[], md_ipc_io_cancelled[];
static pthread_once_t once=PTHREAD_ONCE_INIT;
static int setup_error;

static void interrupt_call(int signal, siginfo_t *info, void *context) {
    (void)signal; (void)info;
    ucontext_t *state=context;
    uintptr_t pc=state->uc_mcontext.pc;
    /* Close the unblock/check/SVC race. After SVC, preserve the actual result
     * and its received FDs, even if cancellation wins the completion race. */
    if (pc>=(uintptr_t)md_ipc_io_begin && pc<(uintptr_t)md_ipc_io_end)
        state->uc_mcontext.pc=(uintptr_t)md_ipc_io_cancelled;
}
static void setup(void) {
    struct sigaction action={.sa_sigaction=interrupt_call,.sa_flags=SA_SIGINFO};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR2,&action,NULL)) setup_error=-errno;
}
static void *run(void *opaque) {
    struct md_ipc_io_job *job=opaque;
    sigset_t mask; sigfillset(&mask); sigdelset(&mask,SIGUSR2);
    int error=pthread_sigmask(SIG_SETMASK,&mask,NULL);
    job->result=error ? -error : md_ipc_io_syscall(job->number,
        job->args[0],job->args[1],job->args[2],job->args[3],job->args[4],&job->cancelled);
    if (md_event_signal(job->event)) abort();
    return NULL;
}
int md_ipc_io_job_start(struct md_ipc_io_job *job, long number, const long args[5]) {
    if (job->started) return -EBUSY;
    pthread_once(&once,setup);
    if (setup_error) return setup_error;
    job->event=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK);
    if (job->event<0) return -errno;
    job->number=number; memcpy(job->args,args,sizeof(job->args));
    atomic_init(&job->cancelled,0);
    int error=pthread_create(&job->thread,NULL,run,job);
    if (error) { close(job->event); job->event=-1; return -error; }
    job->started=1; return 0;
}
long md_ipc_io_job_finish(struct md_ipc_io_job *job, int interrupt) {
    if (!job->started) return -EINVAL;
    if (interrupt) {
        atomic_store_explicit(&job->cancelled,1,memory_order_release);
        int error=pthread_kill(job->thread,SIGUSR2);
        if (error && error!=ESRCH) abort();
    }
    /* EVENT_WAIT: native syscall completion, or cancellation acknowledged by
     * its signal/entry gate. Join precedes releasing buffers and FD custody. */
    int error=pthread_join(job->thread,NULL);
    if (error) abort();
    close(job->event); job->event=-1; job->started=0;
    return job->result;
}
int md_ipc_io_job_event(const struct md_ipc_io_job *job) {
    return job->started ? job->event : -1;
}

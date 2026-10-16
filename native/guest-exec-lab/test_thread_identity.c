#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <grp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static pthread_mutex_t mutex;
static pthread_barrier_t ready, done;
static void *credential_worker(void *unused) {
    (void)unused;
    pthread_barrier_wait(&ready);
    pthread_barrier_wait(&done);
    assert(getuid()==0 && getgid()==0);
    return NULL;
}
static void credentials(void) {
    pthread_t workers[3];
    assert(!pthread_barrier_init(&ready,NULL,4));
    assert(!pthread_barrier_init(&done,NULL,4));
    for (unsigned i=0;i<3;++i) assert(!pthread_create(&workers[i],NULL,credential_worker,NULL));
    pthread_barrier_wait(&ready);
    assert(!setgroups(0,NULL));
    assert(!setgid(0));
    assert(!setuid(0));
    pthread_barrier_wait(&done);
    for (unsigned i=0;i<3;++i) assert(!pthread_join(workers[i],NULL));
    assert(!pthread_barrier_destroy(&ready));
    assert(!pthread_barrier_destroy(&done));
}
static volatile pid_t parent_tid, child_tid;
static int clone_child(void *unused) {
    (void)unused;
    assert(parent_tid==syscall(SYS_gettid));
    assert(child_tid==parent_tid);
    return 0;
}
static void *worker(void *unused) {
    (void)unused;
    assert(!pthread_mutex_lock(&mutex));
    pid_t tid=(pid_t)syscall(SYS_gettid);
    int error=pthread_mutex_unlock(&mutex);
    if (error) fprintf(stderr,"thread tid=%d mutex unlock=%d\n",tid,error);
    assert(!error);
    return NULL;
}
static void threads(void) {
    pthread_mutexattr_t attr;
    assert(!pthread_mutexattr_init(&attr));
    assert(!pthread_mutexattr_settype(&attr,PTHREAD_MUTEX_RECURSIVE));
    assert(!pthread_mutex_init(&mutex,&attr));
    assert(!pthread_mutexattr_destroy(&attr));
    for (unsigned i=0;i<64;++i) {
        pthread_t thread;
        assert(!pthread_create(&thread,NULL,worker,NULL));
        assert(!pthread_join(thread,NULL));
    }
    assert(!pthread_mutex_destroy(&mutex));
    size_t length=1024*1024;
    char *stack=malloc(length);
    assert(stack);
    for (unsigned i=0;i<16;++i) {
        parent_tid=child_tid=-1;
        pid_t child=clone(clone_child,stack+length,CLONE_VM|CLONE_PARENT_SETTID
            |CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID|SIGCHLD,NULL,&parent_tid,NULL,&child_tid);
        assert(child>0 && parent_tid==child);
        int status;
        assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
        assert(!child_tid);
    }
    free(stack);
}
int main(void) {
    credentials();
    threads();
    assert(!prctl(PR_SET_DUMPABLE,0));
    credentials();
    threads();
    puts("PASS thread identity: recursive mutex ownership is stable from first instruction");
    return 0;
}

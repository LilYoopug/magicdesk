/* Exercise the actual recipe-built Mesa queue, including worker admission. */
#include "util/u_queue.h"
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static atomic_int attempts;
static atomic_int workers;
static int allowed_workers = -1;

int __real_u_thread_create(thrd_t *, thrd_start_t, void *);
int __wrap_u_thread_create(thrd_t *, thrd_start_t, void *);
int __wrap_u_thread_create(thrd_t *thread, thrd_start_t start, void *data)
{
   atomic_fetch_add(&attempts, 1);
   if (allowed_workers >= 0 && atomic_load(&workers) >= allowed_workers)
      return thrd_error;
   int result = __real_u_thread_create(thread, start, data);
   if (result == thrd_success)
      atomic_fetch_add(&workers, 1);
   return result;
}

struct job {
   struct util_queue_fence fence;
   atomic_int executions;
   atomic_int cleanups;
   util_barrier *barrier;
};

static void execute(void *data, void *global, int index)
{
   struct job *job = data;
   assert(global == &workers && index >= 0);
   atomic_fetch_add(&job->executions, 1);
   if (job->barrier)
      util_barrier_wait(job->barrier);
}

static void cleanup(void *data, void *global, int index)
{
   struct job *job = data;
   assert(global == &workers && index >= 0);
   atomic_fetch_add(&job->cleanups, 1);
}

static void add(struct util_queue *queue, struct job *job)
{
   util_queue_fence_init(&job->fence);
   util_queue_add_job(queue, job, &job->fence, execute, cleanup, sizeof(*job));
}

static void check(struct job *job)
{
   assert(util_queue_fence_wait_timeout(&job->fence,
                                       os_time_get_nano() + INT64_C(10000000000)));
   assert(atomic_load(&job->executions) == 1);
   assert(atomic_load(&job->cleanups) == 1);
   util_queue_fence_destroy(&job->fence);
}

static void init(struct util_queue *queue)
{
   assert(util_queue_init(queue, "test", 4, 4,
                          UTIL_QUEUE_INIT_RESIZE_IF_FULL, &workers));
}

static void empty(void)
{
   struct util_queue queue;
   int before = atomic_load(&attempts);
   init(&queue);
   util_queue_adjust_num_threads(&queue, 4, false);
   util_queue_finish(&queue);
   assert(util_queue_get_thread_time_nano(&queue, 0) == 0);
   util_queue_adjust_num_threads(&queue, 2, false);
   util_queue_destroy(&queue);
   assert(atomic_load(&attempts) == before);
}

static void parallel(void)
{
   struct util_queue queue;
   struct job jobs[20] = {0};
   util_barrier barrier;
   int before = atomic_load(&workers);
   init(&queue);
   util_queue_adjust_num_threads(&queue, 4, false);
   assert(atomic_load(&workers) == before);
   util_barrier_init(&barrier, 5);
   for (unsigned i = 0; i < ARRAY_SIZE(jobs); ++i) {
      jobs[i].barrier = i < 4 ? &barrier : NULL;
      add(&queue, &jobs[i]);
   }
   /* All four workers must reach the barrier before any job can finish. */
   util_barrier_wait(&barrier);
   util_queue_finish(&queue);
   util_barrier_destroy(&barrier);
   assert(atomic_load(&workers) == before + 4);
   for (unsigned i = 0; i < ARRAY_SIZE(jobs); ++i)
      check(&jobs[i]);
   util_queue_adjust_num_threads(&queue, 2, false);
   util_queue_adjust_num_threads(&queue, 4, false);
   assert(atomic_load(&workers) == before + 6);
   struct job last = {0};
   add(&queue, &last);
   util_queue_finish(&queue);
   check(&last);
   util_queue_destroy(&queue);
}

struct producer {
   struct util_queue *queue;
   util_barrier *barrier;
   struct job jobs[64];
};

static int produce(void *data)
{
   struct producer *producer = data;
   util_barrier_wait(producer->barrier);
   for (unsigned i = 0; i < ARRAY_SIZE(producer->jobs); ++i)
      add(producer->queue, &producer->jobs[i]);
   return 0;
}

static void concurrent(void)
{
   struct util_queue queue;
   util_barrier barrier;
   struct producer producers[8] = {0};
   thrd_t threads[8];
   int before = atomic_load(&workers);
   init(&queue);
   util_barrier_init(&barrier, ARRAY_SIZE(producers));
   for (unsigned i = 0; i < ARRAY_SIZE(producers); ++i) {
      producers[i].queue = &queue;
      producers[i].barrier = &barrier;
      assert(thrd_create(&threads[i], produce, &producers[i]) == thrd_success);
   }
   for (unsigned i = 0; i < ARRAY_SIZE(producers); ++i)
      thrd_join(threads[i], NULL);
   util_queue_finish(&queue);
   for (unsigned i = 0; i < ARRAY_SIZE(producers); ++i)
      for (unsigned j = 0; j < ARRAY_SIZE(producers[i].jobs); ++j)
         check(&producers[i].jobs[j]);
   assert(atomic_load(&workers) > before && atomic_load(&workers) <= before + 4);
   util_queue_destroy(&queue);
   util_barrier_destroy(&barrier);
}

static void partial_failure(void)
{
   struct util_queue queue;
   struct job jobs[16] = {0};
   int before = atomic_load(&workers);
   allowed_workers = before + 1;
   init(&queue);
   util_queue_adjust_num_threads(&queue, 4, false);
   for (unsigned i = 0; i < ARRAY_SIZE(jobs); ++i)
      add(&queue, &jobs[i]);
   util_queue_finish(&queue);
   for (unsigned i = 0; i < ARRAY_SIZE(jobs); ++i)
      check(&jobs[i]);
   assert(atomic_load(&workers) == before + 1);
   util_queue_destroy(&queue);
   allowed_workers = -1;
}

static void child_case(bool fail)
{
   pid_t pid = fork();
   assert(pid >= 0);
   if (!pid) {
      struct rlimit limit = {0, 0};
      assert(setrlimit(RLIMIT_CORE, &limit) == 0);
      static struct util_queue queue;
      init(&queue);
      if (fail) {
         allowed_workers = 0;
         struct job job = {0};
         add(&queue, &job);
         _exit(99);
      }
      exit(0); /* The atexit owner must not join nonexistent workers. */
   }
   int status;
   assert(waitpid(pid, &status, 0) == pid);
   assert(fail ? WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT
               : WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(void)
{
   alarm(60); /* Failure bound for a broken queue/fence, not a settling delay. */
   child_case(false);
   child_case(true);
   empty();
   parallel();
   for (unsigned i = 0; i < 16; ++i)
      concurrent();
   partial_failure();
   puts("PASS Mesa deferred queues: empty, atexit, first failure, parallel, resize, concurrent, partial failure");
   return 0;
}

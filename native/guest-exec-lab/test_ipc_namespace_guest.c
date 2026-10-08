#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <linux/msg.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void completed(pid_t child) {
    int status;
    /* EVENT_WAIT: the child must exit before comparing namespace state. */
    assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
}
struct context { int sem, msg, shm; char *mapping; };
static void fresh(void) {
    assert(syscall(SYS_semget,314,1,0)<0 && errno==ENOENT);
    assert(syscall(SYS_msgget,314,0)<0 && errno==ENOENT);
    assert(syscall(SYS_shmget,314,4096,0)<0 && errno==ENOENT);
}
static void private_objects(void) {
    int sem=syscall(SYS_semget,314,1,IPC_CREAT|IPC_EXCL|0600); assert(sem>=0);
    int msg=syscall(SYS_msgget,314,IPC_CREAT|IPC_EXCL|0600); assert(msg>=0);
    int shm=syscall(SYS_shmget,314,8192,IPC_CREAT|IPC_EXCL|0600); assert(shm>=0);
    char *mapping=(void *)syscall(SYS_shmat,shm,NULL,0); assert(mapping!=(void *)-1);
    strcpy(mapping,"private");
    struct { long type; char body[8]; } message={1,"message"}, received={0};
    assert(!syscall(SYS_msgsnd,msg,&message,8,0));
    int ready[2]; assert(!pipe(ready));
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        close(ready[0]);
        assert(syscall(SYS_semget,314,1,0)==sem);
        assert(syscall(SYS_msgget,314,0)==msg);
        assert(syscall(SYS_shmget,314,8192,0)==shm);
        assert(!strcmp(mapping,"private"));
        assert(write(ready[1],"r",1)==1);
        struct sembuf op={.sem_num=0,.sem_op=-1};
        long result=syscall(SYS_semop,sem,&op,1);
        if (result) fprintf(stderr,"private semop: %ld errno=%d (%s)\n",result,errno,strerror(errno));
        assert(!result);
        assert(!syscall(SYS_shmdt,mapping));
        _exit(0);
    }
    close(ready[1]); char byte;
    /* EVENT_WAIT: child has inherited the namespace before semaphore release;
     * the executable alarm bounds a missing signal or wait completion. */
    assert(read(ready[0],&byte,1)==1); close(ready[0]);
    assert(!syscall(SYS_semctl,sem,0,SETVAL,1)); completed(child);
    assert(syscall(SYS_msgrcv,msg,&received,8,1,0)==8 && !memcmp(&received,&message,sizeof(message)));
    assert(!unshare(CLONE_NEWIPC)); fresh();
    assert(!strcmp(mapping,"private"));
    strcpy(mapping,"retained");
    assert(!munmap(mapping+4096,4096));
    child=fork(); assert(child>=0);
    if (!child) { assert(!strcmp(mapping,"retained")); assert(!syscall(SYS_shmdt,mapping)); _exit(0); }
    completed(child);
    assert(!syscall(SYS_shmdt,mapping));
}
static int isolated(void *argument) {
    struct context *c=argument;
    fresh();
    assert(syscall(SYS_semctl,c->sem,0,GETVAL,0)<0 && errno==EINVAL);
    struct msqid64_ds message;
    struct shmid64_ds segment;
    assert(syscall(SYS_msgctl,c->msg,IPC_STAT,&message)<0 && errno==EINVAL);
    assert(syscall(SYS_shmctl,c->shm,IPC_STAT,&segment)<0 && errno==EINVAL);
    assert(!strcmp(c->mapping,"outer"));
    private_objects();
    assert(!syscall(SYS_shmdt,c->mapping));
    return 0;
}
void test_ipc_namespace_guest(void) {
    alarm(60);
    struct context c={.sem=syscall(SYS_semget,314,1,IPC_CREAT|IPC_EXCL|0600),
        .msg=syscall(SYS_msgget,314,IPC_CREAT|IPC_EXCL|0600),
        .shm=syscall(SYS_shmget,314,4096,IPC_CREAT|IPC_EXCL|0600)};
    assert(c.sem>=0 && c.msg>=0 && c.shm>=0);
    c.mapping=(void *)syscall(SYS_shmat,c.shm,NULL,0); assert(c.mapping!=(void *)-1);
    strcpy(c.mapping,"outer");
    void *stack=malloc(1024*1024); assert(stack);
    pid_t child=clone(isolated,(char *)stack+1024*1024,CLONE_NEWIPC|SIGCHLD,&c); assert(child>=0);
    completed(child);
    assert(clone(isolated,(char *)stack+1024*1024,CLONE_NEWIPC|CLONE_SYSVSEM|SIGCHLD,&c)<0 && errno==EINVAL);
    assert(clone(isolated,(char *)stack+1024*1024,CLONE_NEWIPC|CLONE_SIGHAND|SIGCHLD,&c)<0 && errno==EINVAL);
    free(stack);
    assert(syscall(SYS_semget,314,1,0)==c.sem && syscall(SYS_shmget,314,4096,0)==c.shm);
    assert(!strcmp(c.mapping,"outer"));
    assert(!syscall(SYS_semctl,c.sem,0,SETVAL,1));
    child=fork(); assert(child>=0);
    if (!child) {
        struct sembuf op={.sem_num=0,.sem_op=-1,.sem_flg=SEM_UNDO};
        assert(!syscall(SYS_semop,c.sem,&op,1));
        assert(!unshare(CLONE_NEWIPC)); fresh(); _exit(0);
    }
    completed(child); assert(syscall(SYS_semctl,c.sem,0,GETVAL,0)==1);
    assert(!syscall(SYS_semctl,c.sem,0,IPC_RMID,0));
    assert(!syscall(SYS_msgctl,c.msg,IPC_RMID,NULL));
    assert(!syscall(SYS_shmctl,c.shm,IPC_RMID,NULL));
    assert(!syscall(SYS_shmdt,c.mapping));
    assert(!prctl(PR_SET_DUMPABLE,0));
    assert(!unshare(CLONE_NEWIPC|CLONE_NEWUTS)); private_objects();
    assert(!setuid(1234));
    assert(unshare(CLONE_NEWIPC)<0 && errno==EPERM);
    puts("PASS guest IPC namespaces: keys, ID isolation, nested clone/unshare, semaphore wakeups/undo, protected calls and retained mappings");
}

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/close_range.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/prctl.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void put(int fd) { assert(write(fd, "x", 1) == 1); }
static void get(int fd) {
    char byte;
    /* EVENT_WAIT: pipe acknowledgement orders resource mutation/observation;
     * the fixture's alarm terminates a missing peer, never implies success. */
    assert(read(fd, &byte, 1) == 1);
}
static void reap(pid_t pid) {
    int status = 0;
    pid_t observed = waitpid(pid, &status, 0);
    if (observed != pid || !WIFEXITED(status) || WEXITSTATUS(status))
        fprintf(stderr, "wait pid=%d observed=%d status=%#x errno=%d\n", pid, observed, status, errno);
    assert(observed == pid && WIFEXITED(status) && !WEXITSTATUS(status));
}
struct context { int ready[2], done[2], file, unshare, root; };
static const char *executable;
static int mutate(void *argument) {
    struct context *c = argument;
    if (c->unshare == -2) {
        assert(unshare(CLONE_FS | CLONE_VM) == -1 && errno == EINVAL);
    }
    if (c->unshare == -4) {
        assert(unshare(CLONE_FS | CLONE_NEWNS) == -1 && errno == ENOTSUP);
    }
    if (c->unshare == -3) {
        char ready[24], done[24], file[24];
        snprintf(ready, sizeof(ready), "%d", c->ready[1]);
        snprintf(done, sizeof(done), "%d", c->done[0]);
        snprintf(file, sizeof(file), "%d", c->file);
        execl(executable, executable, "exec-action", ready, done, file, (char *)NULL);
        perror("exec"); return 1;
    }
    if (c->unshare >= 0) assert(!unshare(c->unshare));
    if (c->root) assert(!chroot("/proc/self/fdinfo"));
    else {
        assert(!chdir("b")); umask(0077);
        assert(fcntl(c->file, F_SETFD, FD_CLOEXEC) == 0);
        assert(lseek(c->file, 9, SEEK_SET) == 9);
    }
    put(c->ready[1]); get(c->done[0]);
    return 0;
}
static void sharing(unsigned flags, int split, int root) {
    struct context c = {.unshare=split, .root=root};
    assert(!pipe(c.ready) && !pipe(c.done));
    c.file = open("value", O_RDWR | O_CREAT | O_TRUNC, 0600); assert(c.file >= 0);
    assert(!mkdir("b", 0700) || errno == EEXIST);
    char before[4096]; assert(getcwd(before, sizeof(before)));
    mode_t old = umask(0022);
    void *stack = malloc(1024 * 1024); assert(stack);
    pid_t pid = clone(mutate, (char *)stack + 1024 * 1024, SIGCHLD | flags, &c); assert(pid > 0);
    get(c.ready[0]);
    int shared_fs = (flags & CLONE_FS) && !(split >= 0 && (split & CLONE_FS));
    if (root) {
        int fd = open("value", O_RDONLY);
        if (shared_fs) assert(fd < 0 && errno == EACCES);
        else { assert(fd >= 0); close(fd); }
    } else {
        char after[4096]; assert(getcwd(after, sizeof(after)));
        assert((strcmp(before, after) != 0) == shared_fs);
        assert(umask(0022) == (shared_fs ? 0077 : 0022));
        int shared_files = (flags & CLONE_FILES) && split != -3
            && !(split >= 0 && (split & CLONE_FILES));
        assert(fcntl(c.file, F_GETFD) == (shared_files ? FD_CLOEXEC : 0));
        /* Unsharing a table does not clone its open-file descriptions. */
        assert(lseek(c.file, 0, SEEK_CUR) == 9);
    }
    put(c.done[1]); reap(pid); free(stack);
    if (!root) assert(!chdir(before));
    umask(old);
    close(c.file);
    close(c.ready[0]); close(c.ready[1]); close(c.done[0]); close(c.done[1]);
    printf("PASS sharing flags=%#x unshare=%d root=%d\n", flags, split, root);
}
static void case_sharing(unsigned flags, int split, int root) {
    pid_t pid = fork(); assert(pid >= 0);
    if (!pid) { sharing(flags, split, root); _exit(0); }
    reap(pid);
}
struct range_context { int ready[2], done[2], file, invalid; unsigned flags; };
static int range_child(void *argument) {
    struct range_context *c=argument;
    long result=syscall(SYS_close_range,(unsigned)c->file+c->invalid,(unsigned)c->file,c->flags);
    if (c->invalid) {
        assert(result==-1 && errno==EINVAL);
        assert(!fcntl(c->file,F_SETFD,FD_CLOEXEC));
    } else {
        assert(!result);
        if (c->flags & CLOSE_RANGE_CLOEXEC) assert(fcntl(c->file,F_GETFD)==FD_CLOEXEC);
        else assert(fcntl(c->file,F_GETFD)==-1 && errno==EBADF);
    }
    put(c->ready[1]); get(c->done[0]); return 0;
}
static void range_sharing(unsigned flags, int invalid) {
    struct range_context c={.flags=flags,.invalid=invalid};
    assert(!pipe(c.ready) && !pipe(c.done));
    c.file=open("value",O_RDONLY); assert(c.file>=0);
    void *stack=malloc(1024*1024); assert(stack);
    pid_t pid=clone(range_child,(char *)stack+1024*1024,SIGCHLD|CLONE_FILES,&c);
    assert(pid>0); get(c.ready[0]);
    int split=(flags & CLOSE_RANGE_UNSHARE) && !invalid;
    if (split) assert(fcntl(c.file,F_GETFD)==0);
    else if (invalid || (flags & CLOSE_RANGE_CLOEXEC)) assert(fcntl(c.file,F_GETFD)==FD_CLOEXEC);
    else assert(fcntl(c.file,F_GETFD)==-1 && errno==EBADF);
    put(c.done[1]); reap(pid); free(stack);
    if (split || invalid || (flags & CLOSE_RANGE_CLOEXEC)) assert(!close(c.file));
    close(c.ready[0]); close(c.ready[1]); close(c.done[0]); close(c.done[1]);
    printf("PASS close_range flags=%#x invalid=%d\n",flags,invalid);
}
static void restricted_descriptors(void) {
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        int file=open("value",O_RDWR|O_CREAT,0600); assert(file>=0);
        assert(!chroot("/proc/self/fdinfo"));
        int copy=dup(file); assert(copy>=0);
        int target=fcntl(file,F_DUPFD,100); assert(target>=100);
        assert(dup3(copy,target,O_CLOEXEC)==target);
        assert(fcntl(target,F_GETFD)==FD_CLOEXEC);
        /* The kernel takes a 32-bit command even when the raw ABI has high bits. */
        unsigned long high=1UL<<32;
        assert(!syscall(SYS_fcntl,target,high|F_SETFD,0));
        assert(fcntl(target,F_GETFD)==0);
        int wide=syscall(SYS_fcntl,copy,high|F_DUPFD_CLOEXEC,101); assert(wide>=101);
        assert(fcntl(wide,F_GETFD)==FD_CLOEXEC);
        assert(!syscall(SYS_close_range,(unsigned)target,(unsigned)target,
            CLOSE_RANGE_UNSHARE|CLOSE_RANGE_CLOEXEC));
        assert(fcntl(target,F_GETFD)==FD_CLOEXEC);
        assert(!syscall(SYS_close_range,(unsigned)wide,(unsigned)wide,0));
        assert(fcntl(wide,F_GETFD)==-1 && errno==EBADF);
        assert(!close(copy) && !close(target) && !close(file));
        _exit(0);
    }
    reap(child);
    puts("PASS restricted proc-root preserves native descriptor mutation and flags");
}
struct cwd_context { int ready[2], go[2], directory[2], bad, writer; };
static int cwd_worker(void *argument) {
    struct cwd_context *c=argument;
    put(c->ready[1]); get(c->go[0]);
    for (unsigned i=0;i<250;++i) {
        if (c->writer) {
            assert(!fchdir(c->directory[i%2]));
            assert(fchdir(c->bad)==-1 && errno==ENOTDIR);
        } else {
            /* Ordinary open uses direct notifications; O_PATH and getcwd use
             * the task-affine transport. Either directory is a valid snapshot. */
            int fd=open("item",i%2 ? O_PATH|O_CLOEXEC : O_RDONLY|O_CLOEXEC); assert(fd>=0);
            struct stat st; assert(!fstat(fd,&st) && S_ISREG(st.st_mode));
            assert(!close(fd));
            char path[4096]; assert(getcwd(path,sizeof(path)));
            assert(strstr(path,"/cwd-a") || strstr(path,"/cwd-b"));
        }
    }
    return 0;
}
static void concurrent_cwd(unsigned flags) {
    int original=open(".",O_PATH|O_DIRECTORY|O_CLOEXEC); assert(original>=0);
    struct cwd_context contexts[3]={0};
    struct cwd_context *base=contexts;
    assert(!pipe(base->ready) && !pipe(base->go));
    const char *names[]={"cwd-a","cwd-b"};
    for (unsigned i=0;i<2;++i) {
        assert(!mkdir(names[i],0700) || errno==EEXIST);
        base->directory[i]=open(names[i],O_PATH|O_DIRECTORY|O_CLOEXEC); assert(base->directory[i]>=0);
        int fd=openat(base->directory[i],"item",O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC,0700); assert(fd>=0);
        assert(!close(fd));
    }
    base->bad=openat(base->directory[0],"item",O_PATH|O_CLOEXEC); assert(base->bad>=0);
    assert(!fchdir(base->directory[0]));
    pid_t children[3]; void *stacks[3];
    for (unsigned i=0;i<3;++i) {
        contexts[i]=*base; contexts[i].writer=i==0;
        stacks[i]=malloc(1024*1024); assert(stacks[i]);
        children[i]=clone(cwd_worker,(char *)stacks[i]+1024*1024,SIGCHLD|CLONE_FS|flags,contexts+i);
        assert(children[i]>0);
    }
    for (unsigned i=0;i<3;++i) get(base->ready[0]);
    for (unsigned i=0;i<3;++i) put(base->go[1]);
    for (unsigned i=0;i<3;++i) { reap(children[i]); free(stacks[i]); }
    assert(!fchdir(original) && !close(original));
    assert(!close(base->directory[0]) && !close(base->directory[1]) && !close(base->bad));
    close(base->ready[0]); close(base->ready[1]); close(base->go[0]); close(base->go[1]);
    printf("PASS concurrent cwd: shared FS, files=%s, direct/RPC relative opens and failed fchdir\n",
        flags&CLONE_FILES ? "shared" : "independent");
}
struct alias_context { int ready[2], go[2], directory[2], target, writer; };
static int alias_worker(void *argument) {
    struct alias_context *c=argument;
    char path[128];
    snprintf(path,sizeof(path),"/proc/thread-self/fd/%d/item",c->target);
    put(c->ready[1]); get(c->go[0]);
    for (unsigned i=0;i<250;++i) {
        if (c->writer) assert(dup3(c->directory[i%2],c->target,O_CLOEXEC)==c->target);
        else {
            int fd=open(path,i%2 ? O_PATH|O_CLOEXEC : O_RDONLY|O_CLOEXEC); assert(fd>=0);
            struct stat st; assert(!fstat(fd,&st) && S_ISREG(st.st_mode));
            assert(st.st_size==1 || st.st_size==2);
            if (!(i%2)) {
                char bytes[3]; ssize_t n=read(fd,bytes,sizeof(bytes));
                assert((n==1 && bytes[0]=='a') || (n==2 && !memcmp(bytes,"bb",2)));
            }
            assert(!close(fd));
        }
    }
    return 0;
}
static void concurrent_aliases(void) {
    struct alias_context contexts[3]={0};
    struct alias_context *base=contexts;
    assert(!pipe(base->ready) && !pipe(base->go));
    const char *names[]={"alias-a","alias-b"}, *contents[]={"a","bb"};
    for (unsigned i=0;i<2;++i) {
        assert(!mkdir(names[i],0700) || errno==EEXIST);
        base->directory[i]=open(names[i],O_PATH|O_DIRECTORY|O_CLOEXEC); assert(base->directory[i]>=0);
        int fd=openat(base->directory[i],"item",O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600); assert(fd>=0);
        assert(write(fd,contents[i],i+1)==(ssize_t)i+1 && !close(fd));
    }
    base->target=fcntl(base->directory[0],F_DUPFD_CLOEXEC,0); assert(base->target>=0);
    pid_t children[3]; void *stacks[3];
    for (unsigned i=0;i<3;++i) {
        contexts[i]=*base; contexts[i].writer=i==0;
        stacks[i]=malloc(1024*1024); assert(stacks[i]);
        children[i]=clone(alias_worker,(char *)stacks[i]+1024*1024,SIGCHLD|CLONE_FILES,contexts+i);
        assert(children[i]>0);
    }
    for (unsigned i=0;i<3;++i) get(base->ready[0]);
    for (unsigned i=0;i<3;++i) put(base->go[1]);
    for (unsigned i=0;i<3;++i) { reap(children[i]); free(stacks[i]); }
    assert(!close(base->target) && !close(base->directory[0]) && !close(base->directory[1]));
    close(base->ready[0]); close(base->ready[1]); close(base->go[0]); close(base->go[1]);
    puts("PASS concurrent proc aliases: shared files, dup3 and retained directory capture");
}
static void undo(void) {
    int sem = syscall(SYS_semget, IPC_PRIVATE, 1, 0600); assert(sem >= 0);
    assert(!syscall(SYS_semctl, sem, 0, SETVAL, 1));
    struct sembuf op = {.sem_num=0, .sem_op=-1, .sem_flg=SEM_UNDO};
    assert(!syscall(SYS_semop, sem, &op, 1));
    assert(syscall(SYS_semctl, sem, 0, GETVAL, 0) == 0);
    assert(!unshare(CLONE_SYSVSEM));
    assert(syscall(SYS_semctl, sem, 0, GETVAL, 0) == 1);
    assert(!syscall(SYS_semctl, sem, 0, IPC_RMID, 0));
    puts("PASS unshare SYSVSEM applies the last owner's adjustments");
}
struct undo_context { int sem, ready[2], done[2], exec; };
static int undo_child(void *argument) {
    struct undo_context *c = argument;
    if (c->exec) {
        char sem[24], ready[24], done[24];
        snprintf(sem, sizeof(sem), "%d", c->sem);
        snprintf(ready, sizeof(ready), "%d", c->ready[1]);
        snprintf(done, sizeof(done), "%d", c->done[0]);
        execl(executable, executable, "exec-undo", sem, ready, done, (char *)NULL);
        perror("exec undo"); return 1;
    }
    assert(!unshare(CLONE_SYSVSEM));
    assert(syscall(SYS_semctl, c->sem, 0, GETVAL, 0) == 1);
    struct sembuf op = {.sem_num=0, .sem_op=-1, .sem_flg=SEM_UNDO};
    assert(!syscall(SYS_semop, c->sem, &op, 1));
    put(c->ready[1]); get(c->done[0]); return 0;
}
static void shared_undo(int exec) {
    struct undo_context c = {.exec=exec};
    assert(!pipe(c.ready) && !pipe(c.done));
    c.sem = syscall(SYS_semget, IPC_PRIVATE, 1, 0600); assert(c.sem >= 0);
    assert(!syscall(SYS_semctl, c.sem, 0, SETVAL, 2));
    struct sembuf op = {.sem_num=0, .sem_op=-1, .sem_flg=SEM_UNDO};
    assert(!syscall(SYS_semop, c.sem, &op, 1));
    void *stack = malloc(1024 * 1024); assert(stack);
    pid_t pid = clone(undo_child, (char *)stack + 1024 * 1024, SIGCHLD | CLONE_SYSVSEM, &c);
    assert(pid > 0); get(c.ready[0]);
    assert(syscall(SYS_semctl, c.sem, 0, GETVAL, 0) == 0);
    put(c.done[1]); reap(pid); free(stack);
    assert(syscall(SYS_semctl, c.sem, 0, GETVAL, 0) == (exec ? 0 : 1));
    assert(!unshare(CLONE_SYSVSEM));
    assert(syscall(SYS_semctl, c.sem, 0, GETVAL, 0) == 2);
    assert(!syscall(SYS_semctl, c.sem, 0, IPC_RMID, 0));
    close(c.ready[0]); close(c.ready[1]); close(c.done[0]); close(c.done[1]);
    printf("PASS shared SEM_UNDO last-owner lifetime exec=%d\n", exec);
}
static void workload(const char *mode) {
    struct timespec start, finish;
    assert(!clock_gettime(CLOCK_MONOTONIC, &start));
    unsigned count;
    if (!strcmp(mode, "metadata")) {
        int fd = open("workload", O_WRONLY | O_CREAT | O_TRUNC, 0600); assert(fd >= 0);
        put(fd); assert(!close(fd));
        count = 4000;
        for (unsigned i = 0; i < count; ++i) {
            struct stat named, opened;
            assert(!stat("workload", &named));
            fd = open("workload", O_RDONLY); assert(fd >= 0);
            assert(!fstat(fd, &opened) && opened.st_ino == named.st_ino);
            get(fd); assert(!close(fd));
            assert(stat("absent-workload", &named) == -1 && errno == ENOENT);
        }
        assert(!unlink("workload"));
    } else {
        assert(!strcmp(mode, "spawn")); count = 100;
        for (unsigned i = 0; i < count; ++i) {
            pid_t pid = fork(); assert(pid >= 0);
            if (!pid) { execl(executable, executable, "noop", ".", (char *)NULL); _exit(127); }
            reap(pid);
        }
    }
    assert(!clock_gettime(CLOCK_MONOTONIC, &finish));
    long long elapsed = (finish.tv_sec-start.tv_sec)*1000000000LL + finish.tv_nsec-start.tv_nsec;
    printf("PASS workload=%s count=%u elapsedNs=%lld\n", mode, count, elapsed);
}
static void probe(void) {
    unsigned long flags[] = {0, CLONE_FS, CLONE_FILES, CLONE_SYSVSEM, CLONE_NEWUSER,
        CLONE_NEWNS, CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWPID, CLONE_NEWNET, CLONE_NEWCGROUP};
    for (unsigned i = 0; i < sizeof(flags)/sizeof(flags[0]); i++) {
        pid_t pid = fork(); assert(pid >= 0);
        if (!pid) {
            errno = 0; long r = syscall(SYS_unshare, flags[i]);
            printf("PROBE unshare=%#lx result=%ld errno=%d\n", flags[i], r, errno); _exit(0);
        }
        reap(pid);
    }
}
static void origins(const char *cwd, int protected) {
    char actual[4096]; assert(getcwd(actual,sizeof(actual)) && !strcmp(actual,cwd));
    int fd=open("origin-file",O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC,0600); assert(fd>=0);
    assert(write(fd,"origin",6)==6 && lseek(fd,2,SEEK_SET)==2);
    if (protected) assert(!prctl(PR_SET_DUMPABLE,0));
    for (unsigned i=0;i<6;++i) {
        char path[128];
        switch (i) {
        case 0: snprintf(path,sizeof(path),"/proc/self/fd/%d",fd); break;
        case 1: snprintf(path,sizeof(path),"/proc/thread-self/fd/%d",fd); break;
        case 2: snprintf(path,sizeof(path),"/proc/%d/fd/%d",getpid(),fd); break;
        case 3: snprintf(path,sizeof(path),"/proc/%d/task/%ld/fd/%d",getpid(),syscall(SYS_gettid),fd); break;
        case 4: snprintf(path,sizeof(path),"/dev/fd/%d",fd); break;
        default: snprintf(path,sizeof(path),"/proc/./self/fd//./%d",fd); break;
        }
        int copy=open(path,O_RDONLY|O_CLOEXEC); char bytes[6];
        assert(copy>=0 && read(copy,bytes,sizeof(bytes))==6 && !memcmp(bytes,"origin",6));
        assert(lseek(fd,0,SEEK_CUR)==2 && !close(copy));
        struct stat original, alias;
        assert(!fstat(fd,&original) && !stat(path,&alias));
        assert(original.st_dev==alias.st_dev && original.st_ino==alias.st_ino);
    }
    int directory=open("/proc/thread-self/cwd",O_PATH|O_DIRECTORY|O_CLOEXEC); assert(directory>=0);
    assert(!fchdir(directory) && !close(directory));
    assert(getcwd(actual,sizeof(actual)) && !strcmp(actual,cwd));
    assert(!close(fd) && !unlink("origin-file"));
    puts("PASS initial cwd and proc aliases retain native offsets and protected metadata access");
}
int main(int argc, char **argv) {
    setbuf(stdout, NULL); alarm(40);
    if (argc == 5 && !strcmp(argv[1], "exec-undo")) {
        struct sembuf op = {.sem_num=0, .sem_op=-1, .sem_flg=SEM_UNDO};
        assert(!syscall(SYS_semop, atoi(argv[2]), &op, 1));
        put(atoi(argv[3])); get(atoi(argv[4])); return 0;
    }
    if (argc == 5 && !strcmp(argv[1], "exec-action")) {
        assert(!chdir("b")); umask(0077);
        int fd = atoi(argv[4]);
        assert(!fcntl(fd, F_SETFD, FD_CLOEXEC) && lseek(fd, 9, SEEK_SET) == 9);
        put(atoi(argv[2])); get(atoi(argv[3])); return 0;
    }
    assert(argc == 3); executable = argv[0];
    if (!strcmp(argv[1],"origins") || !strcmp(argv[1],"origins-protected")) {
        origins(argv[2],!strcmp(argv[1],"origins-protected")); return 0;
    }
    assert(!chdir(argv[2]));
    if (!strcmp(argv[1], "noop")) return 0;
    if (!strcmp(argv[1], "metadata") || !strcmp(argv[1], "spawn")) { workload(argv[1]); return 0; }
    if (!strcmp(argv[1], "probe")) { probe(); return 0; }
    int guest = !strcmp(argv[1], "guest");
    assert(guest || !strcmp(argv[1], "native"));
    if (guest) restricted_descriptors();
    concurrent_cwd(0);
    concurrent_cwd(CLONE_FILES);
    concurrent_aliases();
    case_sharing(0, -1, 0);
    case_sharing(CLONE_FS | CLONE_FILES, -1, 0);
    case_sharing(CLONE_FS | CLONE_FILES, CLONE_FS, 0);
    case_sharing(CLONE_FS | CLONE_FILES, CLONE_FILES, 0);
    case_sharing(CLONE_FS | CLONE_FILES, CLONE_FS | CLONE_FILES, 0);
    case_sharing(CLONE_VM | CLONE_FS | CLONE_FILES, -2, 0);
    case_sharing(CLONE_FS | CLONE_FILES, -3, 0);
    range_sharing(0,0);
    range_sharing(CLOSE_RANGE_CLOEXEC,0);
    range_sharing(CLOSE_RANGE_UNSHARE,0);
    range_sharing(CLOSE_RANGE_UNSHARE|CLOSE_RANGE_CLOEXEC,0);
    range_sharing(CLOSE_RANGE_UNSHARE,1);
    range_sharing(CLOSE_RANGE_UNSHARE|CLOSE_RANGE_CLOEXEC,1);
    if (guest) {
        case_sharing(CLONE_FS, -1, 1);
        case_sharing(CLONE_FS, CLONE_FS, 1);
        case_sharing(CLONE_VM | CLONE_FS, -2, 1);
        case_sharing(CLONE_FS | CLONE_FILES, -4, 0);
        case_sharing(CLONE_FS, -4, 1);
        undo();
        shared_undo(0);
        shared_undo(1);
    }
    puts("PASS process resources");
    return 0;
}

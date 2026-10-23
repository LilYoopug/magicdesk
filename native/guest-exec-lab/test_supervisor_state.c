/* Compile the actual coordinator; only external admission/accounting boundaries
 * are fault-injected. No duplicate model of its state machine or product hooks. */
#define main supervisor_program_main
#include "../shroot/src/supervisor.c"
#undef main
#include <assert.h>

static int accounting_enabled, accounting_requested, adoption_error, adoption_calls;
static pid_t wait_result=123;
static struct md_fs_buffer_open adopted={.fd=-1};
int __wrap_md_debugger_active(struct md_debugger *d) {
    (void)d; return accounting_enabled;
}
pid_t __wrap_md_task_wait_ready(struct md_task_wait *w,int *status,struct rusage *usage) {
    (void)w;
    accounting_requested=usage!=NULL;
    if (wait_result>0) {
        *status=(SIGTRAP|0x80)<<8|0x7f;
        if (usage) *usage=(struct rusage){.ru_utime.tv_usec=123,.ru_maxrss=456};
    }
    return wait_result;
}
int __wrap_md_fs_buffer_adopt(struct md_fs_buffer_service *s,pid_t actor,struct md_guest_domain *fs,
        unsigned operation,unsigned flags,const struct md_interception_buffer *buffer,
        struct md_fs_result *result,struct md_fs_buffer_open *opened,struct md_fs_buffer_request **out) {
    (void)s; (void)fs; (void)operation; (void)flags;
    assert(actor>0 && buffer->pool && !result->error && opened->fd>=0 && !*out);
    ++adoption_calls;
    if (adoption_error) return adoption_error;
    adopted=*opened; *opened=(struct md_fs_buffer_open){.fd=-1};
    *out=(struct md_fs_buffer_request *)&adopted;
    return 0;
}
static void barrier_admission(void) {
    struct mapping_owner mapping={0},other={0};
    struct task_action action={0},loan={0};
    struct memory_execution memory={0};
    assert(!quiescence_busy(NULL));
    entry_fence_stage=1;
    assert(quiescence_busy(NULL) && quiescence_busy(&mapping));
    /* Even a retirement without a requester must not acquire a table or actor. */
    loan_start(&loan);
    assert(!loan.files.table && !loan.actor && !task_action_execution && !cancelling);
    entry_fence_stage=2;
    assert(!quiescence_busy(NULL));
    entry_fence_stage=0;
    memory_execution=&memory;
    assert(quiescence_busy(NULL) && quiescence_busy(&mapping));
    memory_execution=NULL;
    task_action_execution=&action;
    assert(quiescence_busy(NULL) && quiescence_busy(&mapping));
    task_action_execution=NULL; task_action_releasing=1;
    assert(quiescence_busy(NULL) && quiescence_busy(&mapping));
    task_action_releasing=0; mapping_execution=&mapping;
    assert(quiescence_busy(NULL) && quiescence_busy(&other) && !quiescence_busy(&mapping));
    entry_fence_stage=1;
    assert(quiescence_busy(&mapping));
    entry_fence_stage=0; mapping_execution=NULL;
    puts("PASS supervisor admission: entry, repair, injection, release and exact nested retirement");
}
static long readiness_return_trace(int request,pid_t pid,void *address,void *data) {
    assert(request==PTRACE_SETREGSET && pid==123 && (uintptr_t)address==NT_PRSTATUS);
    struct user_pt_regs *regs=((struct iovec *)data)->iov_base;
    assert((long)regs->regs[0]==MD_EPOLL_NATIVE);
    errno=ESRCH; return -1;
}
static void readiness_admission_order(void) {
    struct md_fd_origins *files=md_fd_origins_new();
    struct md_fd_selector *group=md_fd_selector_new();
    struct md_control_epoll *queue=md_control_epoll_new();
    assert(files && group && queue);
    struct readiness_owner prior={.loan_number=-1},activation={0};
    struct thread t={.pid=123,.phase=DISPATCHING,.readiness=&prior};
    t.resources.files=files; t.original.regs[0]=5; t.original.regs[8]=SYS_epoll_pwait;
    assert(md_fd_order_begin(files,&prior.files,NULL)==1);
    activation.admission=md_fd_admission_new(md_control_epoll_object(queue),1U<<MD_FD_SELECTOR_EPOLL);
    assert(activation.admission && !md_fd_admission_add(activation.admission,files,group));
    assert(!md_fd_admission_begin(activation.admission,NULL));
    assert(!md_fd_admission_prepare(activation.admission));
    readiness_activation=&activation;
    thread_index[t.pid%THREAD_BUCKETS]=&t;
    checkpoints.trace=readiness_return_trace;
    readiness_start(&t);
    checkpoints.trace=checkpoint_native_trace;
    thread_index[t.pid%THREAD_BUCKETS]=NULL;
    assert(prior.done && !prior.files.table && t.resume_lost);
    assert(md_fd_admission_prepare(activation.admission)==1);
    assert(!t.retries[0].mask && !t.retries[1].mask);
    readiness_activation=NULL;
    md_fd_admission_release(activation.admission);
    md_control_epoll_release(queue); md_fd_selector_release(group); md_fd_origins_release(files);
    puts("PASS supervisor readiness: earlier table turn drains during cold admission");
}
static long no_trace(int request,pid_t pid,void *address,void *data) {
    (void)request; (void)pid; (void)address; (void)data;
    assert(!"deferring a repair must not stop unrelated tasks"); return -1;
}
static void entry_fence_ownership(void) {
    struct thread a={.pid=123,.entry_fence_waiting=1,.entry_fence_status=17},
        b={.pid=124,.entry_fence_waiting=1,.entry_fence_status=19};
    a.next=&b; threads=&a; entry_fence_waiters=2;
    entry_fence_memory=md_memory_new(); assert(entry_fence_memory);
    a.memory=b.memory=entry_fence_memory;
    entry_fence_barrier=md_task_quiesce_new(no_trace); assert(entry_fence_barrier);
    entry_fence_stage=2; entry_fence_error=-EBUSY;
    int status; struct rusage usage;
    assert(entry_fence_take(&status,&usage)==123 && status==17);
    assert(a.entry_fence_result==-EBUSY && !a.entry_fence_waiting && entry_fence_waiters==1);
    /* Exit/exec cancels a waiter exactly once, before its slot can be reused. */
    entry_fence_cancel(&b); entry_fence_cancel(&b);
    assert(!entry_fence_waiters && !entry_fence_take(&status,&usage));
    assert(!entry_fence_memory && !entry_fence_barrier && !entry_fence_stage);
    threads=NULL;
    entry_fence_progress();
    assert(!entry_fence_memory);
    puts("PASS supervisor entry fence: exact waiter retirement, cancellation and idle fast path");
}
static void control_deadlines(void) {
    struct md_control_pending late={.deadline=500},early={.deadline=100};
    struct thread a={.pid=123,.control_pending=&late},b={.pid=124,.control_pending=&early},idle={.pid=125};
    assert(!control_deadline_owner());
    retry_wait(&idle,RETRY_PROC_IO);
    retry_wait(&a,RETRY_CONTROL);
    assert(control_deadline_owner()==&a);
    /* Requeued work and the still-dispatching generation both retain bounds. */
    retry_queues[1].current^=1;
    retry_wait(&b,RETRY_CONTROL);
    assert(control_deadline_owner()==&b);
    early.deadline=600;
    assert(control_deadline_owner()==&a);
    retry_wait(&a,RETRY_PROC_IO);
    retry_clear(&a,RETRY_CONTROL);
    assert(control_deadline_owner()==&b && a.retries[1].mask==RETRY_PROC_IO);
    retry_clear(&b,RETRY_CONTROL); retry_clear(&b,RETRY_CONTROL);
    assert(!control_deadline_owner());
    retry_clear(&a,RETRY_PROC_IO); retry_clear(&idle,RETRY_PROC_IO);
    retry_queues[1].current=0;
    assert(!retry_queues[1].lists[0].first && !retry_queues[1].lists[1].first);
    puts("PASS control deadlines: active continuations only, both generations, reschedule and exact cancellation");
}
struct completion_probe { struct thread *task; size_t copied; unsigned commits; };
static void *completion_retain(void *p) { return p; }
static void completion_release(void *p) { (void)p; }
static int completion_access(void *p,const struct md_identity *id,unsigned mode) {
    (void)p; (void)id; (void)mode; return 0;
}
static long completion_read(void *p,const struct md_control_actor *actor,void *bytes,size_t size,int64_t offset) {
    (void)p; (void)actor; assert(size>=4 && !offset); memcpy(bytes,"data",4); return 4;
}
static long completion_write(void *p,const struct md_control_actor *actor,const void *bytes,size_t size,int64_t offset) {
    (void)p; (void)actor; assert(size==4 && !offset && !memcmp(bytes,"data",4)); return 4;
}
static void completion_commit(void *context,size_t copied) {
    struct completion_probe *p=context;
    struct md_buffer_span span;
    assert(!md_buffer_span(&p->task->buffer,&span) && !memcmp(span.data,"data",4));
    ++p->commits; p->copied=copied;
}
static void terminal_buffer_completion(void) {
    for (int kind=-1;kind<=MD_PROC_FILE_CONTROL;++kind) {
        unsigned flags=MD_DISPATCH_PATHS|MD_DISPATCH_NETWORK_SCOPED|MD_DISPATCH_DEVICE_EVENTS;
        unsigned context=md_dispatch_control(flags,kind);
        assert((context&0xffff)==flags && md_dispatch_control_kind(context)==kind);
    }
    const struct md_control_file_ops ops={.retain=completion_retain,.release=completion_release,
        .access=completion_access,.read=completion_read,.write=completion_write,.read_commit=completion_commit};
    struct md_interception_buffers *pool=NULL;
    assert(!md_buffers_create(1,4096,0,0,&pool));
    for (unsigned terminal=0;terminal<2;++terminal) for (unsigned mode=0;mode<5;++mode) {
        struct thread t={.buffer_open.fd=-1,.proc_image_fd=-1,.control_mapping_fd=-1};
        struct completion_probe probe={.task=&t};
        assert(!md_buffers_take(pool,&t.buffer));
        struct md_proc_file *file=NULL;
        if (mode!=3) {
            file=md_proc_file_open_control(&ops,&probe,&t.identity,O_RDONLY); assert(file);
            assert(md_proc_file_io_begin(&t.proc_io,file,MD_PROC_FILE_READ,0,0,0,4,NULL)==1);
            struct md_buffer_span span; assert(!md_buffer_span(&t.buffer,&span));
            assert(md_proc_file_io_execute(&t.proc_io,&t.identity,NULL,span.data,span.size,4096)==4);
            assert(!md_proc_file_io_offer(&t.proc_io));
        }
        struct outgoing_owner busy={.stage=OUTGOING_SEND};
        if (mode==4) t.outgoing=&busy;
        long copied=mode==1 ? 2 : mode==2 ? -EFAULT : 4;
        if (terminal) {
            long result=proc_io_complete(&t,copied,copied);
            assert(result==(mode==3 ? -EINVAL : mode==4 ? -EBUSY : copied));
        } else {
            struct buffer_completion result=buffer_finish(&t,copied);
            assert(result.value==(mode==3 ? -EINVAL : 0));
            assert(result.released==(mode==4 ? -EBUSY : 0));
        }
        assert(probe.commits==(mode!=3) && probe.copied==(mode==3 || copied<0 ? 0 : (size_t)copied));
        assert(!t.proc_io.file && !!t.buffer.pool==(mode==4));
        t.outgoing=NULL;
        assert(!buffer_cleanup(&t));
        md_proc_file_release(file);
        /* The sole slot is reusable immediately, including a failed finish. */
        assert(!md_buffers_take(pool,&t.buffer) && !md_buffer_release(&t.buffer));
    }
    for (unsigned seek=0;seek<2;++seek) {
        struct thread t={.buffer_open.fd=-1,.proc_image_fd=-1,.control_mapping_fd=-1};
        struct completion_probe probe={.task=&t};
        assert(!md_buffers_take(pool,&t.buffer));
        struct md_proc_file *file=md_proc_file_open_control(&ops,&probe,&t.identity,O_RDWR); assert(file);
        assert(md_proc_file_io_begin(&t.proc_io,file,seek ? MD_PROC_FILE_SEEK : MD_PROC_FILE_WRITE,
            0,seek ? 7 : 0,SEEK_SET,seek ? 0 : 4,NULL)==1);
        struct md_buffer_span span; assert(!md_buffer_span(&t.buffer,&span));
        memcpy(span.data,"data",4);
        long expected=seek ? 7 : 4;
        assert(md_proc_file_io_execute(&t.proc_io,&t.identity,NULL,span.data,span.size,4096)==expected);
        assert(!md_proc_file_io_offer(&t.proc_io));
        assert(proc_io_complete(&t,0,expected)==expected);
        assert(!probe.commits && !t.proc_io.file && !t.buffer.pool);
        md_proc_file_release(file);
    }
    md_buffers_release(pool);
    puts("PASS terminal buffer completion: commit before release, partial copy, EFAULT, failed finish and independent cleanup error");
}
static void buffered_io_pressure(void) {
    struct thread t={.pid=123,.phase=DISPATCHING,.memory=md_memory_new(),.buffer_waiting=1};
    assert(t.memory && !md_memory_buffers_prepare(t.memory,1,4096,0,0));
    t.buffer_registers.regs[0]=MD_BUFFER_PROC_START;
    t.buffer_registers.regs[1]=4;
    struct md_interception_buffer held={0};
    assert(!md_buffers_take(md_memory_buffers(t.memory),&held));
    buffer_take(&t);
    assert(t.buffer_waiting && !t.buffer.pool && !t.proc_io.file && !t.proc_io.turn.queue);
    assert(t.retries[RETRY_BUFFER>=RETRY_FD].mask==RETRY_BUFFER);
    /* Cancellation while waiting has neither provider work nor a buffer to
     * retire; freeing capacity cannot resurrect the removed continuation. */
    retry_clear(&t,RETRY_BUFFER); t.buffer_waiting=0;
    assert(!md_buffer_release(&held));
    assert(!md_buffers_take(md_memory_buffers(t.memory),&held));
    assert(!md_buffer_release(&held));
    md_memory_release(t.memory);
    puts("PASS buffered IO pressure: no OFD turn before buffer admission and cancelled continuation stays retired");
}
static void captured_writes(void) {
    struct thread t={.pid=getpid(),.memory=md_memory_new()};
    assert(t.memory && !md_memory_buffers_prepare(t.memory,1,sizeof(struct md_fs_buffer_frame),0,0));
    const struct md_control_file_ops ops={.retain=completion_retain,.release=completion_release,
        .access=completion_access,.write=completion_write};
    t.proc_file=md_proc_file_open_control(&ops,&t,&t.identity,O_WRONLY); assert(t.proc_file);
    char bytes[MD_CONTROL_IO_MAX]; memset(bytes,'x',sizeof(bytes)); memcpy(bytes,"data",4);
    size_t total;
    for (unsigned vector=0;vector<2;++vector) {
        struct iovec iov[3]={{(void *)1,0},{bytes,2},{bytes+2,2}};
        t.original.regs[8]=vector ? SYS_writev : SYS_write;
        t.original.regs[1]=(uintptr_t)(vector ? (void *)iov : bytes);
        t.original.regs[2]=vector ? 3 : 4;
        assert(proc_write_capture(&t,&total) && total==4);
        struct md_buffer_span span; assert(!md_buffer_span(&t.buffer,&span));
        assert(!memcmp(span.data,"data",4) && !t.proc_io.file && !t.proc_io.turn.queue);
        assert(!md_buffer_release(&t.buffer));
        struct md_interception_buffer held={0};
        assert(!md_buffers_take(md_memory_buffers(t.memory),&held));
        assert(!proc_write_capture(&t,&total) && !t.buffer.pool && !t.proc_io.file);
        assert(!md_buffer_release(&held));
    }
    struct iovec iov[3]={{bytes,sizeof(bytes)},{(void *)1,10}};
    t.original.regs[1]=(uintptr_t)iov; t.original.regs[2]=2;
    /* Only the prefix accepted by control IO is copied; untouched trailing
     * vectors cannot cause a fault or change the amount offered to the OFD. */
    assert(proc_write_capture(&t,&total) && total==sizeof(bytes)+10);
    struct md_buffer_span span; assert(!md_buffer_span(&t.buffer,&span));
    assert(!memcmp(span.data,bytes,sizeof(bytes)) && !md_buffer_release(&t.buffer));
    for (unsigned mode=0;mode<6;++mode) {
        iov[0]=(struct iovec){bytes,2}; iov[1]=(struct iovec){bytes+2,2};
        t.original.regs[1]=(uintptr_t)iov; t.original.regs[2]=2;
        if (mode==0) iov[1].iov_base=(void *)1;
        if (mode==1) t.original.regs[1]=1;
        if (mode==2) t.original.regs[2]=MD_PROC_IO_VECTORS+1;
        if (mode==3) iov[0].iov_len=PTRDIFF_MAX;
        if (mode==4) iov[0].iov_len=iov[1].iov_len=0;
        if (mode==5) t.debug_call_active=1;
        assert(!proc_write_capture(&t,&total) && !t.buffer.pool && !t.proc_io.file);
        t.debug_call_active=0;
    }
    size_t page=(size_t)getpagesize();
    char *mapping=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(mapping!=MAP_FAILED && !mprotect(mapping+page,page,PROT_NONE));
    t.original.regs[8]=SYS_write; t.original.regs[1]=(uintptr_t)(mapping+page-2); t.original.regs[2]=4;
    assert(!proc_write_capture(&t,&total) && !t.buffer.pool && !t.proc_io.file);
    assert(!munmap(mapping,page*2));
    int ready[2]; assert(!pipe(ready));
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        close(ready[0]); assert(!prctl(PR_SET_DUMPABLE,0,0,0,0));
        assert(write(ready[1],"x",1)==1); for (;;) pause();
    }
    close(ready[1]); char value; assert(read(ready[0],&value,1)==1); close(ready[0]);
    t.pid=child; t.original.regs[1]=(uintptr_t)bytes;
    assert(!proc_write_capture(&t,&total) && !t.buffer.pool && !t.proc_io.file);
    assert(!kill(child,SIGKILL)); int status; assert(waitpid(child,&status,0)==child && WIFSIGNALED(status));
    md_proc_file_release(t.proc_file); md_memory_release(t.memory);
    puts("PASS write capture: scalar/vector prefix, empty vector, overflow, partial fault, protected caller and pressure without IO effects");
}
static void repair_events(void) {
    struct thread caller={.pid=123,.phase=OBSERVING,.memory_action=MEMORY_KERNEL};
    caller.original.regs[8]=SYS_mprotect;
    thread_index[caller.pid%THREAD_BUCKETS]=&caller;
    struct thread actor={.pid=456};
    struct mapping_owner mapping={.caller=actor.pid};
    struct task_action action={.actor=&actor};
    struct memory_execution memory={.actor=&actor};
    int status=(SIGTRAP|0x80)<<8|0x7f;
    struct rusage usage={.ru_stime.tv_usec=789};
    assert(!quiescence_repair_event(caller.pid,status,&usage));
    for (unsigned mode=0;mode<5;++mode) {
        struct md_task_quiesce **barrier;
        if (!mode) { entry_fence_stage=1; barrier=&entry_fence_barrier; }
        else if (mode==1) { memory_execution=&memory; barrier=&memory_barrier; }
        else if (mode==2) { task_action_execution=&action; barrier=&task_action_barrier; }
        else {
            mapping_execution=&mapping; barrier=&mapping_barrier;
            if (mode==4) task_action_execution=&action;
        }
        *barrier=md_task_quiesce_new(no_trace); assert(*barrier);
        caller.original.regs[8]=SYS_mmap;
        assert(!quiescence_repair_event(caller.pid,status,&usage));
        caller.original.regs[8]=SYS_mprotect;
        assert(!quiescence_repair_event(caller.pid,(SIGUSR1<<8)|0x7f,&usage));
        assert(!quiescence_repair_event(caller.pid,(PTRACE_EVENT_EXIT<<16)|(SIGTRAP<<8)|0x7f,&usage));
        memory.actor=&caller; action.actor=&caller; mapping.caller=caller.pid;
        if (mode) assert(!quiescence_repair_event(caller.pid,status,&usage));
        memory.actor=&actor; action.actor=&actor; mapping.caller=actor.pid;
        assert(quiescence_repair_event(caller.pid,status,&usage));
        assert(md_task_quiesce_contains(*barrier,caller.pid));
        assert(!md_task_quiesce_contains(*barrier,actor.pid));
        assert(md_task_quiesce_ready(*barrier));
        assert(!md_task_quiesce_release(*barrier));
        int replay=0; struct rusage replay_usage={0};
        assert(md_task_quiesce_take(*barrier,&replay,&replay_usage)==caller.pid);
        assert(replay==status && replay_usage.ru_stime.tv_usec==789);
        assert(!md_task_quiesce_take(*barrier,&replay,&replay_usage));
        md_task_quiesce_destroy(*barrier); *barrier=NULL;
        entry_fence_stage=0; memory_execution=NULL; task_action_execution=NULL; mapping_execution=NULL;
    }
    thread_index[caller.pid%THREAD_BUCKETS]=NULL;
    puts("PASS supervisor repair deferral: every owner, nested mapping, exact replay and unrelated progress");
}
static void event_accounting(void) {
    struct rusage usage,zero={0}; int status;
    for (unsigned round=0;round<3;++round) {
        accounting_enabled=round==1;
        memset(&usage,0xa5,sizeof(usage));
        assert(kernel_event(&status,&usage)==wait_result);
        assert(accounting_requested==accounting_enabled);
        if (accounting_enabled) assert(usage.ru_utime.tv_usec==123 && usage.ru_maxrss==456);
        else assert(!memcmp(&usage,&zero,sizeof(usage)));
        struct md_task_quiesce *queue=md_task_quiesce_new(no_trace); assert(queue);
        assert(!md_task_quiesce_event(queue,wait_result,status,&usage));
        accounting_enabled=!accounting_enabled;
        struct rusage replay;
        assert(md_task_quiesce_take(queue,&status,&replay)==wait_result);
        assert(!memcmp(&replay,&usage,sizeof(usage)));
        md_task_quiesce_destroy(queue);
    }
    accounting_enabled=0;
    assert(kernel_event(&status,NULL)==wait_result && !accounting_requested);
    puts("PASS supervisor accounting: absent, present, detach and deferred events survive debugger changes");
}
static volatile sig_atomic_t received;
static void receive_signal(int signal,siginfo_t *info,void *context) {
    (void)context;
    if ((signal!=SIGRTMAX && signal!=SIGUSR1) || info->si_code!=SI_QUEUE
            || info->si_value.sival_int!=77 || ++received!=1) _exit(92);
}
static void completed_open(unsigned mode,int signal) {
    received=0; adoption_calls=0; adoption_error=mode==1 ? -ENOMEM : mode==2 ? -ESTALE : 0;
    pid_t pid=fork(); assert(pid>=0);
    if (!pid) {
        struct sigaction handler={.sa_sigaction=receive_signal,.sa_flags=SA_SIGINFO};
        sigemptyset(&handler.sa_mask); assert(!sigaction(signal,&handler,NULL));
        assert(!ptrace(PTRACE_TRACEME,0,NULL,NULL));
        (void)raise(SIGSTOP);
        while (!received) pause();
        _exit(received!=1);
    }
    int status;
    assert(waitpid(pid,&status,0)==pid && WIFSTOPPED(status) && WSTOPSIG(status)==SIGSTOP);
    assert(!ptrace(PTRACE_SETOPTIONS,pid,NULL,(void *)(uintptr_t)PTRACE_O_EXITKILL));
    union sigval value={.sival_int=77}; assert(!sigqueue(pid,signal,value));
    assert(!ptrace(PTRACE_CONT,pid,NULL,NULL));
    assert(waitpid(pid,&status,0)==pid && WIFSTOPPED(status) && WSTOPSIG(status)==signal);
    struct user_pt_regs saved;
    struct iovec io={&saved,sizeof(saved)};
    assert(!ptrace(PTRACE_GETREGSET,pid,(void *)NT_PRSTATUS,&io));
    struct thread t={.pid=pid,.tgid=pid,.phase=IDLE,.memory=md_memory_new()};
    thread_index[(unsigned)pid%THREAD_BUCKETS]=&t;
    assert(t.memory && !md_memory_buffers_prepare(t.memory,1,4096,0,0));
    struct md_interception_buffer held={0};
    if (!mode) assert(!md_buffers_take(md_memory_buffers(t.memory),&held));
    t.broker_completion=calloc(1,sizeof(*t.broker_completion)); assert(t.broker_completion);
    t.broker_completion->call=(struct seccomp_data){.nr=SYS_openat,.arch=AUDIT_ARCH_AARCH64,
        .instruction_pointer=saved.pc};
    t.broker_completion->opened.fd=open("/dev/null",O_RDONLY|O_CLOEXEC);
    assert(t.broker_completion->opened.fd>=0);
    struct rusage usage={0};
    assert(completed_notification_event(&t,status,&usage)==(mode==3));
    assert(!t.broker_completion && adoption_calls==(mode!=0));
    if (mode!=3) {
        assert(!t.broker_event.held && !t.buffer.pool && !t.buffer_call);
        assert(!md_signal_delivery_pending(&t.signal_delivery) && !t.retained_signal);
        struct user_pt_regs result;
        io=(struct iovec){&result,sizeof(result)};
        assert(!ptrace(PTRACE_GETREGSET,pid,(void *)NT_PRSTATUS,&io));
        assert((long)result.regs[0]==(!mode ? -EAGAIN : adoption_error));
        assert(!ptrace(PTRACE_CONT,pid,NULL,(void *)(intptr_t)signal));
    } else {
        assert(t.broker_event.held && t.buffer.pool && t.buffer_call);
        assert(md_signal_delivery_pending(&t.signal_delivery));
        /* Simulate worker completion at an internal checkpoint. The old
         * delivery stop is suppressed; only the queue publishes the signal. */
        assert(!md_signal_delivery_publish(&t.signal_delivery,pid,pid));
        assert(!ptrace(PTRACE_CONT,pid,NULL,NULL));
        assert(waitpid(pid,&status,0)==pid && WIFSTOPPED(status) && WSTOPSIG(status)==signal);
        int deliver=signal;
        assert(md_signal_delivery_event(&t.signal_delivery,pid,signal,&deliver)>=0);
        assert(deliver==signal && !md_signal_delivery_pending(&t.signal_delivery));
        assert(!ptrace(PTRACE_CONT,pid,NULL,(void *)(intptr_t)deliver));
        md_fs_buffer_open_release(&adopted); t.buffer_call=NULL;
    }
    assert(waitpid(pid,&status,0)==pid && WIFEXITED(status) && !WEXITSTATUS(status));
    assert(!md_buffer_release(&held) && !md_buffer_release(&t.buffer));
    md_signal_delivery_clear(&t.signal_delivery); md_memory_release(t.memory);
    thread_index[(unsigned)pid%THREAD_BUCKETS]=NULL;
}
extern void test_wait_svc(void);
__asm__(".text\n.balign 4\ntest_wait_svc:\nsvc #0\nret\n");
static void provider_wait_boundaries(void) {
    const enum phase phases[]={FILE_WAIT_ENTRY,CONTROL_WAIT_ENTRY,CLOSE_WAIT_ENTRY};
    uintptr_t saved_gate=abi.raw_gate;
    abi.raw_gate=(uintptr_t)test_wait_svc+4;
    for (unsigned p=0;p<sizeof(phases)/sizeof(*phases);++p) for (unsigned pending_exit=0;pending_exit<2;++pending_exit) {
        pid_t pid=fork(); assert(pid>=0);
        if (!pid) {
            pid_t expected=getpid();
            assert(!ptrace(PTRACE_TRACEME,0,NULL,NULL));
            raise(SIGSTOP);
            struct sock_filter code[]={
                BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
                BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_getpid,0,1),
                BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_TRACE),
                BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
            };
            struct sock_fprog filter={sizeof(code)/sizeof(*code),code};
            assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
            assert(!prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&filter));
            _exit(syscall(SYS_getpid)!=expected);
        }
        int status;
        assert(waitpid(pid,&status,0)==pid && WIFSTOPPED(status));
        assert(!ptrace(PTRACE_SETOPTIONS,pid,NULL,(void *)(uintptr_t)
            (PTRACE_O_EXITKILL|PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACESECCOMP)));
        assert(!ptrace(PTRACE_CONT,pid,NULL,NULL));
        assert(waitpid(pid,&status,0)==pid && (unsigned)status>>16==PTRACE_EVENT_SECCOMP);
        struct thread t={.pid=pid,.phase=phases[p]};
        assert(registers(pid,&t.original) && skip(pid));
        t.buffer_registers=t.close_registers=t.original;
        if (!pending_exit) {
            assert(!ptrace(PTRACE_SYSCALL,pid,NULL,NULL));
            assert(waitpid(pid,&status,0)==pid && WSTOPSIG(status)==(SIGTRAP|0x80));
        }
        struct user_pt_regs poll=wait_poll_registers(&t,t.phase);
        assert(set_registers(pid,&poll));
        assert(!ptrace(PTRACE_SYSCALL,pid,NULL,NULL));
        assert(waitpid(pid,&status,0)==pid && WSTOPSIG(status)==(SIGTRAP|0x80));
        if (pending_exit) {
            assert(!wait_poll_entry(&t) && t.phase==phases[p]);
            assert(!ptrace(PTRACE_SYSCALL,pid,NULL,NULL));
            assert(waitpid(pid,&status,0)==pid && WSTOPSIG(status)==(SIGTRAP|0x80));
        }
        assert(wait_poll_entry(&t)==1);
        struct user_pt_regs entered;
        assert(registers(pid,&entered));
        for (unsigned i=0;i<5;++i) assert(!entered.regs[i]);
        /* Provider completion may precede entry. Cancel only the actual poll,
         * drain its exit, then publish the application's retained result. */
        assert(skip(pid));
        assert(!ptrace(PTRACE_SYSCALL,pid,NULL,NULL));
        assert(waitpid(pid,&status,0)==pid && WSTOPSIG(status)==(SIGTRAP|0x80));
        t.original.regs[0]=pid;
        assert(set_registers(pid,&t.original));
        assert(!ptrace(PTRACE_CONT,pid,NULL,NULL));
        assert(waitpid(pid,&status,0)==pid && WIFEXITED(status) && !WEXITSTATUS(status));
    }
    abi.raw_gate=saved_gate;
    puts("PASS provider wait: seccomp exit drain, post-exit entry, poll arguments and cancelled completion");
}
int main(void) {
    alarm(30);
    barrier_admission(); readiness_admission_order(); entry_fence_ownership(); control_deadlines(); terminal_buffer_completion(); buffered_io_pressure(); captured_writes(); repair_events(); event_accounting();
    for (unsigned mode=0;mode<4;++mode) {
        completed_open(mode,SIGUSR1); completed_open(mode,SIGRTMAX);
    }
    provider_wait_boundaries();
    md_task_checkpoints_clear(&checkpoints);
    puts("PASS supervisor completed open: exhausted buffer, failed adoption and single standard/realtime delivery");
    return 0;
}

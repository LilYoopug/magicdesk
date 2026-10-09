#define _GNU_SOURCE
#include "file_open_job.h"
#include "fs_wire.h"
#include "raw.h"
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

static int isolate_proc(const unsigned *keep, unsigned count) {
    long directory=RAW4(openat,AT_FDCWD,"/proc/self/fd",O_RDONLY|O_DIRECTORY|O_CLOEXEC,0);
    if (directory<0) return (int)directory;
    struct entry { uint64_t inode; int64_t offset; unsigned short size; unsigned char type; char name[]; };
    _Alignas(struct entry) char bytes[4096];
    int error=0;
    for (;;) {
        long size=RAW3(getdents64,directory,bytes,sizeof(bytes));
        if (size<=0) { error=(int)size; break; }
        for (long at=0;at<size;) {
            const struct entry *e=(void *)(bytes+at);
            if (size-at<(long)offsetof(struct entry,name)+2 || e->size<offsetof(struct entry,name)+2
                    || e->size>size-at) { error=-EIO; break; }
            if (e->name[0]>='0' && e->name[0]<='9') {
                unsigned number=0;
                size_t n=0,limit=e->size - offsetof(struct entry,name);
                while (n<limit && e->name[n]>='0' && e->name[n]<='9') {
                    if (number>((unsigned)INT_MAX-9)/10) { error=-EIO; break; }
                    number=number*10+(unsigned)(e->name[n++]-'0');
                }
                if (error || n==limit || e->name[n]) { error=-EIO; break; }
                int retained=number==(unsigned)directory;
                for (unsigned i=0;i<count;++i) retained|=number==keep[i];
                if (!retained) RAW1(close,number);
            }
            at+=e->size;
        }
        if (error) break;
    }
    RAW1(close,directory); return error;
}
static int isolate(int pin, int control, int channel) {
    unsigned keep[3]={(unsigned)pin,(unsigned)channel,(unsigned)control};
    unsigned count=control>=0 ? 3 : 2;
    for (unsigned i=0;i<count;++i) for (unsigned j=i+1;j<count;++j)
        if (keep[j]<keep[i]) { unsigned n=keep[i]; keep[i]=keep[j]; keep[j]=n; }
    unsigned from=0;
    for (unsigned i=0;i<=count;++i) {
        unsigned to=i<count ? keep[i] : UINT_MAX;
        if (from<to || i==count) {
            long r=RAW3(close_range,from,i<count ? to-1 : to,0);
            if (r==-ENOSYS) return isolate_proc(keep,count);
            if (r<0) return (int)r;
        }
        from=to+1;
    }
    return 0;
}
int md_open_job_start(struct md_open_job *job, int pin, int flags, struct md_open_completion completion) {
    if (!job || job->pid || pin<0 || (completion.kind!=MD_OPEN_PIPE && completion.kind!=MD_OPEN_FIFO)
            || (completion.kind==MD_OPEN_PIPE && completion.control<0)) return -EINVAL;
    int pair[2];
    if (socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,pair)) return -errno;
    pid_t parent=getpid(), child=fork();
    if (!child) {
        /* After fork from a multithreaded supervisor, only raw syscalls and
         * stack-only helpers run; no allocator, SQLite, pthread or logging. */
        long r=RAW2(prctl,PR_SET_PDEATHSIG,SIGKILL);
        if (!r && RAW0(getppid)!=parent) r=-ECANCELED;
        if (!r) r=isolate(pin,completion.kind==MD_OPEN_PIPE ? completion.control : -1,pair[1]);
        if (!r) r=md_complete_open(pin,flags|O_CLOEXEC,completion);
        struct md_fs_rights rights={0};
        int error=r<0 ? (int)r : 0;
        if (!error) { rights.count=1; rights.fd[0]=(int)r; }
        long sent=md_fs_send(pair[1],&error,sizeof(error),&rights);
        RAW1(exit_group,sent==sizeof(error) ? 0 : 125);
        __builtin_unreachable();
    }
    int error=child<0 ? -errno : 0;
    close(pair[1]);
    if (error) close(pair[0]);
    else *job=(struct md_open_job){.pid=child,.channel=pair[0]};
    return error;
}
int md_open_job_cancel(struct md_open_job *job) {
    if (!job || !job->pid || job->cancelled) return 0;
    if (kill(job->pid,SIGKILL) && errno!=ESRCH) return -errno;
    job->cancelled=1;
    close(job->channel); job->channel=-1;
    return 0;
}
int md_open_job_finish(struct md_open_job *job, int status) {
    if (!job || !job->pid || (!WIFEXITED(status) && !WIFSIGNALED(status))) return -EINVAL;
    int result=-ECANCELED;
    if (!job->cancelled) {
        struct md_fs_rights rights={0};
        int error=0;
        long received=md_fs_receive(job->channel,&error,sizeof(error),&rights);
        if (!WIFEXITED(status) || WEXITSTATUS(status)) result=-EIO;
        else if (received!=sizeof(error) || error>0 || error < -4095
                || rights.count!=(unsigned)!error) result=-EPROTO;
        else if (error) result=error;
        else { result=rights.fd[0]; rights.count=0; }
        md_fs_close_rights(&rights); close(job->channel);
    }
    *job=(struct md_open_job){0}; return result;
}

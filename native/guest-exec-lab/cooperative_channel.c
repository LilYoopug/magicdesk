#define _GNU_SOURCE
#include "cooperative_channel.h"
#include "fs_wire.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

_Static_assert(ATOMIC_INT_LOCK_FREE==2,"shared futex state must be lock-free");
_Static_assert(sizeof(atomic_uint)==4,"Linux futex word size");
static int64_t now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC,&value)) return -1;
    return (int64_t)value.tv_sec*1000000000+value.tv_nsec;
}
static int wait_state(struct md_cooperative_channel *channel,unsigned state,int64_t deadline,unsigned side,
        void (*before_wait)(void *),void *context) {
    int64_t current=now(),left=deadline-current;
    if (current<0) return -EIO;
    if (left<=0) return -ETIMEDOUT;
    unsigned budget=side && channel->receive_spin_override ? channel->receive_spin_ns : channel->spin_ns;
    if (state==MD_COOPERATIVE_DELEGATED
            || (side && state==MD_COOPERATIVE_RECEIPT)
            || (side && channel->park_owner_handoff && state==MD_COOPERATIVE_RUNNING)) budget=0;
    if (channel->adaptive_spin) budget=md_spin_budget(&channel->feedback[side],budget);
    if (budget) {
        int64_t until=current+budget;
        int attempted=0;
        if (until>deadline) until=deadline;
        /* Experimental bounded handoff only: idle peers still sleep in futex.
         * Check time every 32 loads; never keep a CPU busy for an idle channel. */
        do {
            for (unsigned i=0;i<32;++i) {
                unsigned observed=atomic_load_explicit(&channel->state,memory_order_acquire);
                if (observed!=state) {
                    if (channel->adaptive_spin && attempted)
                        md_spin_observed(&channel->feedback[side],
                            observed==(side ? MD_COOPERATIVE_REQUEST : MD_COOPERATIVE_RESPONSE),now(),until);
                    return 0;
                }
                attempted=1;
            }
            current=now();
            if (current<0) return -EIO;
        } while (current<until);
        if (channel->adaptive_spin) md_spin_result(&channel->feedback[side],0);
        left=deadline-current;
        if (left<=0) return -ETIMEDOUT;
    }
    struct timespec timeout={left/1000000000,left%1000000000};
    unsigned event=atomic_load_explicit(&channel->event[side],memory_order_acquire);
    if (before_wait) before_wait(context);
    /* SC registration and state publication prohibit both peers missing each
     * other. A change after this recheck makes FUTEX_WAIT return EAGAIN. */
    atomic_store_explicit(&channel->sleeping[side],1,memory_order_seq_cst);
    int error=0;
    /* EVENT_WAIT: peer changes the shared request/receipt state. Timeout fails
     * the channel; it never authorizes replay of a published mutation. */
    if (atomic_load_explicit(&channel->state,memory_order_seq_cst)==state
            && syscall(SYS_futex,&channel->event[side],FUTEX_WAIT,event,&timeout,NULL,0)<0)
        error=errno==EAGAIN || errno==EINTR ? 0 : -errno;
    atomic_store_explicit(&channel->sleeping[side],0,memory_order_seq_cst);
    return error;
}
static int wake(struct md_cooperative_channel *channel,unsigned side) {
    if (channel->selective_wake && !atomic_load_explicit(&channel->sleeping[side],memory_order_seq_cst)) return 0;
    atomic_fetch_add_explicit(&channel->event[side],1,memory_order_seq_cst);
    return syscall(SYS_futex,&channel->event[side],FUTEX_WAKE,1,NULL,NULL,0)<0 ? -errno : 0;
}
static int capture(struct md_cooperative_request *out,const struct md_cooperative_request *in) {
    uint32_t length[2]={in->length[0],in->length[1]};
    for (unsigned i=0;i<2;++i) if (!length[i] || length[i]>PATH_MAX) return -EPROTO;
    out->sequence=in->sequence; out->syscall=in->syscall;
    out->flags=in->flags; out->mode=in->mode;
    for (unsigned i=0;i<2;++i) {
        out->length[i]=length[i];
        memcpy(out->path[i],in->path[i],length[i]);
        if (out->path[i][length[i]-1] || memchr(out->path[i],0,length[i]-1)) return -EPROTO;
    }
    return 0;
}
void md_cooperative_client_init(struct md_cooperative_client *client,struct md_cooperative_channel *channel,int delivery) {
    client->channel=channel; client->tid=(pid_t)syscall(SYS_gettid); client->sequence=0;
    client->delivery=delivery; client->closer=NULL;
    atomic_flag_clear(&client->busy);
}
int md_cooperative_sync(struct md_cooperative_client *client) {
    struct md_cooperative_channel *channel=client->channel;
    int64_t start=now();
    if (start<0) return -EIO;
    for (;;) {
        if (channel->completion_queue) {
            unsigned read=atomic_load_explicit(&channel->completion_read,memory_order_acquire);
            if (read!=atomic_load_explicit(&channel->completion_write,memory_order_acquire)) {
                int64_t left=start+10000000000LL-now();
                if (left<=0) return -ETIMEDOUT;
                struct timespec timeout={left/1000000000,left%1000000000};
                atomic_store_explicit(&channel->completion_waiting,1,memory_order_seq_cst);
                md_cooperative_notify_owner(channel);
                int error=0;
                /* EVENT_WAIT: owner consumes ordered completion records. A
                 * full queue or explicit flush waits, never ordinary close. */
                if (atomic_load_explicit(&channel->completion_read,memory_order_seq_cst)==read
                        && syscall(SYS_futex,&channel->completion_read,FUTEX_WAIT,read,&timeout,NULL,0)<0)
                    error=errno==EAGAIN || errno==EINTR ? 0 : -errno;
                atomic_store_explicit(&channel->completion_waiting,0,memory_order_seq_cst);
                if (error) return error;
                continue;
            }
        }
        unsigned state=atomic_load_explicit(&channel->state,memory_order_acquire);
        if (channel->completion_queue) return state==MD_COOPERATIVE_CLOSED ? -ESHUTDOWN : 0;
        if (state==MD_COOPERATIVE_IDLE) return 0;
        if (state!=MD_COOPERATIVE_RECEIPT) return state==MD_COOPERATIVE_CLOSED ? -ESHUTDOWN : -EBUSY;
        int error=wait_state(channel,state,start+10000000000LL,0,NULL,NULL);
        if (error) return error;
    }
}
static int completion_reserve(struct md_cooperative_client *client) {
    struct md_cooperative_channel *channel=client->channel;
    unsigned write=atomic_load_explicit(&channel->completion_write,memory_order_relaxed);
    return write-atomic_load_explicit(&channel->completion_read,memory_order_acquire)==64
        ? md_cooperative_sync(client) : 0;
}
static int completion_publish(struct md_cooperative_client *client,const struct md_cooperative_completion *result) {
    struct md_cooperative_channel *channel=client->channel;
    unsigned write=atomic_load_explicit(&channel->completion_write,memory_order_relaxed);
    /* One producer with its reentry guard held reserves before the native
     * side effect. No allocation or acknowledgement is needed afterwards. */
    channel->completions[write%64]=*result;
    atomic_store_explicit(&channel->completion_write,write+1,memory_order_release);
    md_cooperative_notify_owner(channel);
    return 0;
}
int md_cooperative_completion_peek(struct md_cooperative_channel *channel,struct md_cooperative_completion *out) {
    unsigned read=atomic_load_explicit(&channel->completion_read,memory_order_relaxed);
    if (read==atomic_load_explicit(&channel->completion_write,memory_order_acquire)) return 0;
    *out=channel->completions[read%64]; return 1;
}
void md_cooperative_completion_consume(struct md_cooperative_channel *channel) {
    atomic_fetch_add_explicit(&channel->completion_read,1,memory_order_seq_cst);
    if (atomic_load_explicit(&channel->completion_waiting,memory_order_seq_cst))
        (void)syscall(SYS_futex,&channel->completion_read,FUTEX_WAKE,1,NULL,NULL,0);
}
int md_cooperative_receipt_complete(struct md_cooperative_channel *channel) {
    unsigned state=MD_COOPERATIVE_RECEIPT;
    if (!atomic_compare_exchange_strong_explicit(&channel->state,&state,MD_COOPERATIVE_IDLE,
            memory_order_seq_cst,memory_order_relaxed)) return -ECANCELED;
    return wake(channel,0);
}
struct md_cooperative_response md_cooperative_call(struct md_cooperative_client *client,
        const struct md_cooperative_request *request) {
    struct md_cooperative_response out={.outcome=MD_COOPERATIVE_DECLINED,.fd=-1};
    if (client->tid!=(pid_t)syscall(SYS_gettid)) { out.error=-EXDEV; return out; }
    if (atomic_flag_test_and_set_explicit(&client->busy,memory_order_acquire)) {
        out.error=-EBUSY; return out;
    }
    struct md_cooperative_channel *channel=client->channel;
    if (channel->completion_queue && request->syscall==SYS_close) {
        if (atomic_load_explicit(&channel->state,memory_order_acquire)!=MD_COOPERATIVE_IDLE) {
            out.error=-ESHUTDOWN; goto done;
        }
        out.error=completion_reserve(client);
        if (out.error) goto done;
        int result=close((int)request->flags) ? -errno : 0;
        struct md_cooperative_completion completion={.kind=MD_COOPERATIVE_CLOSED_FD,
            .fd=(int)request->flags,.error=result};
        out.error=completion_publish(client,&completion);
        out.outcome=out.error ? MD_COOPERATIVE_UNKNOWN : MD_COOPERATIVE_COMPLETED;
        if (!out.error) out.error=result;
        goto done;
    }
    if (channel->prepared_open && !channel->completion_queue) {
        out.error=md_cooperative_sync(client);
        if (out.error) goto done;
    }
    if (atomic_load_explicit(&channel->state,memory_order_acquire)!=MD_COOPERATIVE_IDLE) {
        out.error=-ESHUTDOWN; goto done;
    }
    out.error=capture(&channel->request,request);
    if (out.error) goto done;
    if (client->sequence==UINT64_MAX) { out.error=-EOVERFLOW; goto done; }
    int64_t start=now();
    if (start<0) { out.error=-EIO; goto done; }
    out.sequence=channel->request.sequence=++client->sequence;
    unsigned idle=MD_COOPERATIVE_IDLE;
    if (!atomic_compare_exchange_strong_explicit(&channel->state,&idle,MD_COOPERATIVE_REQUEST,
            memory_order_seq_cst,memory_order_relaxed)) { out.error=-ESHUTDOWN; goto done; }
    out.outcome=MD_COOPERATIVE_UNKNOWN;
    out.error=wake(channel,1);
    int64_t deadline=start+10000000000LL;
    while (!out.error) {
        unsigned state=atomic_load_explicit(&channel->state,memory_order_acquire);
        if (state==MD_COOPERATIVE_RESPONSE) {
            out=channel->response;
            if (out.outcome==MD_COOPERATIVE_PLAN && channel->prepared_open) {
                if (out.sequence!=client->sequence || out.error || out.fd!=-1
                        || out.open_plan.owner<=0 || out.open_plan.pin<0
                        || out.open_plan.flags!=(O_RDONLY|O_CLOEXEC)) {
                    out.outcome=MD_COOPERATIVE_UNKNOWN; out.error=-EPROTO; break;
                }
                if (channel->completion_queue) {
                    out.error=completion_reserve(client);
                    if (out.error) { out.outcome=MD_COOPERATIVE_UNKNOWN; break; }
                }
                char path[80];
                snprintf(path,sizeof(path),"/proc/%d/fd/%d",out.open_plan.owner,out.open_plan.pin);
                out.fd=open(path,out.open_plan.flags);
                out.error=out.fd<0 ? -errno : 0;
                if (out.fd>=0) {
                    struct stat st;
                    if (fstat(out.fd,&st)) out.error=-errno;
                    else if ((uint64_t)st.st_dev!=out.open_plan.device || (uint64_t)st.st_ino!=out.open_plan.inode)
                        out.error=-ESTALE;
                    if (out.error) { close(out.fd); out.fd=-1; }
                }
                out.outcome=MD_COOPERATIVE_COMPLETED;
                if (channel->completion_queue) {
                    struct md_cooperative_completion completion={.kind=MD_COOPERATIVE_OPENED,
                        .sequence=out.sequence,.fd=out.fd,.error=out.error};
                    int error=completion_publish(client,&completion);
                    if (error) { out.error=error; out.outcome=MD_COOPERATIVE_UNKNOWN; break; }
                    atomic_store_explicit(&channel->state,MD_COOPERATIVE_IDLE,memory_order_release);
                    goto done;
                }
                channel->response=out;
                atomic_store_explicit(&channel->state,MD_COOPERATIVE_RECEIPT,memory_order_seq_cst);
                int error=wake(channel,1);
                if (error) { out.error=error; out.outcome=MD_COOPERATIVE_UNKNOWN; break; }
                goto done;
            }
            int rights=out.fd; out.fd=-1;
            if (out.sequence!=client->sequence || (out.outcome!=MD_COOPERATIVE_DECLINED
                    && out.outcome!=MD_COOPERATIVE_COMPLETED) || rights < -1
                    || (!channel->shared_files && rights > 0)
                    || (rights>=0 && (out.outcome!=MD_COOPERATIVE_COMPLETED || out.error))) {
                out.outcome=MD_COOPERATIVE_UNKNOWN; out.error=-EPROTO; break;
            }
            if (channel->shared_files) out.fd=rights;
            else if (rights==0) {
                uint64_t sequence=0; int fd=-1; unsigned count=0;
                long size=md_fs_receive_fds(client->delivery,&sequence,sizeof(sequence),&fd,1,&count);
                if (size!=sizeof(sequence) || count!=1 || sequence!=out.sequence) {
                    if (count) close(fd);
                    out.outcome=MD_COOPERATIVE_UNKNOWN; out.error=size<0 ? (int)size : -EPROTO; break;
                }
                out.fd=fd;
            }
            atomic_store_explicit(&channel->state,MD_COOPERATIVE_IDLE,memory_order_release);
            goto done;
        }
        if (state==MD_COOPERATIVE_CLOSED) { out.error=-ESHUTDOWN; break; }
        out.error=wait_state(channel,state,deadline,0,NULL,NULL);
    }
    md_cooperative_close(channel);
done:
    atomic_flag_clear_explicit(&client->busy,memory_order_release);
    return out;
}
int md_cooperative_receive(struct md_cooperative_channel *channel,struct md_cooperative_request *request,
        void (*before_wait)(void *),void *context) {
    int64_t start=now();
    if (start<0) return -EIO;
    int64_t deadline=start+10000000000LL;
    for (;;) {
        unsigned state=atomic_load_explicit(&channel->state,memory_order_acquire);
        if (state==MD_COOPERATIVE_CLOSED) return 0;
        if (state==MD_COOPERATIVE_REQUEST) {
            if (!atomic_compare_exchange_strong_explicit(&channel->state,&state,MD_COOPERATIVE_RUNNING,
                    memory_order_acquire,memory_order_relaxed)) continue;
            int error=capture(request,&channel->request);
            return error ? error : 1;
        }
        int error=wait_state(channel,state,deadline,1,before_wait,context);
        if (error) return error;
    }
}
int md_cooperative_delegate(struct md_cooperative_channel *channel) {
    unsigned state=MD_COOPERATIVE_RUNNING;
    return atomic_compare_exchange_strong_explicit(&channel->state,&state,MD_COOPERATIVE_DELEGATED,
        memory_order_seq_cst,memory_order_relaxed) ? 0 : -ECANCELED;
}
int md_cooperative_post(struct md_cooperative_channel *channel,const struct md_cooperative_request *request) {
    if (atomic_load_explicit(&channel->state,memory_order_acquire)!=MD_COOPERATIVE_IDLE) return -EBUSY;
    int error=capture(&channel->request,request);
    if (error) return error;
    unsigned idle=MD_COOPERATIVE_IDLE;
    if (!atomic_compare_exchange_strong_explicit(&channel->state,&idle,MD_COOPERATIVE_REQUEST,
            memory_order_seq_cst,memory_order_relaxed)) return -ESHUTDOWN;
    return wake(channel,1);
}
int md_cooperative_retire(struct md_cooperative_channel *channel) {
    unsigned state=MD_COOPERATIVE_RUNNING;
    return atomic_compare_exchange_strong_explicit(&channel->state,&state,MD_COOPERATIVE_IDLE,
        memory_order_release,memory_order_relaxed) ? 0 : -ECANCELED;
}
void md_cooperative_notify_owner(struct md_cooperative_channel *channel) {
    atomic_fetch_add_explicit(&channel->event[1],1,memory_order_seq_cst);
    if (atomic_load_explicit(&channel->sleeping[1],memory_order_seq_cst))
        (void)syscall(SYS_futex,&channel->event[1],FUTEX_WAKE,1,NULL,NULL,0);
}
int md_cooperative_reply(struct md_cooperative_channel *channel,const struct md_cooperative_response *response,int delivery,int *published) {
    *published=0;
    if (response->fd>=0 && !channel->shared_files) {
        long sent=md_fs_send_fds(delivery,&response->sequence,sizeof(response->sequence),&response->fd,1);
        if (sent!=sizeof(response->sequence)) {
            md_cooperative_close(channel); return sent<0 ? (int)sent : -EPROTO;
        }
    }
    channel->response=*response;
    if (!channel->shared_files) channel->response.fd=response->fd>=0 ? 0 : -1;
    unsigned state=MD_COOPERATIVE_RUNNING;
    if (!atomic_compare_exchange_strong_explicit(&channel->state,&state,MD_COOPERATIVE_RESPONSE,
            memory_order_seq_cst,memory_order_relaxed)) {
        if (state!=MD_COOPERATIVE_DELEGATED || !atomic_compare_exchange_strong_explicit(
                &channel->state,&state,MD_COOPERATIVE_RESPONSE,memory_order_seq_cst,memory_order_relaxed))
            return -ECANCELED;
    }
    *published=1;
    return wake(channel,0);
}
void md_cooperative_close(struct md_cooperative_channel *channel) {
    atomic_store_explicit(&channel->state,MD_COOPERATIVE_CLOSED,memory_order_seq_cst);
    (void)wake(channel,0); (void)wake(channel,1);
}

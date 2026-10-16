#define _GNU_SOURCE
#include "fd_exchange.h"
#include "event_wait.h"
#include "fs_service.h"
#include "fs_engine.h"
#include "image_catalogue.h"
#include "inode_watch.h"
#include "ipc_credentials.h"
#include "shm_bridge.h"
#include "ofd_order.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include "event_signal.h"
#include <unistd.h>

#ifdef MD_FS_TESTING
static void (*observer)(enum md_fs_checkpoint, const struct md_fs_packet *, void *);
static void *observation;
void md_fs_observe(void (*fn)(enum md_fs_checkpoint, const struct md_fs_packet *, void *), void *context) {
    observer = fn; observation = context;
}
#define OBSERVE(stage, packet) do { if (observer) observer(stage, packet, observation); } while (0)
#else
#define OBSERVE(stage, packet) ((void)0)
#endif

int md_fs_listen(const char *name) {
    struct sockaddr_un address;
    long length = md_fs_address(name, &address); if (length < 0) return (int)length;
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return -errno;
    if (bind(fd, (struct sockaddr *)&address, (socklen_t)length) || listen(fd, 32)) {
        int r = -errno; close(fd); return r;
    }
    return fd;
}
static int valid(const struct md_fs_packet *q, size_t size, const struct md_fs_rights *rights) {
    if (size < offsetof(struct md_fs_packet, data) || q->magic != MD_FS_MAGIC
            || q->version != MD_FS_VERSION || q->descriptors > 3 || (q->cwd & ~q->descriptors)
            || (q->cwd && !q->exchange) || q->value_size>MD_FS_VALUE_MAX || q->actor <= 0
            || !q->length[0] || !q->length[1] || q->length[0] > PATH_MAX || q->length[1] > PATH_MAX
            || size != offsetof(struct md_fs_packet, data) + q->length[0] + q->length[1] + q->value_size
            || rights->count != ((q->descriptors & ~q->cwd) & 1)
                + (((q->descriptors & ~q->cwd) >> 1) & 1)) return -EPROTO;
    const char *a = q->data, *b = a + q->length[0];
    if (a[q->length[0]-1] || b[q->length[1]-1]
            || memchr(a, 0, q->length[0]-1) || memchr(b, 0, q->length[1]-1)) return -EPROTO;
    struct md_fs_request request={.operation=q->operation,.flags=q->flags,.mode=q->mode,
        .directory={q->descriptors&1 ? 0 : -1,q->descriptors&2 ? 0 : -1},
        .object={q->object[0][0] ? q->object[0] : NULL,q->object[1][0] ? q->object[1] : NULL},
        .path={a,b},.capacity=q->capacity,.offset=q->offset,.resolve=q->resolve,.attributes=q->attributes,
        .value=b+q->length[1],.value_size=q->value_size};
    if (q->cwd & md_fs_operation_data_inputs(q->operation)) return -EINVAL;
    return md_fs_request_validate(&request);
}
static int dispatch(struct md_fs_context *context, const struct md_fs_packet *q,
        const struct md_fs_rights *input, struct md_fs_reply *out, struct md_fs_rights *output,
        struct md_fd_exchange *exchange, struct md_fs_anchor **origin) {
    struct md_fs_request request = {.actor = q->actor, .peer = context->peer, .operation = q->operation, .flags = q->flags, .mode = q->mode,
        .capacity = q->capacity, .offset = q->offset, .resolve = q->resolve, .attributes = q->attributes,
        .directory = {MD_INODE_ROOT, MD_INODE_ROOT}, .path = {q->data, q->data + q->length[0]},
        .object={q->object[0][0] ? q->object[0] : NULL,q->object[1][0] ? q->object[1] : NULL},
        .value=q->data+q->length[0]+q->length[1],.value_size=q->value_size};
    unsigned index = 0;
    for (unsigned i=0;i<2;++i) {
        request.origin[i]=md_fd_exchange_input(exchange,i);
        if (q->cwd & (1U<<i)) request.directory[i]=md_fs_anchor_fd(request.origin[i]);
        else if (q->descriptors & (1U<<i)) request.directory[i]=input->fd[index++];
    }
    struct md_fs_result result;
    struct md_fs_output buffer = {.data = out->data,
        .capacity = md_fs_operation_value(q->operation) ? sizeof(out->data)
            : q->operation==MD_FS_OPEN_IMAGE ? sizeof(struct md_image_identity) : PATH_MAX,
        .reserve_watch=q->operation==MD_FS_WATCH_READ,
        .origin=exchange && md_fs_operation_has_origin(q->operation) ? origin : NULL};
    md_fs_context_execute(context, &request, &result, &buffer);
    out->info = result.info; out->size = result.size; out->position = result.position;
    out->host_path=result.host_path;
    out->proc_namespace=result.proc_namespace;
    out->open_completion=result.open_completion.kind;
    if (result.fd >= 0) output->fd[output->count++] = result.fd;
    if (result.open_completion.kind == MD_OPEN_PIPE) output->fd[output->count++] = result.open_completion.control;
    return result.error;
}
enum peer_phase { REQUEST, DIRECTORY, REPLY, VALUE, RIGHTS, ACKNOWLEDGE, CONFIRM, RELEASE };
struct peer {
    pid_t process;
    enum peer_phase phase;
    int64_t deadline;
    struct md_fs_reply reply;
    size_t reply_position;
    struct md_fs_rights output;
    struct md_fs_context context;
    struct md_fd_exchange *exchange;
    int watch_reader;
    struct md_fs_request directory;
    struct md_ofd_order cursor;
    int directory_fd, directory_reserved;
    int64_t directory_position;
};
static int directory_finish(struct peer *peer, int copied) {
    int error=0;
    if (peer->directory_reserved && copied
            && lseek(peer->directory_fd,peer->directory_position,SEEK_SET)!=peer->directory_position)
        error=-errno;
    peer->directory_reserved=0;
    if (peer->cursor.owner) {
        int ended=md_ofd_order_cancel(&peer->cursor);
        if (ended==1) ended=md_ofd_order_complete(&peer->cursor);
        if (!error) error=ended;
    }
    if (peer->directory_fd>=0) close(peer->directory_fd);
    peer->directory_fd=-1;
    return error;
}
static int directory_progress(struct peer *peer) {
    if (peer->cursor.owner) {
        if (md_ofd_order_state(&peer->cursor)!=MD_RESOURCE_ORDER_READY) return 0;
        peer->reply.error=md_ofd_order_start(&peer->cursor);
    }
    if (!peer->reply.error) {
        struct md_fs_output output={.data=peer->reply.data,.capacity=PATH_MAX,
            .directory_position=peer->directory.operation==MD_FS_GETDENTS ? &peer->directory_position : NULL};
        struct md_fs_result result;
        md_fs_context_execute(&peer->context,&peer->directory,&result,&output);
        peer->reply.error=result.error; peer->reply.size=result.size; peer->reply.position=result.position;
        peer->reply.host_path=result.host_path; peer->reply.proc_namespace=result.proc_namespace;
        peer->directory_reserved=output.directory_position && !result.error && !result.host_path;
        const struct md_fs_packet observed={.operation=peer->directory.operation};
        OBSERVE(MD_FS_AFTER_DISPATCH,&observed);
        (void)observed;
    }
    if (!peer->directory_reserved) {
        int error=directory_finish(peer,0);
        if (!peer->reply.error) peer->reply.error=error;
    }
    peer->phase=REPLY; return 1;
}
static int service_request(struct md_filesystem *fs, int socket,
        struct peer *peer, struct md_resource_wakeup *wake) {
    struct md_fs_packet packet;
    struct md_fs_rights input = {0};
    long n = md_fs_receive(socket, &packet, sizeof(packet), &input);
    if (n == -EAGAIN || n == -EINTR) return 0;
    if (!n) { md_fs_close_rights(&input); return 1; }
    struct md_fs_reply *reply = &peer->reply;
    memset(reply,0,offsetof(struct md_fs_reply,data));
    reply->magic=MD_FS_MAGIC; reply->version=MD_FS_VERSION;
    if (n > 0) {
        reply->error = valid(&packet, (size_t)n, &input);
        if (!reply->error) reply->error=md_fs_context_begin(fs,packet.actor,peer->process,&peer->context);
        if (!reply->error && packet.exchange) {
            peer->exchange=md_fd_exchange_acquire(fs->exchanges,packet.exchange,packet.actor,peer->context.task.files);
            if (!peer->exchange || md_fd_exchange_cwd(peer->exchange)!=packet.cwd) reply->error=-ESTALE;
        }
        if (!reply->error) {
            OBSERVE(MD_FS_BEFORE_DISPATCH, &packet);
            struct md_fs_anchor *origin=NULL;
            if (packet.operation==MD_FS_GETDENTS || packet.operation==MD_FS_SEEKDIR) {
                peer->directory_fd=input.fd[0]; input.count=0;
                peer->directory=(struct md_fs_request){.actor=packet.actor,.peer=peer->context.peer,
                    .operation=packet.operation,.directory={peer->directory_fd,-1},
                    .origin={md_fd_exchange_input(peer->exchange,0),NULL},
                    .flags=packet.flags,.capacity=packet.capacity,.offset=packet.offset};
                int ready=md_ofd_order_begin(fs->cursors,peer->directory_fd,packet.operation==MD_FS_GETDENTS,
                    &peer->cursor,wake);
                if (ready<0) reply->error=ready;
                else peer->phase=DIRECTORY;
            } else reply->error = dispatch(&peer->context, &packet, &input, reply, &peer->output,peer->exchange,&origin);
            if (!reply->error && packet.operation==MD_FS_WATCH_READ) {
                peer->watch_reader=input.fd[0]; input.count=0;
            }
            if (peer->exchange) {
                int error=md_fd_exchange_offer(peer->exchange,origin,peer->output.count);
                if (error) { md_fs_close_rights(&peer->output); reply->error=error; }
            }
            md_fs_anchor_release(origin);
            if (peer->phase!=DIRECTORY) OBSERVE(MD_FS_AFTER_DISPATCH, &packet);
        }
    } else reply->error = -EPROTO;
    md_fs_close_rights(&input);
    if (reply->error) {
        md_fs_close_rights(&peer->output);
        reply->size=reply->host_path=reply->open_completion=0;
        reply->proc_namespace=0;
        reply->position=0;
    }
    reply->descriptors = peer->output.count;
    reply->receipt=peer->output.count && md_fd_exchange_receipt(peer->exchange)>=0;
    if (reply->error || peer->phase!=DIRECTORY) peer->phase = REPLY;
    return 0;
}
static int service_peer(struct md_filesystem *fs,
        struct pollfd *fd, struct peer *peer, struct md_resource_wakeup *wake) {
    struct md_inode_store *s = fs->store;
    if (md_fd_exchange_closed(peer->exchange)) return 1;
    if (peer->phase == RELEASE) return 1;
    if (peer->phase == ACKNOWLEDGE) {
        int copied;
        struct md_fs_rights rights = {0};
        long size = md_fs_receive(fd->fd, &copied, sizeof(copied), &rights);
        unsigned count = rights.count; md_fs_close_rights(&rights);
        if (size == -EAGAIN || size == -EINTR) return 0;
        /* A missing/invalid acknowledgement leaves delivery unconfirmed. Never
         * put possibly delivered events back into another consumer's stream. */
        int rejected = size == sizeof(copied) && !count && copied < 0 && copied >= -4095;
        if (peer->directory_reserved) peer->reply.error=directory_finish(peer,!rejected);
        else {
            peer->reply.error = md_inode_watch_complete(s, peer->watch_reader, !rejected);
            close(peer->watch_reader); peer->watch_reader = -1;
        }
        if (size != sizeof(copied) || count) return 1;
        peer->phase = CONFIRM;
    }
    if (peer->phase == CONFIRM) {
        struct md_fs_rights none = {0};
        long sent = md_fs_send(fd->fd, &peer->reply.error, sizeof(peer->reply.error), &none);
        if (sent == -EAGAIN || sent == -EINTR) { fd->events = POLLOUT; return 0; }
        if (sent != sizeof(peer->reply.error)) return 1;
        peer->phase = RELEASE; fd->events = POLLIN; return 0;
    }
    if (peer->phase == REQUEST && service_request(fs, fd->fd, peer,wake)) return 1;
    if (peer->phase==DIRECTORY && !directory_progress(peer)) { fd->events=0; return !!(fd->revents&POLLHUP); }
    if (md_fd_exchange_closed(peer->exchange)) return 1;
    if (peer->phase==REPLY) {
        size_t bytes=peer->reply.size<MD_FS_REPLY_CHUNK ? peer->reply.size : MD_FS_REPLY_CHUNK;
        size_t size=offsetof(struct md_fs_reply,data)+bytes;
        struct md_fs_rights receipt={.count=1,.fd={md_fd_exchange_receipt(peer->exchange)}};
        long sent=md_fs_send(fd->fd,&peer->reply,size,peer->reply.receipt ? &receipt : &peer->output);
        if (sent==-EAGAIN || sent==-EINTR) { fd->events=POLLOUT; return 0; }
        if (sent!=(long)size) return 1;
        peer->reply_position=bytes;
        if (bytes<peer->reply.size) { peer->phase=VALUE; fd->events=POLLOUT; return 0; }
        if (peer->reply.receipt) peer->phase=RIGHTS;
    } else if (peer->phase==VALUE) {
        size_t left=peer->reply.size-peer->reply_position;
        size_t size=left<MD_FS_REPLY_CHUNK ? left : MD_FS_REPLY_CHUNK;
        const struct md_fs_rights none={0};
        long sent=md_fs_send(fd->fd,peer->reply.data+peer->reply_position,size,&none);
        if (sent==-EAGAIN || sent==-EINTR) { fd->events=POLLOUT; return 0; }
        if (sent!=(long)size) return 1;
        peer->reply_position+=size;
        if (peer->reply_position<peer->reply.size) { fd->events=POLLOUT; return 0; }
    } else if (peer->phase!=RIGHTS) return 0;
    long sent=1;
    if (peer->phase==RIGHTS) {
        unsigned char byte=1;
        sent=md_fs_send(fd->fd,&byte,sizeof(byte),&peer->output);
    }
    if (sent == -EAGAIN || sent == -EINTR) { fd->events = POLLOUT; return 0; }
    if (sent != 1) return 1;
    md_fs_close_rights(&peer->output);
    /* Client close acknowledges receipt. Do not race a nonblocking SEQPACKET
     * receive with server shutdown; never redispatch a completed mutation. */
    peer->phase = peer->watch_reader >= 0 || peer->directory_reserved ? ACKNOWLEDGE : RELEASE;
    fd->events = POLLIN;
    OBSERVE(MD_FS_REPLY_SENT, NULL);
    return 0;
}
static void close_peer(struct md_inode_store *s, struct pollfd *fd, struct peer *peer) {
    directory_finish(peer,peer->phase==ACKNOWLEDGE);
    if (peer->watch_reader >= 0) {
        md_inode_watch_complete(s, peer->watch_reader, peer->phase == ACKNOWLEDGE);
        close(peer->watch_reader); peer->watch_reader = -1;
    }
    md_fs_close_rights(&peer->output);
    close(fd->fd); fd->fd = -1;
    md_fs_context_end(&peer->context);
    md_fd_exchange_release(peer->exchange); peer->exchange=NULL;
    OBSERVE(MD_FS_CONNECTION_CLOSED, NULL);
}
int md_fs_serve(struct md_filesystem *fs, int listener, int stop_fd,
        unsigned timeout_ms, struct md_fs_statistics *statistics, const struct md_fs_work_source *work) {
    struct md_inode_store *s = fs->store;
    if (!s || listener < 0 || stop_fd < 0 || !timeout_ms || timeout_ms > 60000) return -EINVAL;
    enum { SLOTS = 32, BASE = 9 };
    struct pollfd fds[BASE+SLOTS] = {{.fd = listener, .events = POLLIN}, {.fd = stop_fd, .events = POLLIN},
        {.fd = work ? work->fd : -1, .events = POLLIN}, {.fd = -1, .events = POLLIN},
        {.fd = -1}, {.fd = md_fd_exchanges_pollfd(fs->exchanges), .events = POLLIN}, {.fd=-1,.events=POLLIN},
        {.fd=-1,.events=POLLIN}, {.fd=-1,.events=POLLIN}};
    /* Fixed capacity, allocated once per service, never per request. */
    struct peer *peers = calloc(SLOTS, sizeof(*peers));
    if (!peers) return -ENOMEM;
    struct md_ofd_orders *owned=NULL;
    struct md_resource_wakeup *cursor_wake=NULL;
    int error=fs->cursors ? 0 : md_ofd_orders_new(&owned);
    if (!error && owned) fs->cursors=owned;
    if (!error && !work) {
        fds[6].fd=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK);
        if (fds[6].fd<0) error=-errno;
    }
    if (!error && work) {
        cursor_wake=md_resource_wakeup_retain(work->wakeup);
        if (!cursor_wake) error=-EINVAL;
    } else if (!error) error=md_resource_wakeup_create(fds[6].fd,&cursor_wake);
    if (error) {
        if (fds[6].fd>=0) close(fds[6].fd);
        if (owned) { fs->cursors=NULL; md_ofd_orders_release(owned); }
        free(peers); return error;
    }
    struct md_fs_statistics *previous=fs->statistics;
    fs->statistics=statistics;
    for (unsigned i = BASE; i < BASE+SLOTS; ++i) fds[i].fd = -1;
    for (;;) {
        if (work && work->paused && work->paused(work->context)) {
            struct pollfd control[]={{stop_fd,POLLIN,0},{work->fd,POLLIN,0}};
            /* EVENT_WAIT: explicit worker-pause release or shutdown; the
             * supervisor's operation deadline owns cancellation. No namespace
             * transaction or queue lock crosses this wait. */
            long ready=md_event_wait(control,2,INT64_MAX);
            if (ready<0) { error=(int)ready; break; }
            if (control[0].revents) break;
            if (control[1].revents) work->ready(work->context,fs);
            continue;
        }
        long now = md_event_now(); if (now < 0) { error = (int)now; break; }
        int64_t nearest = INT64_MAX;
        int expired_watch = 0;
        for (unsigned i = 0; i < SLOTS; ++i) if (fds[BASE+i].fd >= 0) {
            if (md_fd_exchange_closed(peers[i].exchange) || peers[i].deadline <= now) {
                expired_watch |= peers[i].watch_reader >= 0;
                close_peer(s, &fds[BASE+i], &peers[i]);
            }
            else {
                if (peers[i].phase==DIRECTORY && (!peers[i].cursor.owner
                        || md_ofd_order_state(&peers[i].cursor)==MD_RESOURCE_ORDER_READY)) {
                    if (service_peer(fs,&fds[BASE+i],&peers[i],cursor_wake))
                        close_peer(s,&fds[BASE+i],&peers[i]);
                }
                if (fds[BASE+i].fd>=0 && peers[i].deadline < nearest) nearest = peers[i].deadline;
            }
        }
        if (expired_watch && work && work->notification) {
            error = work->notification(work->context, fs, 0);
            if (error) break;
        }
        struct timespec timeout = {0};
        if (nearest != INT64_MAX) {
            int64_t left = nearest-now;
            timeout.tv_sec = left / 1000000000LL; timeout.tv_nsec = left % 1000000000LL;
        }
        /* EVENT_WAIT: request/reply/exchange-close/client-close/stop readiness; the absolute
         * peer deadline drops only that connection, without replaying work. */
        fds[3].fd = work && work->notification_fd ? work->notification_fd(work->context) : -1;
        fds[4] = (struct pollfd){.fd = md_inode_watch_pollfd(s), .events = POLLIN};
        fds[7].fd=md_ipc_credentials_pollfd(fs->ipc);
        fds[8].fd=md_shm_bridge_pollfd(fs->shm_bridge);
        int r = ppoll(fds, BASE+SLOTS, nearest == INT64_MAX ? NULL : &timeout, NULL);
        if (r < 0) { if (errno == EINTR) continue; error = -errno; break; }
        if (fds[1].revents) break;
        if (fds[8].revents) {
            error=md_shm_bridge_dispatch(fs->shm_bridge);
            if (error) break;
        }
        if (fds[7].revents) {
            int retired=md_ipc_credentials_dispatch(fs->ipc);
            if (retired<0) { error=retired; break; }
        }
        if (fds[6].revents) {
            error=md_event_acknowledge(fds[6].fd);
            if (error) break;
        }
        if (fds[5].revents) {
            error=md_fd_exchanges_drain(fs->exchanges);
            if (error) break;
        }
        int serviced_request = 0;
        if (fds[4].revents) {
            error = md_inode_watch_pump(s);
            if (error) break;
        }
        if (work && fds[2].revents) work->ready(work->context, fs);
        if (work && fds[3].revents) {
            error = work->notification(work->context, fs, fds[3].revents);
            if (error) break;
        }
        if (fds[0].revents & (POLLNVAL | POLLERR | POLLHUP)) { error = -EIO; break; }
        for (unsigned i = BASE; i < BASE+SLOTS; ++i) if (fds[i].fd >= 0 && fds[i].revents) {
            serviced_request |= peers[i-BASE].phase == REQUEST || peers[i-BASE].phase == ACKNOWLEDGE;
            if (service_peer(fs, &fds[i], &peers[i-BASE],cursor_wake)) close_peer(s, &fds[i], &peers[i-BASE]);
        }
        if (fds[0].revents & POLLIN) {
            /* Bound each accept batch so a connecting peer cannot starve shutdown or requests. */
            for (unsigned n = 0; n < SLOTS; ++n) {
                int fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
                if (fd < 0) { if (errno == EAGAIN || errno == EINTR) break; error = -errno; break; }
                if (md_fs_peer(fd)) { close(fd); continue; }
                struct ucred identity; socklen_t identity_size = sizeof(identity);
                if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &identity, &identity_size)
                        || identity_size != sizeof(identity)) { close(fd); continue; }
                unsigned slot = 0; while (slot < SLOTS && fds[BASE+slot].fd >= 0) ++slot;
                if (slot == SLOTS) { close(fd); continue; }
                now = md_event_now();
                if (now < 0) { close(fd); error = (int)now; break; }
                fds[BASE+slot] = (struct pollfd){.fd = fd, .events = POLLIN};
                peers[slot].phase = REQUEST;
                peers[slot].process = identity.pid;
                peers[slot].watch_reader = -1;
                peers[slot].directory_fd=-1;
                peers[slot].deadline = now + (int64_t)timeout_ms * 1000000;
            }
            if (error) break;
        }
        /* Event-driven retry on watch readiness or cancellation. Namespace
         * commits signal the native journal watch; unrelated stat/open traffic
         * must not rescan every pending reader. */
        if (work && work->notification && fds[3].fd >= 0
                && (fds[4].revents || fds[2].revents || serviced_request)) {
            error = work->notification(work->context, fs, 0);
            if (error) break;
        }
    }
    for (unsigned i = BASE; i < BASE+SLOTS; ++i)
        if (fds[i].fd >= 0) close_peer(s, &fds[i], &peers[i-BASE]);
    md_shm_bridge_close(fs->shm_bridge); fs->shm_bridge=NULL;
    free(peers);
    md_resource_wakeup_release(cursor_wake);
    if (fds[6].fd>=0) close(fds[6].fd);
    if (owned) { fs->cursors=NULL; md_ofd_orders_release(owned); }
    fs->statistics=previous;
    return error;
}

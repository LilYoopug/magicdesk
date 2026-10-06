#ifndef MD_LAUNCH_PEER_H
#define MD_LAUNCH_PEER_H
#include "launch_registry.h"

/* Lazy private rendezvous for an exact registered launch. The registration
 * outlives listener and admission work. Closing the listener removes its
 * abstract name; unregister only after closing it. No worker/thread/daemon.
 * Registry IO (listen/connect/verify) belongs on the filesystem worker. */
int md_launch_peer_listen(const struct md_launch_registration *);
/* Returns an owned NONBLOCK|CLOEXEC seqpacket channel after checking the server
 * and sending our launch ID. A full backlog/queue is an explicit error, not a
 * wait or retry. Failure closes only this attempt's private socket. */
int md_launch_peer_connect(const struct md_launch_registration *, const char *peer_id);
/* Use accept4(NONBLOCK|CLOEXEC). Receive consumes exactly one discovery packet,
 * never the following ipc_peer offer. EAGAIN/EINTR leaves this phase pending;
 * other errors terminate it. Success fills id; caller still owns the socket. */
int md_launch_peer_receive(int socket, char id[33]);
/* Worker-side admission after receive, or verification of the expected server.
 * Checks the exact live registration against kernel peer credentials. Does not
 * consume packets or take socket ownership. Success is not application-socket
 * ownership, negotiated features or permission to frame SCM_RIGHTS traffic. */
int md_launch_peer_verify(const struct md_launch_registration *, int socket, const char *id);
#endif

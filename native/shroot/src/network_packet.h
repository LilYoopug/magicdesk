#ifndef MD_NETWORK_PACKET_H
#define MD_NETWORK_PACKET_H
#include <stdint.h>
#include "pid_namespace.h"

/* Internal datagram envelope. Payload remains an ordinary netlink message;
 * source group is independent of payload truncation and concurrent readers. */
struct md_network_packet {
    uint32_t group, port;
    int32_t pid;
    uint32_t uid, gid, pid_count;
    /* Message-time numbers survive sender exit/reaping and PID reuse. */
    struct md_pid_number_value pids[MD_PID_LEVELS];
};
#define MD_NETWORK_PACKET_MAX 65536
#define MD_NETWORK_BUFFER_SIZE 65536
enum { MD_NETWORK_PACKET_INFO=1, MD_NETWORK_PACKET_CREDENTIALS=2 };
long md_network_packet_receive(long,const unsigned long *);
#endif

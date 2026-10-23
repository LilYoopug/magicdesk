#ifndef MD_NETWORK_PACKET_H
#define MD_NETWORK_PACKET_H
#include <stdint.h>
#include <linux/if_packet.h>
#include "pid_namespace.h"

/* Internal datagram envelope. Payload remains an ordinary protocol message;
 * source group is independent of payload truncation and concurrent readers. */
struct md_network_packet {
    uint32_t group, port;
    int32_t pid;
    uint32_t uid, gid, pid_count;
    /* Message-time numbers survive sender exit/reaping and PID reuse. */
    struct md_pid_number_value pids[MD_PID_LEVELS];
    union {
        struct sockaddr_ll ethernet;
        struct {
            unsigned char source[16], destination[16];
            unsigned interface;
            int hops;
            int64_t seconds, microseconds;
        } ipv6;
    };
};
#define MD_NETWORK_PACKET_MAX 65536
#define MD_NETWORK_BUFFER_SIZE 65536
struct md_network_address {
    uint32_t size;
    _Alignas(uint64_t) unsigned char value[128];
};
struct md_network_request {
    struct md_network_address destination;
    _Alignas(uint64_t) unsigned char data[MD_NETWORK_BUFFER_SIZE];
};
enum { MD_NETWORK_PACKET_INFO=1, MD_NETWORK_PACKET_CREDENTIALS=2, MD_NETWORK_PACKET_ETHERNET=4,
    MD_NETWORK_PACKET_IPV6=8, MD_NETWORK_PACKET_IPV6_INFO=16, MD_NETWORK_PACKET_IPV6_HOPS=32,
    MD_NETWORK_PACKET_TIMESTAMP=64 };
long md_network_packet_receive(long,const unsigned long *);
#endif

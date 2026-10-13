#ifndef MD_NETWORK_PACKET_H
#define MD_NETWORK_PACKET_H
#include <stdint.h>

/* Internal datagram envelope. Payload remains an ordinary netlink message;
 * source group is independent of payload truncation and concurrent readers. */
struct md_network_packet { uint32_t group; };
#define MD_NETWORK_PACKET_MAX 65536
#define MD_NETWORK_BUFFER_SIZE 65536
enum { MD_NETWORK_PACKET_INFO=1, MD_NETWORK_PACKET_CREDENTIALS=2 };
long md_network_packet_receive(long,const unsigned long *);
#endif

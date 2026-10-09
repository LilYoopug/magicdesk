#ifndef MD_LAUNCH_PEER_WIRE_H
#define MD_LAUNCH_PEER_WIRE_H
#include <stdint.h>
#define MD_LAUNCH_PEER_MAGIC 0x4d444c50U
#define MD_LAUNCH_PEER_VERSION 1U
struct md_launch_peer_packet { uint32_t magic, version; char id[32]; };
_Static_assert(sizeof(struct md_launch_peer_packet)==40, "launch discovery wire size");
#endif

#ifndef MD_IPC_PEER_WIRE_H
#define MD_IPC_PEER_WIRE_H
#include <stdint.h>

enum { MD_IPC_PEER_MAGIC=0x4d444950, MD_IPC_PEER_VERSION=1,
    MD_IPC_PEER_OFFER=1, MD_IPC_PEER_CONFIRM=2 };
/* Local ARM64 control ABI, fixed-width and pointer-free. Never placed in an
 * application's byte stream. Confirmation echoes this exchange's challenge. */
struct md_ipc_peer_packet {
    uint32_t magic, version, kind, side;
    unsigned char link[16], nonce[16], echo[16];
    uint64_t supported, required;
};
_Static_assert(sizeof(struct md_ipc_peer_packet)==80,"IPC peer packet layout");
#endif

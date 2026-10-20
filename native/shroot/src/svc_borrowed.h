#ifndef MD_LAB_SVC_BORROWED_H
#define MD_LAB_SVC_BORROWED_H

/* Optional LSE experiment. SP distributes contention; it is NOT task identity.
 * Each 64K slot has a metadata page, a guard, and a private 32K stack. */
#define MD_SVC_POOL_HIGH 0x21
#define MD_SVC_POOL_BASE 0x2100000000UL
#define MD_SVC_SLOT_SIZE 65536
#define MD_SVC_SLOT_COUNT 64
#define MD_SVC_POOL_SIZE (MD_SVC_SLOT_COUNT*MD_SVC_SLOT_SIZE)
#define MD_SVC_FRAME_OFFSET 64
#define MD_SVC_OWNER_OFFSET 384
#define MD_SVC_SAVED_SP 864

#endif

#ifndef MD_MOUNT_PIN_H
#define MD_MOUNT_PIN_H
/* An anonymous file in the selected store is only a lifetime/lock identity.
 * The graph retains an unlocked description; exported origins own independent
 * shared range locks. Kernel queues retain these locks through sender death. */
int md_mount_pin_create(int root);
int md_mount_pin_acquire(int source, unsigned slot);
/* Nonblocking exclusive lease, independent of the graph's shared description. */
int md_mount_pin_exclude(int source, unsigned slot);
int md_mount_pin_check(int source, int pin);
#endif

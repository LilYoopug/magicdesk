#ifndef MD_TERMINAL_CALLS_H
#define MD_TERMINAL_CALLS_H
#include <asm/termbits.h>
#include <asm/ioctls.h>
#include <sys/ioctl.h>
static inline int md_terminal_attributes_command(unsigned command) {
    return command==TCGETS2 || command==TCSETS2 || command==TCSETSW2 || command==TCSETSF2;
}
long md_terminal_attributes(const unsigned long *);
#endif

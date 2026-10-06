#ifndef MD_ADAPTER_BUFFER_H
#define MD_ADAPTER_BUFFER_H
#include <stddef.h>

enum { MD_ADAPTER_BUFFER_SLOTS=32 };
enum md_adapter_buffer_control { MD_BUFFER_MAPPED=1, MD_BUFFER_TAKE, MD_BUFFER_RELEASE,
    MD_BUFFER_IPC_PREPARE, MD_BUFFER_SHM_STAT, MD_BUFFER_PROBE };
#ifndef MD_USE_LIBC
int md_adapter_buffer_install(void);
int md_adapter_buffer_ready(void);
long md_adapter_buffer_take(void);
long md_adapter_buffer_release(void);
long md_guest_buffer_control(unsigned, unsigned long, unsigned long);
#endif
#endif

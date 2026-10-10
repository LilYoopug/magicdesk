#pragma once
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>
#include <pthread.h>
#include <sched.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/syscall.h>

/* Bionic lacks these GNU conveniences; no dependency on Termux's libc shim. */
#define index strchr
#define rindex strrchr
#ifndef strdupa
#define strdupa(s) (__extension__ ({ const char *_s = (s); size_t _n = strlen(_s) + 1; \
    char *_d = alloca(_n); (char *)memcpy(_d, _s, _n); }))
#endif
#ifndef IPTOS_DSCP_MASK
#define IPTOS_DSCP_MASK 0xfc
#endif
static inline int md_pthread_setaffinity_np(pthread_t thread, size_t size, const cpu_set_t *set) {
    return sched_setaffinity(pthread_gettid_np(thread), size, set) == 0 ? 0 : errno;
}
#define pthread_setaffinity_np md_pthread_setaffinity_np
/* The on-device compiler's link stubs may predate the API-34 declarations. */
static inline int md_memfd_create(const char *name, unsigned flags) {
    return (int)syscall(SYS_memfd_create, name, flags);
}
static inline ssize_t md_getrandom(void *data, size_t size, unsigned flags) {
    return syscall(SYS_getrandom, data, size, flags);
}
#define memfd_create md_memfd_create
#define getrandom md_getrandom

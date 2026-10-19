/* Opt-in laboratory interposer, NOT a DRM implementation or installable driver.
 * Presents one discovery-only node; Mesa/KGSL owns real buffers and rendering.
 * Never install globally. Unknown DRM operations fail; no fake fences or GEM.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <gbm.h>
#include <limits.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <drm.h>

static const char heap[] = "/dev/dma_heap/system";
static const char node[] = "/dev/dri/renderD128";

static int heap_fd(int fd) {
    int (*fs)(int, struct stat *) = dlsym(RTLD_NEXT, "fstat");
    int (*st)(const char *, struct stat *) = dlsym(RTLD_NEXT, "stat");
    struct stat a, b;
    return !fs(fd, &a) && !st(heap, &b) && S_ISCHR(a.st_mode) &&
        a.st_rdev == b.st_rdev;
}

static const char *mapped(const char *path, char buf[PATH_MAX]) {
    const char *root = getenv("SHROOT_GBM_PROBE_ROOT");
    if (root && (!strcmp(path, "/dev/dri") || !strncmp(path, "/dev/dri/", 9) ||
                 (!strncmp(path, "/sys/dev/char/226:128", 21) &&
                  (path[21] == '/' || !path[21])))) {
        int n = snprintf(buf, PATH_MAX, "%s%s", root, path);
        if (n > 0 && n < PATH_MAX) return buf;
    }
    return path;
}

static int open_probe(const char *symbol, const char *path, int flags, mode_t mode) {
    int (*real)(const char *, int, ...) = dlsym(RTLD_NEXT, symbol);
    if (!strcmp(path, node)) {
        fprintf(stderr, "GBM-PROBE pid=%d open render node\n", getpid());
        return real(heap, (flags & ~O_ACCMODE) | O_RDONLY, mode);
    }
    char buf[PATH_MAX];
    return real(mapped(path, buf), flags, mode);
}

#define PROBE_OPEN(name) \
int name(const char *path, int flags, ...) { \
    mode_t mode = 0; \
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) { \
        va_list args; va_start(args, flags); mode = va_arg(args, mode_t); va_end(args); \
    } \
    return open_probe(#name, path, flags, mode); \
}
PROBE_OPEN(open)
PROBE_OPEN(open64)

#define PROBE_STAT(name, type) \
int name(const char *path, struct type *st) { \
    int (*real)(const char *, struct type *) = dlsym(RTLD_NEXT, #name); \
    char buf[PATH_MAX]; \
    int special = !strcmp(path, node); \
    int r = real(special ? heap : mapped(path, buf), st); \
    if (!r && special) { st->st_rdev = makedev(226, 128); st->st_mode = S_IFCHR | 0666; } \
    return r; \
}
PROBE_STAT(stat, stat)
PROBE_STAT(stat64, stat64)

#define PROBE_FSTAT(name, type) \
int name(int fd, struct type *st) { \
    int (*real)(int, struct type *) = dlsym(RTLD_NEXT, #name); \
    int r = real(fd, st); \
    if (!r && S_ISCHR(st->st_mode) && heap_fd(fd)) st->st_rdev = makedev(226, 128); \
    return r; \
}
PROBE_FSTAT(fstat, stat)
PROBE_FSTAT(fstat64, stat64)

DIR *opendir(const char *path) {
    DIR *(*real)(const char *) = dlsym(RTLD_NEXT, "opendir");
    char buf[PATH_MAX];
    return real(mapped(path, buf));
}

int access(const char *path, int mode) {
    int (*real)(const char *, int) = dlsym(RTLD_NEXT, "access");
    char buf[PATH_MAX];
    return real(mapped(path, buf), mode);
}

#define PROBE_FOPEN(name) \
FILE *name(const char *path, const char *mode) { \
    FILE *(*real)(const char *, const char *) = dlsym(RTLD_NEXT, #name); \
    char buf[PATH_MAX]; \
    return real(mapped(path, buf), mode); \
}
PROBE_FOPEN(fopen)
PROBE_FOPEN(fopen64)

ssize_t readlink(const char *path, char *result, size_t size) {
    ssize_t (*real)(const char *, char *, size_t) = dlsym(RTLD_NEXT, "readlink");
    char buf[PATH_MAX];
    return real(mapped(path, buf), result, size);
}

char *realpath(const char *path, char *result) {
    char *(*real)(const char *, char *) = dlsym(RTLD_NEXT, "realpath");
    char buf[PATH_MAX];
    return real(mapped(path, buf), result);
}

static void version_string(char *out, size_t *capacity, const char *value) {
    size_t n = strlen(value);
    if (out) memcpy(out, value, n < *capacity ? n : *capacity);
    *capacity = n;
}

int ioctl(int fd, unsigned long command, ...) {
    va_list args;
    va_start(args, command);
    void *arg = va_arg(args, void *);
    va_end(args);
    if (_IOC_TYPE(command) == 'd' && heap_fd(fd)) {
        if (command == DRM_IOCTL_VERSION && arg) {
            struct drm_version *v = arg;
            v->version_major = 0; v->version_minor = 0; v->version_patchlevel = 0;
            version_string(v->name, &v->name_len, "shroot-probe");
            version_string(v->desc, &v->desc_len, "laboratory discovery only");
            version_string(v->date, &v->date_len, "");
            return 0;
        }
        fprintf(stderr, "GBM-PROBE unsupported DRM ioctl=%lx\n", command);
        errno = ENOTTY;
        return -1;
    }
    int (*real)(int, unsigned long, ...) = dlsym(RTLD_NEXT, "ioctl");
    return real(fd, command, arg);
}

/* Observe real GBM calls without changing their inputs, outputs or ownership. */
struct gbm_bo *gbm_bo_create_with_modifiers(struct gbm_device *dev,
        uint32_t width, uint32_t height, uint32_t format,
        const uint64_t *modifiers, unsigned count) {
    struct gbm_bo *(*real)(struct gbm_device *, uint32_t, uint32_t, uint32_t,
            const uint64_t *, unsigned) = dlsym(RTLD_NEXT, "gbm_bo_create_with_modifiers");
    struct gbm_bo *bo = real(dev, width, height, format, modifiers, count);
    static _Atomic unsigned observed;
    if (atomic_fetch_add(&observed, 1) < 32)
        fprintf(stderr, "GBM-PROBE allocation %ux%u format=%08x bo=%p\n",
                width, height, format, (void *)bo);
    return bo;
}

int gbm_bo_get_fd_for_plane(struct gbm_bo *bo, int plane) {
    int (*real)(struct gbm_bo *, int) = dlsym(RTLD_NEXT, "gbm_bo_get_fd_for_plane");
    int fd = real(bo, plane);
    static _Atomic unsigned observed;
    if (atomic_fetch_add(&observed, 1) < 32)
        fprintf(stderr, "GBM-PROBE export bo=%p plane=%d fd=%d\n", (void *)bo, plane, fd);
    return fd;
}

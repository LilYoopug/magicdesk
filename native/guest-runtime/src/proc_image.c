#define _GNU_SOURCE
#include "proc_paths.h"
#include "fs.h"
#include "fs_rpc.h"
#include "fs_buffer.h"
#include "namespace.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>

long md_proc_executable_open(const struct md_fs *fs, const char *path, int flags) {
    if (!fs->image || !fs->image->executable_object[0])
        return md_namespace_open(fs, AT_FDCWD, path, flags, 0);
    if (!(flags & O_PATH) && ((flags & O_ACCMODE) != O_RDONLY || (flags & O_TRUNC))) return -ETXTBSY;
    if ((flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) return -EEXIST;
    struct md_fs_request q = {.operation = MD_FS_OPEN_OBJECT, .directory = {-1, -1},
        .path = {fs->image->executable_object, NULL}, .flags = (unsigned)(flags & ~(O_CREAT | O_EXCL | O_NOFOLLOW))};
    struct md_fs_response result;
    long r = md_fs_call(fs->endpoint, 5000, &q, &result);
    if (r < 0) return r;
    if (result.result.error) return result.result.error;
    if (!(flags & O_CLOEXEC)) {
        r = RAW3(fcntl, result.result.fd, F_SETFD, 0);
        if (r < 0) { RAW1(close, result.result.fd); return r; }
    }
    return result.result.fd;
}
void md_proc_image_init(struct md_process_image *image, unsigned argc,
        char *const *argv, const void *auxv, size_t bytes) {
    if (argc > sizeof(image->arg_lengths) / sizeof(image->arg_lengths[0]) || bytes > sizeof(image->auxv))
        md_die("process image bounds", -E2BIG);
    image->argc = argc;
    for (unsigned i = 0; i < argc; ++i) {
        image->argv[i] = (uintptr_t)argv[i];
        image->arg_lengths[i] = md_length(argv[i]) + 1;
    }
    memcpy(image->auxv, auxv, bytes); image->auxv_bytes = bytes;
}
static long append_bytes(int fd, const void *data, size_t size) {
    while (size) {
        long n = RAW3(write, fd, data, size);
        if (n == -EINTR) continue;
        if (n <= 0) return n ? n : -EIO;
        data = (const char *)data + n; size -= (size_t)n;
    }
    return 0;
}
struct image_snapshot {
    const struct md_process_image *image;
    enum md_proc_kind kind;
    unsigned argument;
    size_t offset;
};
static long snapshot_bytes(void *context, void *out, size_t capacity) {
    struct image_snapshot *s=context;
    const struct md_process_image *image=s->image;
    size_t copied=0;
    while (copied<capacity) {
        const void *data;
        size_t size;
        if (s->kind==MD_PROC_AUXV) {
            data=image->auxv; size=image->auxv_bytes;
        } else {
            if (s->argument==image->argc) break;
            data=(void *)image->argv[s->argument]; size=image->arg_lengths[s->argument];
        }
        if (s->offset==size) {
            if (s->kind==MD_PROC_AUXV) break;
            ++s->argument; s->offset=0; continue;
        }
        size_t n=size-s->offset;
        if (n>capacity-copied) n=capacity-copied;
        long error=md_read_memory((char *)out+copied,(const char *)data+s->offset,n);
        if (error<0) return error;
        copied+=n; s->offset+=n;
    }
    return (long)copied;
}
long md_proc_image_open(const struct md_fs *fs, enum md_proc_kind kind, int flags) {
    const struct md_process_image *image = fs->image;
    if (!image || !image->auxv_bytes) return -ENOTSUP;
    if (flags & O_DIRECTORY) return -ENOTDIR;
    if ((flags & O_ACCMODE) != O_RDONLY || (flags & O_TRUNC)) return -EACCES;
    if ((flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) return -EEXIST;
    struct image_snapshot snapshot={.image=image,.kind=kind};
    if (fs->endpoint[0]) {
#ifndef MD_USE_LIBC
        return md_fs_buffer_snapshot((unsigned)(flags&~(O_CREAT|O_EXCL|O_NOFOLLOW)),snapshot_bytes,&snapshot);
#else
        return -ENOTSUP;
#endif
    }
    long fd = RAW4(openat, AT_FDCWD, fs->root, O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) return fd;
    long r = 0;
    char bytes[4096];
    while (!r) {
        long size=snapshot_bytes(&snapshot,bytes,sizeof(bytes));
        if (size<=0) { r=size; break; }
        r=append_bytes((int)fd,bytes,(size_t)size);
    }
    if (!r) {
        char path[64] = "/proc/thread-self/fd/";
        md_decimal(path + md_length(path), (unsigned)fd);
        r = RAW4(openat, AT_FDCWD, path, flags & ~(O_CREAT | O_EXCL | O_NOFOLLOW), 0);
    }
    RAW1(close, fd);
    return r;
}

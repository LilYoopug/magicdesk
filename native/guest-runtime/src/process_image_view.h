#ifndef MD_PROCESS_IMAGE_VIEW_H
#define MD_PROCESS_IMAGE_VIEW_H
#include <stdint.h>
#include <sys/types.h>
/* The supervisor authorizes identity/lifetime before taking a guest snapshot. */
struct md_process_executable;
/* Supervisor-owned anonymous executable; no descriptor remains in the guest. */
struct md_process_executable *md_process_executable_new(int fd);
struct md_process_executable *md_process_executable_retain(struct md_process_executable *);
void md_process_executable_release(struct md_process_executable *);
struct md_control_file md_process_executable_view(struct md_process_executable *);
int md_process_image_view(pid_t, uintptr_t image, unsigned kind, unsigned flags, const char *endpoint, pid_t caller);
ssize_t md_process_image_link(pid_t, uintptr_t image, char *, size_t capacity);
#endif

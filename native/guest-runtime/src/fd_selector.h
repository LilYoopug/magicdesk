#ifndef MD_FD_SELECTOR_H
#define MD_FD_SELECTOR_H

/* Finite selector classes bound irreversible kernel filter growth. A selector
 * is never file identity; the namespace owner checks the retained kernel FD. */
enum { MD_FD_SELECTOR_MASK = 511 };
enum md_fd_selector_kind { MD_FD_SELECTOR_WATCH, MD_FD_SELECTOR_PROC, MD_FD_SELECTOR_KINDS };
/* Installed seccomp selectors belong to a thread group, not its address space
 * or descriptor table. Fork copies them, threads share them, exec retains them. */
struct md_fd_selector;
struct md_fd_selector *md_fd_selector_new(void);
struct md_fd_selector *md_fd_selector_fork(struct md_fd_selector *, int shared);
void md_fd_selector_release(struct md_fd_selector *);
int md_fd_selector_has(struct md_fd_selector *, unsigned kind, unsigned fd);
int md_fd_selector_mark(struct md_fd_selector *, unsigned kind, unsigned fd);
#endif

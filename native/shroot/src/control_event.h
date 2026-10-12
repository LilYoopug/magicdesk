#ifndef MD_CONTROL_EVENT_H
#define MD_CONTROL_EVENT_H
#include <stdint.h>

/* Generation notifications, independently of file contents and read offsets.
 * Each open owns a cursor; dup/fork retain that same cursor through its OFD.
 * Only explicit observation allocates a kernel wakeup descriptor. */
struct md_control_event;
struct md_control_cursor {
    struct md_control_event *source;
    struct md_control_cursor *previous, *next;
    uint64_t generation;
    int wake;
};
struct md_control_event *md_control_event_new(void);
struct md_control_event *md_control_event_retain(struct md_control_event *);
void md_control_event_release(struct md_control_event *);
/* No allocation, task scan or callback into a consumer. */
int md_control_event_publish(struct md_control_event *);
void md_control_cursor_open(struct md_control_cursor *,struct md_control_event *);
void md_control_cursor_close(struct md_control_cursor *);
/* Borrowed nonblocking eventfd. Readiness is a hint, not the application mask.
 * Register it before checking the cursor to avoid check/subscribe races. */
int md_control_cursor_watch(struct md_control_cursor *);
/* One evaluation consumes all changes seen by this open, even when the caller
 * did not request the changed mask. This matches proc sysctl poll semantics. */
int md_control_cursor_poll(struct md_control_cursor *);
#endif

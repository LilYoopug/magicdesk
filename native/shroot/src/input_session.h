#ifndef MD_INPUT_SESSION_H
#define MD_INPUT_SESSION_H
struct md_filesystem;
struct md_input_session;
struct md_device_events;
struct md_input_launch { const char *endpoint; int wake_fd; };
/* Startup mounts are installed by the filesystem owner. The transport thread
 * subsequently changes only its private device tree and synchronized bus. */
int md_input_session_start(struct md_filesystem *,const struct md_input_launch *,
    struct md_device_events *,struct md_input_session **);
void md_input_session_stop(struct md_input_session *);
#endif

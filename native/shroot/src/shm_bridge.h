#ifndef MD_SHM_BRIDGE_H
#define MD_SHM_BRIDGE_H
struct md_shm_bridge;
struct md_task_snapshot;
/* Worker-owned, lazy, event-driven resource channels. No work per pixel/frame. */
int md_shm_bridge_connect(struct md_shm_bridge **,const struct md_task_snapshot *);
int md_shm_bridge_pollfd(const struct md_shm_bridge *);
int md_shm_bridge_dispatch(struct md_shm_bridge *);
void md_shm_bridge_close(struct md_shm_bridge *);
#endif

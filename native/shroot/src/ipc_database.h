#ifndef MD_IPC_DATABASE_H
#define MD_IPC_DATABASE_H
#include <sqlite3.h>
#include <stdint.h>

/* One authority's native storage and lease. Embedded, lazy and confined to
 * its supervisor thread; guest object semantics remain with the caller. */
struct md_ipc_database {
    sqlite3 *handle;
    int directory, gate, lease, locked, admitted;
    int64_t owner;
};
int md_ipc_database_sql(int);
int md_ipc_database_exec(struct md_ipc_database *,const char *);
int md_ipc_database_query(struct md_ipc_database *,const char *,sqlite3_stmt **);
/* Success retains the gate for schema/admission; failure closes partial state.
 * Only a committed owner registration sets admitted, never a created lease. */
int md_ipc_database_open(struct md_ipc_database *,const char *store,const char *kind,const char *name);
void md_ipc_database_close(struct md_ipc_database *);
int md_ipc_database_begin(struct md_ipc_database *);
/* Commit/rollback retains the gate for provider-specific post-commit cleanup. */
int md_ipc_database_commit(struct md_ipc_database *,int error);
void md_ipc_database_unlock(struct md_ipc_database *);
int md_ipc_database_boot(struct md_ipc_database *,const char *reset);
int md_ipc_database_reap(struct md_ipc_database *,const char *select_owners,
    int (*remove)(void *,int64_t),void *context);
#endif

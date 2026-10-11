#define _GNU_SOURCE
#include "sysv_ipc_internal.h"
#include "sysv_shm.h"
#include "private_tree.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

static int fixed_owner;
void test_storage_database(void);
ssize_t __real_getrandom(void *,size_t,unsigned);
ssize_t __wrap_getrandom(void *data,size_t size,unsigned flags) {
    if (!fixed_owner || size!=sizeof(uint64_t)) return __real_getrandom(data,size,flags);
    memset(data,0x39,size); return (ssize_t)size;
}
static int owners(sqlite3 *db) {
    sqlite3_stmt *q=NULL;
    assert(sqlite3_prepare_v2(db,"SELECT count(*) FROM owners",-1,&q,NULL)==SQLITE_OK);
    assert(sqlite3_step(q)==SQLITE_ROW);
    int count=sqlite3_column_int(q,0); sqlite3_finalize(q); return count;
}
static unsigned descriptors(void) {
    DIR *d=opendir("/proc/self/fd"); assert(d);
    unsigned count=0;
    while (readdir(d)) ++count;
    closedir(d); return count;
}
void test_ipc_database(void) {
    test_storage_database();
    char root[]="ipc-database-XXXXXX"; assert(mkdtemp(root));
    struct md_ipc *ipc=NULL,*rejected=NULL;
    fixed_owner=1;
    assert(!md_ipc_open(root,0,NULL,&ipc));
    assert(owners(ipc->database.handle)==1);
    assert(md_ipc_open(root,0,NULL,&rejected)==-EEXIST && !rejected);
    assert(owners(ipc->database.handle)==1);
    fixed_owner=0;
    md_ipc_close(ipc);

    struct md_shm *shm=NULL,*rejected_shm=NULL;
    fixed_owner=1;
    assert(!md_shm_open(root,0,NULL,&shm));
    char path[256]; snprintf(path,sizeof(path),"%s/ipc/v2/shm/segments.db",root);
    sqlite3 *db=NULL; assert(sqlite3_open(path,&db)==SQLITE_OK);
    assert(owners(db)==1);
    assert(md_shm_open(root,0,NULL,&rejected_shm)==-EEXIST && !rejected_shm);
    assert(owners(db)==1);
    fixed_owner=0;
    md_shm_close(shm);
    assert(owners(db)==0); assert(sqlite3_close(db)==SQLITE_OK);
    assert(sqlite3_open(path,&db)==SQLITE_OK);
    assert(sqlite3_exec(db,"UPDATE metadata SET value=NULL WHERE name='boot'",NULL,NULL,NULL)==SQLITE_OK);
    assert(sqlite3_close(db)==SQLITE_OK);
    unsigned count=descriptors();
    for (unsigned i=0;i<8;++i) {
        assert(md_shm_open(root,0,NULL,&shm)==-EIO && !shm);
        assert(descriptors()==count);
    }
    snprintf(path,sizeof(path),"%s/ipc/v2/sysv/ipc.db",root);
    assert(sqlite3_open(path,&db)==SQLITE_OK);
    assert(sqlite3_exec(db,"UPDATE metadata SET value=NULL WHERE name='boot'",NULL,NULL,NULL)==SQLITE_OK);
    assert(sqlite3_close(db)==SQLITE_OK);
    for (unsigned i=0;i<8;++i) {
        assert(md_ipc_open(root,0,NULL,&ipc)==-EIO && !ipc);
        assert(descriptors()==count);
    }
    assert(!md_private_tree_discard(AT_FDCWD,root));
    puts("PASS IPC admission failure preserves live ownership and closes corrupt-database resources");
}

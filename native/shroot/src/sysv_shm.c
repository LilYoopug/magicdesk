#define _GNU_SOURCE
#include "sysv_shm.h"
#include "ipc_storage.h"
#include "ipc_permissions.h"
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct md_shm { sqlite3 *db; int dir, gate, lease; uint64_t owner, namespace_id; unsigned references;
    struct md_user_namespace *user_namespace; };
struct md_shm_mapping {
    struct md_shm_mapping *next;
    struct md_shm_space *space;
    struct md_shm *authority;
    int segment;
    uintptr_t address;
    uintptr_t base;
    size_t size;
};
struct md_shm_space { unsigned references; uint64_t id; struct md_shm_mapping *maps; };
static uint64_t spaces;
static int sql(int rc) { return rc == SQLITE_OK || rc == SQLITE_ROW || rc == SQLITE_DONE ? 0 : -EIO; }
static int exec_sql(struct md_shm *s, const char *text) { return sql(sqlite3_exec(s->db, text, NULL, NULL, NULL)); }
static int query(struct md_shm *s, const char *text, sqlite3_stmt **q) {
    return sql(sqlite3_prepare_v2(s->db, text, -1, q, NULL));
}
static void body(char *out, size_t size, int id) { snprintf(out, size, "segment-%d", id); }
static void owner_name(char *out, size_t size, uint64_t id) { snprintf(out, size, "owner-%016llx", (unsigned long long)id); }
static int refs(struct md_shm *s, uint64_t owner, uint64_t space, int segment, int delta) {
    sqlite3_stmt *q = NULL;
    int r = query(s, "INSERT INTO refs(owner,space,segment,n) VALUES(?1,?2,?3,?4) "
        "ON CONFLICT(owner,space,segment) DO UPDATE SET n=n+excluded.n", &q);
    if (!r) {
        sqlite3_bind_int64(q,1,owner); sqlite3_bind_int64(q,2,space);
        sqlite3_bind_int(q,3,segment); sqlite3_bind_int(q,4,delta); r = sql(sqlite3_step(q));
    }
    sqlite3_finalize(q); return r;
}
static int load(struct md_shm *s, int id, struct shmid64_ds *out) {
    sqlite3_stmt *q = NULL;
    int r = query(s, "SELECT info,(SELECT coalesce(sum(n),0) FROM refs WHERE segment=?1) FROM segments WHERE id=?1 AND namespace=?2", &q);
    if (!r) {
        sqlite3_bind_int(q,1,id); sqlite3_bind_int64(q,2,s->namespace_id); int step = sqlite3_step(q);
        if (step == SQLITE_DONE) r = -EINVAL;
        else if (step != SQLITE_ROW || sqlite3_column_bytes(q,0) != sizeof(*out)) r = -EIO;
        else { memcpy(out,sqlite3_column_blob(q,0),sizeof(*out)); out->shm_nattch = sqlite3_column_int64(q,1); }
    }
    sqlite3_finalize(q); return r;
}
static int save(struct md_shm *s, int id, const struct shmid64_ds *info) {
    sqlite3_stmt *q = NULL;
    int r = query(s,"UPDATE segments SET info=?2,key=?3,removed=?4 WHERE id=?1",&q);
    if (!r) {
        sqlite3_bind_int(q,1,id); sqlite3_bind_blob(q,2,info,sizeof(*info),SQLITE_STATIC);
        sqlite3_bind_int(q,3,info->shm_perm.key); sqlite3_bind_int(q,4,!!(info->shm_perm.mode & 01000));
        r = sql(sqlite3_step(q));
    }
    sqlite3_finalize(q); return r;
}
static int collect(struct md_shm *s) {
    return exec_sql(s,"UPDATE segments SET removed=1,key=0 WHERE namespace!=0 AND namespace NOT IN (SELECT namespace FROM owners);"
        "DELETE FROM refs WHERE n=0;"
        "INSERT OR IGNORE INTO garbage SELECT id FROM segments WHERE removed=1 "
        "AND NOT EXISTS(SELECT 1 FROM refs WHERE segment=id AND n>0);"
        "DELETE FROM segments WHERE id IN (SELECT id FROM garbage)");
}
/* Delete data only after its logical removal commits. Interrupted cleanup is
 * replayable; a failed transaction cannot resurrect a segment without its bytes. */
static int collect_bodies(struct md_shm *s) {
    sqlite3_stmt *q = NULL;
    int r = query(s,"SELECT id FROM garbage",&q);
    if (!r) {
        int step;
        while ((step = sqlite3_step(q)) == SQLITE_ROW) {
            char name[64]; body(name,sizeof(name),sqlite3_column_int(q,0));
            if (unlinkat(s->dir,name,0) && errno != ENOENT) { r = -errno; break; }
        }
        if (!r && step != SQLITE_DONE) r = -EIO;
    }
    sqlite3_finalize(q);
    if (!r) r = exec_sql(s,"DELETE FROM garbage");
    return r;
}
static int dead_owners(struct md_shm *s) {
    sqlite3_stmt *q = NULL;
    int r = query(s,"SELECT owner FROM owners",&q);
    if (!r) {
        int step;
        while ((step = sqlite3_step(q)) == SQLITE_ROW) {
            uint64_t id = sqlite3_column_int64(q,0);
            if (id == s->owner) continue;
            char name[64]; owner_name(name,sizeof(name),id);
            int fd = openat(s->dir,name,O_RDWR|O_CLOEXEC|O_NOFOLLOW);
            int dead = fd < 0 && errno == ENOENT;
            if (fd >= 0) {
                dead = !flock(fd,LOCK_EX|LOCK_NB);
                if (!dead && errno != EWOULDBLOCK) r = -errno;
            } else if (!dead) r = -errno;
            if (!r && dead) {
                char statement[256];
                snprintf(statement,sizeof(statement),"DELETE FROM refs WHERE owner=%lld; DELETE FROM owners WHERE owner=%lld",
                    (long long)id,(long long)id);
                r = exec_sql(s,statement); unlinkat(s->dir,name,0);
            }
            if (fd >= 0) close(fd);
            if (r) break;
        }
        if (!r && step != SQLITE_DONE) r = -EIO;
    }
    sqlite3_finalize(q); return r;
}
static int begin(struct md_shm *s) {
    if (flock(s->gate,LOCK_EX)) return -errno;
    int r = exec_sql(s,"BEGIN IMMEDIATE");
    if (!r) r = dead_owners(s);
    if (r) { exec_sql(s,"ROLLBACK"); flock(s->gate,LOCK_UN); }
    return r;
}
static int finish(struct md_shm *s, int error) {
    if (!error) error = collect(s);
    if (!error) error = exec_sql(s,"COMMIT");
    if (error) exec_sql(s,"ROLLBACK");
    else error = collect_bodies(s);
    flock(s->gate,LOCK_UN); return error;
}
static int boot_namespace(struct md_shm *s) {
    char boot[64]={0};
    int fd=open("/proc/sys/kernel/random/boot_id",O_RDONLY|O_CLOEXEC);
    if (fd<0) return -errno;
    ssize_t n=read(fd,boot,sizeof(boot)-1); close(fd);
    if (n<=0) return -EIO;
    sqlite3_stmt *q=NULL;
    int r=query(s,"SELECT value FROM metadata WHERE name='boot'",&q), changed=1;
    if (!r) {
        int rc=sqlite3_step(q);
        if (rc==SQLITE_ROW) changed=strcmp((const char *)sqlite3_column_text(q,0),boot)!=0;
        else if (rc!=SQLITE_DONE) r=-EIO;
    }
    sqlite3_finalize(q); q=NULL;
    if (!r && changed) {
        r=exec_sql(s,"DELETE FROM refs; DELETE FROM owners; UPDATE segments SET removed=1;");
        if (!r) r=collect(s);
        if (!r) r=query(s,"INSERT OR REPLACE INTO metadata VALUES('boot',?1)",&q);
        if (!r) { sqlite3_bind_text(q,1,boot,-1,SQLITE_STATIC); r=sql(sqlite3_step(q)); }
        sqlite3_finalize(q);
    }
    return r;
}
static int collect_orphans(struct md_shm *s) {
    int fd=openat(s->dir,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if (fd<0) return -errno;
    DIR *dir=fdopendir(fd);
    if (!dir) { int r=-errno; close(fd); return r; }
    sqlite3_stmt *q=NULL;
    int r=query(s,"SELECT 1 FROM segments WHERE id=?1",&q);
    struct dirent *entry;
    while (!r && (entry=readdir(dir))) {
        int id=0; char end=0;
        if (sscanf(entry->d_name,"segment-%d%c",&id,&end)!=1 || id<=0) continue;
        sqlite3_bind_int(q,1,id); int rc=sqlite3_step(q);
        if (rc==SQLITE_DONE) { if (unlinkat(s->dir,entry->d_name,0)) r=-errno; }
        else if (rc!=SQLITE_ROW) r=-EIO;
        sqlite3_reset(q);
    }
    sqlite3_finalize(q); closedir(dir); return r;
}
int md_shm_open(const char *store, uint64_t namespace_id, struct md_user_namespace *owner, struct md_shm **out) {
    *out = NULL;
    struct md_shm *s = calloc(1,sizeof(*s));
    if (!s) return -ENOMEM;
    s->dir = s->gate = s->lease = -1;
    s->references=1; s->namespace_id=namespace_id;
    s->user_namespace=md_user_namespace_retain(owner);
    s->dir=md_ipc_storage_open(store,"shm");
    int r=s->dir<0 ? s->dir : 0;
    if (!r && (s->gate = openat(s->dir,"gate",O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600)) < 0) r = -errno;
    if (!r && getrandom(&s->owner,sizeof(s->owner),0) != sizeof(s->owner)) r = -EIO;
    s->owner &= INT64_MAX;
    char name[64]; owner_name(name,sizeof(name),s->owner);
    if (!r && (s->lease = openat(s->dir,name,O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600)) < 0) r = -errno;
    if (!r && flock(s->lease,LOCK_EX|LOCK_NB)) r = -errno;
    int locked = !r && !flock(s->gate,LOCK_EX);
    if (!r && !locked) r = -errno;
    char descriptor[64], path[PATH_MAX];
    snprintf(descriptor,sizeof(descriptor),"/proc/self/fd/%d",s->dir);
    size_t capacity=sizeof(path)-sizeof("/segments.db");
    ssize_t length=r ? -1 : readlink(descriptor,path,capacity);
    if (!r && length<0) r=-errno;
    if (!r && (size_t)length>=capacity) r=-ENAMETOOLONG;
    if (!r) memcpy(path+length,"/segments.db",sizeof("/segments.db"));
    if (!r) r = sql(sqlite3_open_v2(path,&s->db,SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_NOFOLLOW,NULL));
    if (!r) r = exec_sql(s,"PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;"
        "CREATE TABLE IF NOT EXISTS segments(id INTEGER PRIMARY KEY AUTOINCREMENT,key INTEGER,removed INTEGER,info BLOB,namespace INTEGER NOT NULL);"
        "CREATE UNIQUE INDEX IF NOT EXISTS segment_key ON segments(namespace,key) WHERE key!=0 AND removed=0;"
        "CREATE TABLE IF NOT EXISTS owners(owner INTEGER PRIMARY KEY,namespace INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS metadata(name TEXT PRIMARY KEY,value TEXT);"
        "CREATE TABLE IF NOT EXISTS garbage(id INTEGER PRIMARY KEY);"
        "CREATE TABLE IF NOT EXISTS refs(owner INTEGER,space INTEGER,segment INTEGER,n INTEGER,PRIMARY KEY(owner,space,segment));");
    if (!r) r = exec_sql(s,"BEGIN IMMEDIATE");
    if (!r) r = boot_namespace(s);
    if (!r) r = dead_owners(s);
    if (!r) r = collect(s);
    if (!r) {
        snprintf(path,sizeof(path),"INSERT INTO owners VALUES(%lld,%lld)",(long long)s->owner,(long long)s->namespace_id);
        r = exec_sql(s,path);
    }
    if (!r) r = exec_sql(s,"COMMIT");
    if (r && s->db) exec_sql(s,"ROLLBACK");
    if (!r) r = collect_bodies(s);
    if (!r) r = collect_orphans(s);
    if (locked) flock(s->gate,LOCK_UN);
    if (r) md_shm_close(s); else *out = s;
    return r;
}
void md_shm_close(struct md_shm *s) {
    if (!s || --s->references) return;
    if (s->db && s->gate >= 0 && !begin(s)) {
        char text[256]; snprintf(text,sizeof(text),"DELETE FROM refs WHERE owner=%lld; DELETE FROM owners WHERE owner=%lld",
            (long long)s->owner,(long long)s->owner);
        finish(s,exec_sql(s,text));
    }
    char name[64]; owner_name(name,sizeof(name),s->owner);
    if (s->lease >= 0) { unlinkat(s->dir,name,0); close(s->lease); }
    if (s->db) sqlite3_close(s->db);
    if (s->gate >= 0) close(s->gate);
    if (s->dir >= 0) close(s->dir);
    md_user_namespace_release(s->user_namespace);
    free(s);
}
struct md_shm_space *md_shm_space_new(void) {
    struct md_shm_space *m = calloc(1,sizeof(*m));
    if (m) { m->references = 1; m->id = ++spaces; }
    return m;
}
struct md_shm_space *md_shm_space_fork(struct md_shm_space *old, int shared) {
    if (shared) { ++old->references; return old; }
    struct md_shm_space *m = md_shm_space_new();
    if (!m || !old->maps) return m;
    int r = 0;
    struct md_shm_mapping *pending=NULL;
    for (struct md_shm_mapping *a = old->maps; !r && a; a = a->next) {
        struct md_shm_mapping *b = malloc(sizeof(*b));
        if (!b) { r = -ENOMEM; break; }
        *b=*a; b->space=m; b->next=pending; pending=b;
    }
    /* Publish a namespace's mappings only after its complete reference batch
     * commits. Failure leaves the remaining candidates unowned. */
    while (!r && pending) {
        struct md_shm *s=pending->authority;
        r=begin(s);
        if (r) break;
        for (struct md_shm_mapping *p=pending; !r && p; p=p->next)
            if (p->authority==s) r=refs(s,s->owner,m->id,p->segment,1);
        r=finish(s,r);
        if (r) break;
        struct md_shm_mapping **link=&pending;
        while (*link) {
            struct md_shm_mapping *p=*link;
            if (p->authority!=s) { link=&p->next; continue; }
            *link=p->next; p->next=m->maps; m->maps=p; ++s->references;
        }
    }
    while (pending) { struct md_shm_mapping *next=pending->next; free(pending); pending=next; }
    if (r) {
        md_shm_space_release(m); m = NULL;
    }
    return m;
}
int md_shm_space_release(struct md_shm_space *m) {
    if (!m || --m->references) return 0;
    int r = 0;
    while (m->maps) {
        struct md_shm *s=m->maps->authority;
        ++s->references;
        int error=begin(s);
        if (!error) {
            sqlite3_stmt *q=NULL;
            error=query(s,"DELETE FROM refs WHERE owner=?1 AND space=?2",&q);
            if (!error) {
                sqlite3_bind_int64(q,1,s->owner); sqlite3_bind_int64(q,2,m->id);
                error=sql(sqlite3_step(q));
            }
            sqlite3_finalize(q); error=finish(s,error);
        }
        if (!r) r=error;
        struct md_shm_mapping **link=&m->maps;
        while (*link) {
            struct md_shm_mapping *p=*link;
            if (p->authority!=s) { link=&p->next; continue; }
            *link=p->next; free(p); md_shm_close(s);
        }
        md_shm_close(s);
    }
    free(m); return r;
}
int md_shm_abort(struct md_shm_mapping **pending) {
    struct md_shm_mapping *p = *pending;
    if (!p) return 0;
    struct md_shm *s=p->authority;
    int r = begin(s);
    if (!r) r = finish(s,refs(s,s->owner,p->space->id,p->segment,-1));
    free(p); *pending = NULL; md_shm_close(s); return r;
}
size_t md_shm_pending_size(const struct md_shm_mapping *pending) {
    return pending ? pending->size : 0;
}
int md_shm_intersects(const struct md_shm_space *m, uintptr_t address, size_t size) {
    uintptr_t end = size > UINTPTR_MAX-address ? UINTPTR_MAX : address+size;
    for (const struct md_shm_mapping *p = m->maps; p; p = p->next)
        if (p->address < end && p->address+p->size > address) return 1;
    return 0;
}
int md_shm_unmapped(struct md_shm_space *m, uintptr_t address, size_t size, pid_t pid) {
    if (!md_shm_intersects(m,address,size)) return 0;
    uintptr_t end = size > UINTPTR_MAX-address ? UINTPTR_MAX : address+size;
    int r = 0;
    struct md_shm_mapping **link = &m->maps;
    while (!r && *link) {
        struct md_shm_mapping *p = *link;
        uintptr_t stop = p->address+p->size;
        if (p->address >= end || stop <= address) { link = &p->next; continue; }
        struct md_shm *s=p->authority;
        r=begin(s); if (r) break;
        int released=0;
        struct md_shm_mapping *right=NULL;
        if (p->address < address && stop > end) {
            right = malloc(sizeof(*right));
            if (!right) { r = finish(s,-ENOMEM); break; }
            *right = *p; right->address = end; right->size = stop-end;
            r = refs(s,s->owner,m->id,p->segment,1);
        } else if (p->address>=address && stop<=end) {
            struct shmid64_ds st;
            r = refs(s,s->owner,m->id,p->segment,-1);
            if (!r) r = load(s,p->segment,&st);
            if (!r) { st.shm_dtime = time(NULL); st.shm_lpid = pid; r = save(s,p->segment,&st); }
            released=1;
        }
        r=finish(s,r);
        if (r) { free(right); break; }
        if (right) { p->size=address-p->address; p->next=right; ++s->references; link=&right->next; }
        else if (released) { *link=p->next; free(p); md_shm_close(s); }
        else if (p->address<address) { p->size=address-p->address; link=&p->next; }
        else { p->address=end; p->size=stop-end; link=&p->next; }
    }
    return r;
}
static int permission(const struct md_shm *s, const struct md_identity *id, const struct shmid64_ds *st, unsigned mode) {
    return md_ipc_perm_access(s->user_namespace,id,&st->shm_perm,mode);
}
long md_shm_call(struct md_shm *s, struct md_shm_space *m, struct md_shm_mapping **pending,
        const struct md_identity *id, pid_t pid, unsigned op, const unsigned long a[4], struct shmid64_ds *info) {
    if (op == MD_SHM_ABORT) return md_shm_abort(pending);
    if (op == MD_SHM_ATTACHED) {
        struct md_shm_mapping *p = *pending;
        if (!p || p->space != m || !a[0]) return -EINVAL;
        p->address = p->base = a[0]; p->next = m->maps; m->maps = p; *pending = NULL; return 0;
    }
    if (op == MD_SHM_DETACH_ADDRESS) {
        for (struct md_shm_mapping *p = m->maps; p; p = p->next) if (p->base == a[0]) return p->address;
        return -EINVAL;
    }
    if (op == MD_SHM_DETACH_SIZE || op == MD_SHM_DETACHED) {
        for (struct md_shm_mapping *p = m->maps; p; p = p->next) if (p->address == a[0])
            return op == MD_SHM_DETACH_SIZE ? (long)p->size : md_shm_unmapped(m,p->address,p->size,pid);
        return -EINVAL;
    }
    int r = begin(s), fd = -1;
    long result = 0;
    if (r) return r;
    int segment = (int)a[0];
    struct shmid64_ds st = {0};
    if (op == MD_SHM_GET) {
        int key = (int)a[0], flags = (int)a[2];
        uint64_t size = a[1];
        if (flags & ~(0777|IPC_CREAT|IPC_EXCL|SHM_NORESERVE)) r = -ENOTSUP;
        sqlite3_stmt *q = NULL;
        if (!r) r = query(s,"SELECT id FROM segments WHERE key=?1 AND key!=0 AND removed=0 AND namespace=?2",&q);
        segment = 0;
        if (!r) { sqlite3_bind_int(q,1,key); sqlite3_bind_int64(q,2,s->namespace_id); int rc = sqlite3_step(q);
            if (rc == SQLITE_ROW) segment = sqlite3_column_int(q,0); else if (rc != SQLITE_DONE) r = -EIO; }
        sqlite3_finalize(q); q = NULL;
        if (!r && segment) {
            r = load(s,segment,&st);
            if (!r && (flags & (IPC_CREAT|IPC_EXCL)) == (IPC_CREAT|IPC_EXCL)) r = -EEXIST;
            if (!r && size > st.shm_segsz) r = -EINVAL;
            if (!r) r = permission(s,id,&st,((flags>>6)|(flags>>3)|flags)&7);
        } else if (!r) {
            if (key && !(flags & IPC_CREAT)) r = -ENOENT;
            else if (!size || size > LONG_MAX - (unsigned long)getpagesize()) r = -EINVAL;
            if (!r) r = query(s,"INSERT INTO segments(key,removed,info,namespace) VALUES(?1,0,?2,?3)",&q);
            st.shm_perm.key = key; st.shm_perm.uid = st.shm_perm.cuid = id->uid.effective;
            st.shm_perm.gid = st.shm_perm.cgid = id->gid.effective; st.shm_perm.mode = flags&0777;
            st.shm_segsz = size; st.shm_ctime = time(NULL); st.shm_cpid = pid;
            if (!r) { sqlite3_bind_int(q,1,key); sqlite3_bind_blob(q,2,&st,sizeof(st),SQLITE_STATIC);
                sqlite3_bind_int64(q,3,s->namespace_id); r = sql(sqlite3_step(q)); }
            sqlite3_finalize(q);
            if (!r) {
                sqlite3_int64 next = sqlite3_last_insert_rowid(s->db);
                if (next <= 0 || next > INT_MAX) r = -ENOSPC; else segment = (int)next;
            }
            if (!r) {
                char name[64]; body(name,sizeof(name),segment);
                fd = openat(s->dir,name,O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600);
                if (fd < 0) r = -errno;
                else if (ftruncate(fd,(off_t)((size+getpagesize()-1)&~(uint64_t)(getpagesize()-1)))) r = -errno;
                if (fd >= 0) close(fd);
                fd = -1;
                if (r) unlinkat(s->dir,name,0);
            }
        }
        result = segment;
    } else {
        r = load(s,segment,&st);
        if (!r && op == MD_SHM_OPEN) {
            if (*pending) r = -EBUSY;
            if (!r) r = permission(s,id,&st,(a[1]&SHM_RDONLY)?4:6);
            if (!r && (a[1]&SHM_EXEC)) r = permission(s,id,&st,1);
            if (!r) {
                char name[64]; body(name,sizeof(name),segment);
                fd = openat(s->dir,name,((a[1]&SHM_RDONLY)?O_RDONLY:O_RDWR)|O_CLOEXEC|O_NOFOLLOW);
                if (fd < 0) r = -errno;
            }
            struct md_shm_mapping *p = !r ? calloc(1,sizeof(*p)) : NULL;
            if (!r && !p) r = -ENOMEM;
            if (!r) r = refs(s,s->owner,m->id,segment,1);
            if (!r) { st.shm_atime = time(NULL); st.shm_lpid = pid; r = save(s,segment,&st); }
            if (!r) { *p = (struct md_shm_mapping){.space=m,.segment=segment,.authority=s,
                .size=(st.shm_segsz+getpagesize()-1)&~(size_t)(getpagesize()-1)}; *pending = p; result = fd; }
            else free(p);
        } else if (!r && op == MD_SHM_STAT) {
            r = permission(s,id,&st,4);
            if (!r) { *info=st; md_ipc_perm_visible(id,&info->shm_perm); }
        } else if (!r && (op == MD_SHM_SET || op == MD_SHM_REMOVE)) {
            r=md_ipc_perm_owner(s->user_namespace,id,&st.shm_perm);
            if (!r) {
                if (op == MD_SHM_SET) {
                    r=md_ipc_perm_set(id,&st.shm_perm,(uint32_t)a[1],a[1]>>32,a[2]);
                    st.shm_ctime = time(NULL);
                } else { st.shm_perm.mode |= 01000; st.shm_perm.key = IPC_PRIVATE; }
                if (!r) r = save(s,segment,&st);
            }
        } else if (!r) r = -ENOTSUP;
    }
    r = finish(s,r);
    if (op == MD_SHM_OPEN && *pending) {
        if (r) { free(*pending); *pending=NULL; }
        else ++s->references;
    }
    if (r && fd >= 0) close(fd);
    return r ? r : result;
}

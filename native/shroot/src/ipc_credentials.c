#define _GNU_SOURCE
#include "ipc_credentials.h"
#include "fd_messages.h"
#include "ipc_scope.h"
#include "storage_database.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

struct md_ipc_credentials {
    sqlite3 *db;
    struct md_ipc_scope *scope;
    int gate, directory;
    enum md_ipc_ancillary_transport offer;
};
struct snapshot { struct md_ipc_identity ids; uint32_t process_count; uint32_t groups[]; };
static int sql(int rc) { return md_database_result(rc); }
static int statement(struct md_ipc_credentials *s, const char *text, sqlite3_stmt **q) {
    return sql(sqlite3_prepare_v2(s->db, text, -1, q, NULL));
}
static int execute(struct md_ipc_credentials *s, const char *text) {
    return sql(sqlite3_exec(s->db, text, NULL, NULL, NULL));
}
void md_ipc_credentials_close(struct md_ipc_credentials *s) {
    if (!s) return;
    if (s->scope) {
        struct md_fd_messages *messages=s->scope->local_messages;
        s->scope->local_messages=NULL;
        md_fd_messages_free(messages);
    }
    if (s->db) sqlite3_close(s->db);
    if (s->directory>=0) close(s->directory);
    if (s->gate >= 0) close(s->gate);
    md_ipc_scope_release(s->scope);
    free(s);
}
int md_ipc_credentials_pollfd(const struct md_ipc_credentials *s) {
    return s && s->scope ? md_fd_messages_fd(s->scope->local_messages) : -1;
}
int md_ipc_credentials_dispatch(struct md_ipc_credentials *s) {
    return s && s->scope ? md_fd_messages_dispatch(s->scope->local_messages) : 0;
}
int md_ipc_credentials_open(const char *store, enum md_ipc_ancillary_transport offer,
        struct md_ipc_credentials **out) {
    if (!store || !out || (offer!=MD_IPC_TRANSPORT_NATIVE && offer!=MD_IPC_TRANSPORT_ORIGINS_V1))
        return -EINVAL;
    struct md_ipc_credentials *s = calloc(1, sizeof(*s));
    if (!s) return -ENOMEM;
    s->gate = s->directory = -1;
    s->offer = offer;
    s->scope=calloc(1,sizeof(*s->scope));
    if (!s->scope) { free(s); return -ENOMEM; }
    atomic_init(&s->scope->refs,1); s->scope->lease=s->scope->root=-1;
    int root = open(store, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW), dir = -1;
    int r = root < 0 ? -errno : 0;
    s->scope->root=root;
    if (!r && flock(root,LOCK_SH|LOCK_NB)) r=errno==EWOULDBLOCK ? -EBUSY : -errno;
    struct stat opened, named;
    if (!r && (fstat(root,&opened) || lstat(store,&named) || !opened.st_nlink
            || opened.st_dev!=named.st_dev || opened.st_ino!=named.st_ino)) r=-ESTALE;
    if (!r) { s->scope->device=opened.st_dev; s->scope->inode=opened.st_ino; }
    if (!r && mkdirat(root, "ipc", 0700) && errno != EEXIST) r = -errno;
    if (!r && (dir = openat(root, "ipc", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)) < 0) r = -errno;
    if (!r && (s->gate = openat(dir, "gate", O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600)) < 0) r = -errno;
    /* EVENT_WAIT: current metadata transaction releases its gate; syscall
     * interruption fails admission before any snapshot is published. */
    if (!r && flock(s->gate, LOCK_EX)) r = -errno;
    if (!r && (s->scope->lease = openat(dir, "live", O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600)) < 0) r = -errno;
    int first = !r && !flock(s->scope->lease, LOCK_EX | LOCK_NB);
    if (!r && !first && errno != EWOULDBLOCK) r = -errno;
    s->directory=dir;
    if (!r) r=md_database_open(dir,"credentials.db",1,&s->db);
    if (!r && first) r = execute(s, "DROP TABLE IF EXISTS endpoints;DROP TABLE IF EXISTS connections;DROP TABLE IF EXISTS messages;DROP TABLE IF EXISTS native_sockets;");
    if (!r && first && unlinkat(dir,"auth",0) && errno!=ENOENT) r=-errno;
    if (!r && first && unlinkat(dir,"auth.pending",0) && errno!=ENOENT) r=-errno;
    if (!r) r = execute(s, "PRAGMA journal_mode=WAL;PRAGMA synchronous=NORMAL;"
        "CREATE TABLE IF NOT EXISTS endpoints(name BLOB PRIMARY KEY,cookie INTEGER,revision INTEGER,identity BLOB,ready INTEGER,transport INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS connections(cookie INTEGER PRIMARY KEY,name BLOB,identity BLOB,peer BLOB,endpoint BLOB,revision INTEGER,hidden INTEGER,valid INTEGER,link BLOB,side INTEGER,transport INTEGER NOT NULL);"
        "CREATE INDEX IF NOT EXISTS connection_name ON connections(name);"
        "CREATE INDEX IF NOT EXISTS connection_link ON connections(link,side);"
        "CREATE INDEX IF NOT EXISTS endpoint_cookie ON endpoints(cookie);"
        "CREATE TABLE IF NOT EXISTS native_sockets(cookie INTEGER PRIMARY KEY);"
        "CREATE TABLE IF NOT EXISTS messages(nonce BLOB PRIMARY KEY,link BLOB,device INTEGER,inode INTEGER,pid INTEGER,uid INTEGER,gid INTEGER,side INTEGER,process BLOB);");
    /* The first live owner discards stale metadata, including cookies from an
     * earlier boot. This directory is not part of OCI/image inode metadata. */
    if (!r && flock(s->scope->lease, LOCK_SH)) r = -errno;
    if (s->gate >= 0) flock(s->gate, LOCK_UN);
    if (r) md_ipc_credentials_close(s); else *out = s;
    return r;
}
static int socket_key(int fd, uint64_t *cookie) {
    int domain = 0, type = 0;
    socklen_t n = sizeof(domain);
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &n)) return -errno;
    if (domain != AF_UNIX) return -EAFNOSUPPORT;
    n = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &n)) return -errno;
    if (type != SOCK_STREAM && type != SOCK_SEQPACKET && type != SOCK_DGRAM) return -EPROTOTYPE;
    n = sizeof(*cookie);
    return getsockopt(fd, SOL_SOCKET, SO_COOKIE, cookie, &n) ? -errno : 0;
}
static int optional_socket_key(int fd, uint64_t *cookie) {
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    if (!S_ISSOCK(st.st_mode)) return 0;
    int flags=fcntl(fd,F_GETFL);
    if (flags<0) return -errno;
    if (flags&O_PATH) return 0;
    int r=socket_key(fd,cookie);
    return r==-EAFNOSUPPORT || r==-EPROTOTYPE ? 0 : r ? r : 1;
}
static int native_socket(struct md_ipc_credentials *s, uint64_t cookie) {
    sqlite3_stmt *q=NULL;
    int r=statement(s,"SELECT 1 FROM native_sockets WHERE cookie=?1",&q);
    if (!r) {
        sqlite3_bind_int64(q,1,(sqlite3_int64)cookie);
        int step=sqlite3_step(q);
        r=step==SQLITE_ROW ? 1 : step==SQLITE_DONE ? 0 : -EIO;
    }
    sqlite3_finalize(q); return r;
}
static int expose(struct md_ipc_credentials *s, const uint64_t *keys, unsigned count, int inherited) {
    if (!count) return 0;
    /* EVENT_WAIT: connection/exposure transaction releases the metadata gate;
     * interruption fails admission without performing application IO. */
    if (flock(s->gate,LOCK_EX)) return -errno;
    int r=execute(s,"BEGIN IMMEDIATE");
    sqlite3_stmt *known=NULL,*mark=NULL;
    if (!r) r=statement(s,"SELECT 1 FROM connections WHERE cookie=?1 AND valid>=0 "
        "UNION ALL SELECT 1 FROM endpoints WHERE cookie=?1 LIMIT 1",&known);
    if (!r) r=statement(s,"INSERT OR IGNORE INTO native_sockets VALUES(?1)",&mark);
    for (unsigned i=0;!r && i<count;++i) {
        sqlite3_bind_int64(known,1,(sqlite3_int64)keys[i]);
        int step=sqlite3_step(known);
        if (step==SQLITE_ROW) { if (!inherited) r=-EXDEV; }
        else if (step!=SQLITE_DONE) r=-EIO;
        else {
            sqlite3_bind_int64(mark,1,(sqlite3_int64)keys[i]);
            r=sql(sqlite3_step(mark)); sqlite3_reset(mark);
        }
        sqlite3_reset(known);
    }
    sqlite3_finalize(known); sqlite3_finalize(mark);
    if (!r) r=execute(s,"COMMIT");
    if (r) execute(s,"ROLLBACK");
    flock(s->gate,LOCK_UN); return r;
}
int md_ipc_credentials_native(struct md_ipc_credentials *s, const int *fds, unsigned count) {
    if (!s || (count && !fds) || count>253) return -EINVAL;
    uint64_t keys[253]; unsigned n=0;
    for (unsigned i=0;i<count;++i) {
        int r=optional_socket_key(fds[i],&keys[n]);
        if (r<0) return r;
        n+=(unsigned)r;
    }
    return expose(s,keys,n,0);
}
int md_ipc_inherited_capture(struct md_ipc_inherited *out) {
    if (!out || out->cookies || out->count) return -EINVAL;
    DIR *dir=opendir("/proc/self/fd");
    if (!dir) return -errno;
    struct md_ipc_inherited found={0}; int r=0;
    for (;;) {
        errno=0; struct dirent *entry=readdir(dir);
        if (!entry) { if (errno) r=-errno; break; }
        char *end; long fd=strtol(entry->d_name,&end,10);
        if (*end || fd<0 || fd>INT_MAX || fd==dirfd(dir)) continue;
        int flags=fcntl((int)fd,F_GETFD);
        if (flags<0) { r=-errno; break; }
        if (flags&FD_CLOEXEC) continue;
        uint64_t cookie;
        r=optional_socket_key((int)fd,&cookie);
        if (r<0) break;
        if (!r) continue;
        uint64_t *more=realloc(found.cookies,(found.count+1)*sizeof(*more));
        if (!more) { r=-ENOMEM; break; }
        found.cookies=more; found.cookies[found.count++]=cookie; r=0;
    }
    closedir(dir);
    if (r) free(found.cookies); else *out=found;
    return r;
}
int md_ipc_credentials_inherit(struct md_ipc_credentials *s, const struct md_ipc_inherited *inherited) {
    if (!s || !inherited) return -EINVAL;
    return expose(s,inherited->cookies,inherited->count,1);
}
void md_ipc_inherited_release(struct md_ipc_inherited *inherited) {
    free(inherited->cookies); *inherited=(struct md_ipc_inherited){0};
}
static int address(int fd, int peer, struct sockaddr_un *out, int *size) {
    socklen_t n = sizeof(*out);
    memset(out, 0, sizeof(*out));
    if ((peer ? getpeername(fd, (void *)out, &n) : getsockname(fd, (void *)out, &n))) return -errno;
    if (out->sun_family != AF_UNIX || n > sizeof(*out) || n < offsetof(struct sockaddr_un, sun_path)) return -EINVAL;
    *size = (int)n - offsetof(struct sockaddr_un, sun_path); return 0;
}
static int decode_name(const char *hex, struct sockaddr_un *a, int *size) {
    *a = (struct sockaddr_un){.sun_family=AF_UNIX};
    size_t n = hex ? strlen(hex) : 0;
    if (!n || n % 2 || n > 2 * sizeof(a->sun_path)) return -EINVAL;
    for (size_t i = 0; i < n / 2; ++i) {
        const char *hi = strchr("0123456789abcdef", hex[2*i]), *lo = strchr("0123456789abcdef", hex[2*i+1]);
        if (!hi || !lo) return -EINVAL;
        a->sun_path[i] = (char)(((hi - "0123456789abcdef") << 4) | (lo - "0123456789abcdef"));
    }
    *size = (int)n/2; return 0;
}
static struct snapshot *snapshot(const struct md_identity *id, const struct md_pid_identity *process, pid_t pid, size_t *bytes) {
    unsigned n = md_identity_group_count(id);
    struct md_pid_number_value numbers[MD_PID_LEVELS];
    unsigned count=md_pid_identity_export(process,numbers);
    *bytes = sizeof(struct snapshot) + n * sizeof(uint32_t) + count*sizeof(*numbers);
    struct snapshot *p = malloc(*bytes);
    if (!p) return NULL;
    p->ids = (struct md_ipc_identity){pid, id->uid.effective, id->gid.effective, n};
    p->process_count=count;
    if (n) memcpy(p->groups, md_identity_group_data(id), n * sizeof(uint32_t));
    if (count) memcpy(p->groups+n,numbers,count*sizeof(*numbers));
    return p;
}
static int blob_view(sqlite3_stmt *q, int column, const void **out, size_t *bytes) {
    int n = sqlite3_column_bytes(q, column);
    const void *p = sqlite3_column_blob(q, column);
    if (!p || n < (int)sizeof(struct snapshot)) return -EPROTO;
    const struct snapshot *value=p;
    if (value->ids.group_count>MD_IDENTITY_GROUPS_MAX || value->process_count>MD_PID_LEVELS
            || (size_t)n!=sizeof(*value)+value->ids.group_count*sizeof(uint32_t)
                +value->process_count*sizeof(struct md_pid_number_value)) return -EPROTO;
    *out=p; *bytes=(size_t)n; return 0;
}
static int blob_copy(sqlite3_stmt *q, int column, void **out, size_t *bytes) {
    const void *p;
    int error=blob_view(q,column,&p,bytes);
    if (error) return error;
    *out = malloc(*bytes);
    if (!*out) return -ENOMEM;
    memcpy(*out, p, *bytes); return 0;
}
/* Caller owns the metadata gate and transaction. In particular both ends of a
 * socketpair must commit together; a failed second insertion rolls back both. */
static int save_connection(struct md_ipc_credentials *s, uint64_t key, const struct sockaddr_un *name, int size,
        const void *self, size_t self_size, const void *peer, size_t peer_size,
        const struct sockaddr_un *endpoint, int endpoint_size, int64_t revision, int hidden, int valid,
        const struct md_ipc_connection *connection, enum md_ipc_ancillary_transport transport) {
    sqlite3_stmt *q = NULL;
    int r = 0;
    if (!r && size) {
        /* close can release a bound name before accept. Keep unresolved
         * candidates: selecting the newest would misidentify queued peers.
         * Accepted endpoints already have their own cookie-bound snapshot. */
        r = statement(s, "UPDATE connections AS old SET name=NULL WHERE name=?1 AND cookie<>?2 "
            "AND (valid<0 OR EXISTS(SELECT 1 FROM connections AS accepted "
            "WHERE accepted.link=old.link AND accepted.side=1))", &q);
        if (!r) {
            sqlite3_bind_blob(q, 1, name->sun_path, size, SQLITE_STATIC);
            sqlite3_bind_int64(q, 2, (sqlite3_int64)key);
            r = sql(sqlite3_step(q));
        }
        sqlite3_finalize(q); q = NULL;
    }
    if (!r) r = statement(s, "INSERT INTO connections VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) "
        "ON CONFLICT(cookie) DO UPDATE SET name=excluded.name,identity=excluded.identity,peer=excluded.peer,"
        "endpoint=excluded.endpoint,revision=excluded.revision,hidden=excluded.hidden,valid=excluded.valid,"
        "link=excluded.link,side=excluded.side,transport=excluded.transport WHERE connections.valid<>1", &q);
    if (!r) {
        sqlite3_bind_int64(q, 1, (sqlite3_int64)key);
        sqlite3_bind_blob(q, 2, name ? name->sun_path : NULL, size, SQLITE_STATIC);
        sqlite3_bind_blob(q, 3, self, (int)self_size, SQLITE_STATIC);
        sqlite3_bind_blob(q, 4, peer, (int)peer_size, SQLITE_STATIC);
        sqlite3_bind_blob(q, 5, endpoint ? endpoint->sun_path : NULL, endpoint_size, SQLITE_STATIC);
        sqlite3_bind_int64(q, 6, revision); sqlite3_bind_int(q, 7, hidden); sqlite3_bind_int(q, 8, valid);
        sqlite3_bind_blob(q, 9, connection->link, sizeof(connection->link), SQLITE_STATIC);
        sqlite3_bind_int(q, 10, (int)connection->side);
        sqlite3_bind_int(q, 11, transport);
        r = sql(sqlite3_step(q));
        if (!r && !sqlite3_changes(s->db)) r=-EALREADY;
    }
    sqlite3_finalize(q);
    return r;
}
static int listen_update(struct md_ipc_credentials *s, const struct md_fs_request *req,
        uint64_t key, const void *self, size_t bytes) {
    int native=native_socket(s,key);
    if (native<0) return native;
    struct sockaddr_un name; int n;
    int r = address(req->directory[0], 0, &name, &n);
    if (r || !n) return r ? r : -EINVAL;
    sqlite3_stmt *q = NULL;
    if (native) {
        r=statement(s,"DELETE FROM endpoints WHERE name=?1",&q);
        if (!r) {
            sqlite3_bind_blob(q,1,name.sun_path,n,SQLITE_STATIC);
            r=sql(sqlite3_step(q));
        }
        sqlite3_finalize(q); return r;
    }
    if (req->flags == MD_IPC_LISTEN_BEGIN) {
        r = statement(s, "INSERT INTO endpoints VALUES(?1,?2,1,?3,0,?4) ON CONFLICT(name) DO UPDATE SET "
            "cookie=excluded.cookie,revision=revision+1,identity=excluded.identity,ready=0,transport=excluded.transport", &q);
    } else {
        r = statement(s, "UPDATE endpoints SET ready=?3 WHERE name=?1 AND cookie=?2", &q);
    }
    if (!r) {
        sqlite3_bind_blob(q, 1, name.sun_path, n, SQLITE_STATIC); sqlite3_bind_int64(q, 2, (sqlite3_int64)key);
        if (req->flags == MD_IPC_LISTEN_BEGIN) {
            sqlite3_bind_blob(q, 3, self, (int)bytes, SQLITE_STATIC);
            sqlite3_bind_int(q, 4, s->offer);
        }
        else sqlite3_bind_int(q, 3, req->offset == 0);
        r = sql(sqlite3_step(q));
    }
    sqlite3_finalize(q); return r;
}
static int connect_begin(struct md_ipc_credentials *s, const struct md_fs_request *req,
        uint64_t key, const void *self, size_t bytes, struct md_fs_result *result) {
    int native=native_socket(s,key);
    if (native) return native<0 ? native : 0;
    struct sockaddr_un endpoint, local; int size, local_size;
    int type; socklen_t type_size = sizeof(type);
    if (getsockopt(req->directory[0], SOL_SOCKET, SO_TYPE, &type, &type_size)) return -errno;
    if (type == SOCK_DGRAM) return 0;
    if (!address(req->directory[0], 1, &endpoint, &size)) return 0;
    int r = decode_name(req->path[0], &endpoint, &size);
    sqlite3_stmt *q = NULL;
    if (!r) r = statement(s, "SELECT identity,revision,ready,transport FROM endpoints WHERE name=?1", &q);
    void *peer = NULL; size_t peer_size = 0; int64_t revision = 0;
    enum md_ipc_ancillary_transport transport=MD_IPC_TRANSPORT_NATIVE;
    if (!r) {
        sqlite3_bind_blob(q, 1, endpoint.sun_path, size, SQLITE_STATIC);
        int step = sqlite3_step(q);
        if (step == SQLITE_DONE) { sqlite3_finalize(q); return 0; } // External endpoint.
        if (step != SQLITE_ROW) r = -EIO;
        else if (!sqlite3_column_int(q, 2)) r = -EAGAIN;
        else {
            r = blob_copy(q, 0, &peer, &peer_size); revision = sqlite3_column_int64(q, 1);
            int offered=sqlite3_column_int(q,3);
            if (sqlite3_column_type(q,3)!=SQLITE_INTEGER || offered<0 || offered>MD_IPC_TRANSPORT_ORIGINS_V1)
                r=-EPROTONOSUPPORT;
            else if ((unsigned)offered==s->offer) transport=s->offer;
        }
    }
    sqlite3_finalize(q);
    int hidden = 0;
    if (!r) r = address(req->directory[0], 0, &local, &local_size);
    if (!r && local_size) {
        sqlite3_stmt *old = NULL;
        r = statement(s, "SELECT hidden FROM connections WHERE cookie=?1", &old);
        if (!r) {
            sqlite3_bind_int64(old, 1, (sqlite3_int64)key);
            int step = sqlite3_step(old);
            if (step == SQLITE_ROW) hidden = sqlite3_column_int(old, 0);
            else if (step != SQLITE_DONE) r = -EIO;
        }
        sqlite3_finalize(old);
    }
    if (!r && !local_size) {
        /* A private transport name identifies this exact connecting socket to
         * accept(), without payload framing, PID guesses or netlink privilege.
         * The address adapter hides this implementation name from the guest. */
        unsigned char random[16];
        if (getrandom(random, sizeof(random), 0) != sizeof(random)) r = -EIO;
        if (!r) {
            memcpy(local.sun_path + 1, "md-guest-peer-", 14);
            for (unsigned i = 0; i < sizeof(random); i++) snprintf(local.sun_path + 15 + 2*i, 3, "%02x", random[i]);
            local_size = 47;
            if (bind(req->directory[0], (void *)&local, (socklen_t)(offsetof(struct sockaddr_un, sun_path)+local_size))) r = -errno;
            else hidden = 1;
        }
    }
    struct md_ipc_connection connection={0};
    if (!r && getrandom(connection.link, sizeof(connection.link), 0) != sizeof(connection.link)) r = -EIO;
    if (!r) r = save_connection(s, key, &local, local_size, self, bytes, peer, peer_size,
        &endpoint, size, revision, hidden, 2, &connection, transport);
    if (!r) result->position = 1;
    free(peer); return r;
}
static int peer_matches(int fd, const struct md_ipc_identity *expected) {
    struct ucred actual; socklen_t size=sizeof(actual);
    if (getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&actual,&size)) return -errno;
    return size==sizeof(actual) && actual.pid==expected->pid ? 0 : -ESTALE;
}
static int connect_end(struct md_ipc_credentials *s, const struct md_fs_request *req, uint64_t key) {
    sqlite3_stmt *q = NULL;
    if (!req->offset) {
        int r=statement(s,"SELECT peer FROM connections WHERE cookie=?1",&q);
        if (!r) {
            sqlite3_bind_int64(q,1,(sqlite3_int64)key);
            int step=sqlite3_step(q);
            if (step!=SQLITE_ROW) r=step==SQLITE_DONE ? -ENODATA : -EIO;
            else {
                const void *peer; size_t bytes;
                r=blob_view(q,0,&peer,&bytes);
                if (!r) r=peer_matches(req->directory[0],peer);
            }
        }
        sqlite3_finalize(q); q=NULL;
        if (r) return r; // A reused native listen address cannot confirm this connection.
    }
    int r = statement(s, "UPDATE connections SET valid=CASE WHEN ?2=0 AND (EXISTS(SELECT 1 FROM endpoints "
        "WHERE endpoints.name=connections.endpoint AND endpoints.revision=connections.revision AND ready=1) "
        "OR EXISTS(SELECT 1 FROM connections AS accepted WHERE accepted.link=connections.link "
        "AND accepted.side=1 AND accepted.valid=1)) "
        "THEN 1 ELSE CASE WHEN ?2=0 THEN 0 ELSE -1 END END WHERE cookie=?1 AND valid<>1", &q);
    if (!r) {
        sqlite3_bind_int64(q, 1, (sqlite3_int64)key); sqlite3_bind_int64(q, 2, req->offset);
        r = sql(sqlite3_step(q));
    }
    sqlite3_finalize(q); return r;
}
static int accept_peer(struct md_ipc_credentials *s, int fd, uint64_t key) {
    struct sockaddr_un peer, local; int size, local_size;
    int r = address(fd, 1, &peer, &size);
    if (r || !size) return r;
    r=address(fd,0,&local,&local_size);
    struct ucred actual; socklen_t actual_size=sizeof(actual);
    if (!r && getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&actual,&actual_size)) r=-errno;
    if (r) return r;
    sqlite3_stmt *q = NULL;
    r = statement(s, "SELECT identity,link,side,valid,transport,EXISTS(SELECT 1 FROM endpoints "
        "WHERE endpoints.name=connections.endpoint AND endpoints.revision=connections.revision AND ready=1) "
        "FROM connections WHERE name=?1 AND endpoint=?2 AND valid>=0", &q);
    void *id = NULL; size_t bytes = 0;
    struct md_ipc_connection connection={.side=1};
    enum md_ipc_ancillary_transport transport=MD_IPC_TRANSPORT_NATIVE;
    if (!r) {
        sqlite3_bind_blob(q, 1, peer.sun_path, size, SQLITE_STATIC);
        sqlite3_bind_blob(q, 2, local.sun_path, local_size, SQLITE_STATIC);
        int step;
        while (!r && (step=sqlite3_step(q))==SQLITE_ROW) {
            const void *candidate; size_t candidate_bytes;
            r=blob_view(q,0,&candidate,&candidate_bytes);
            if (r) break;
            if (((const struct md_ipc_identity *)candidate)->pid!=actual.pid) continue;
            if (id) { r=-ESTALE; break; }
            if (sqlite3_column_int(q,3)!=1 && sqlite3_column_int(q,3)!=2) { r=-ESTALE; break; }
            if (sqlite3_column_int(q,3)==2 && !sqlite3_column_int(q,5)) { r=-ESTALE; break; }
            if (sqlite3_column_bytes(q, 1) != sizeof(connection.link)
                    || sqlite3_column_type(q, 2)!=SQLITE_INTEGER
                    || sqlite3_column_int(q, 2)!=0
                    || sqlite3_column_type(q,4)!=SQLITE_INTEGER
                    || (unsigned)sqlite3_column_int(q,4)>MD_IPC_TRANSPORT_ORIGINS_V1) { r=-EPROTO; break; }
            r=blob_copy(q,0,&id,&bytes);
            if (!r) {
                memcpy(connection.link,sqlite3_column_blob(q,1),sizeof(connection.link));
                transport=(enum md_ipc_ancillary_transport)sqlite3_column_int(q,4);
            }
        }
        if (!r && step!=SQLITE_DONE) r=-EIO;
    }
    sqlite3_finalize(q);
    if (!r && id) r = save_connection(s, key, NULL, 0, NULL, 0, id, bytes, NULL, 0, 0, 0, 1, &connection, transport);
    free(id); return r;
}
static int peer_snapshot(struct md_ipc_credentials *s, const struct md_identity *viewer, const struct md_pid_identity *process, const struct md_fs_request *req,
        uint64_t key, struct md_fs_result *result, const struct md_fs_output *output) {
    sqlite3_stmt *q = NULL;
    int r = statement(s, "SELECT peer,valid FROM connections WHERE cookie=?1", &q);
    const void *id = NULL; size_t bytes = 0;
    if (!r) {
        sqlite3_bind_int64(q, 1, (sqlite3_int64)key);
        int step = sqlite3_step(q);
        if (step == SQLITE_ROW) {
            if (sqlite3_column_int(q, 1) < 0) r = -ENODATA;
            else if (sqlite3_column_int(q, 1) != 1) r = -ESTALE;
            else r = blob_view(q, 0, &id, &bytes);
        } else r = step == SQLITE_DONE ? -ENODATA : -EIO;
    }
    if (!r) r=peer_matches(req->directory[0],id);
    const struct snapshot *saved=id;
    if (!r) bytes=sizeof(struct md_ipc_identity)+(req->mode ? saved->ids.group_count*sizeof(uint32_t) : 0);
    if (!r && (!output || !output->data)) r=-EFAULT;
    if (!r && output->capacity<bytes) r=-EOVERFLOW;
    if (!r) {
        struct md_ipc_identity *visible=output->data;
        *visible=saved->ids;
        int pid=md_pid_numbers_visible(saved->groups+saved->ids.group_count,
            saved->process_count*sizeof(struct md_pid_number_value),md_pid_identity_namespace(process),saved->ids.pid);
        if (pid<0) { sqlite3_finalize(q); return pid; }
        visible->pid=pid;
        uint32_t *groups=(void *)(visible+1);
        if (req->mode) memcpy(groups,saved->groups,saved->ids.group_count*sizeof(uint32_t));
        result->size=bytes;
        if (viewer->user_namespace) {
            visible->uid=md_identity_visible_id(viewer,0,visible->uid);
            visible->gid=md_identity_visible_id(viewer,1,visible->gid);
            if (req->mode) for (unsigned i=0;i<visible->group_count;++i)
                groups[i]=md_identity_visible_id(viewer,1,groups[i]);
        }
    }
    sqlite3_finalize(q); return r;
}
static int connection_key(struct md_ipc_credentials *s, uint64_t key, struct md_ipc_connection *out,
        enum md_ipc_ancillary_transport *transport) {
    sqlite3_stmt *q = NULL;
    struct md_ipc_connection connection={0};
    int r = statement(s, "SELECT link,valid,side,transport FROM connections WHERE cookie=?1", &q);
    enum md_ipc_ancillary_transport selected=MD_IPC_TRANSPORT_NATIVE;
    if (!r) {
        sqlite3_bind_int64(q, 1, (sqlite3_int64)key);
        int step = sqlite3_step(q);
        if (step != SQLITE_ROW) r = step == SQLITE_DONE ? -ENODATA : -EIO;
        else if (sqlite3_column_int(q, 1) != 1) r = -ESTALE;
        else if (sqlite3_column_bytes(q, 0) != sizeof(connection.link)
                || sqlite3_column_type(q, 2)!=SQLITE_INTEGER
                || (unsigned)sqlite3_column_int(q, 2)>1
                || sqlite3_column_type(q,3)!=SQLITE_INTEGER
                || (unsigned)sqlite3_column_int(q,3)>MD_IPC_TRANSPORT_ORIGINS_V1) r = -EPROTO;
        else {
            memcpy(connection.link, sqlite3_column_blob(q, 0), sizeof(connection.link));
            connection.side=(unsigned)sqlite3_column_int(q, 2);
            selected=(enum md_ipc_ancillary_transport)sqlite3_column_int(q,3);
        }
    }
    sqlite3_finalize(q);
    if (!r) { *out=connection; if (transport) *transport=selected; }
    return r;
}
static int connection_snapshot(struct md_ipc_credentials *s, int fd, struct md_ipc_connection *out,
        enum md_ipc_ancillary_transport *transport) {
    if (!s) return -ENOTSUP;
    if (!out) return -EINVAL;
    uint64_t key;
    int r=socket_key(fd,&key);
    /* EVENT_WAIT: metadata gate release; interruption returns an error without
     * publishing a connection or running any application IO. */
    if (!r && flock(s->gate,LOCK_EX)) r=-errno;
    if (r) return r;
    r=connection_key(s,key,out,transport);
    flock(s->gate,LOCK_UN);
    return r;
}
int md_ipc_credentials_connection(struct md_ipc_credentials *s, int fd, struct md_ipc_connection *out) {
    return connection_snapshot(s,fd,out,NULL);
}
int md_ipc_credentials_bind(struct md_ipc_credentials *s, int fd, struct md_ipc_binding *out) {
    if (!out || out->scope) return -EINVAL;
    struct md_ipc_connection connection;
    enum md_ipc_ancillary_transport transport;
    int r=connection_snapshot(s,fd,&connection,&transport);
    if (!r) {
        atomic_fetch_add_explicit(&s->scope->refs,1,memory_order_relaxed);
        *out=(struct md_ipc_binding){.connection=connection,.scope=s->scope,.transport=transport};
    }
    return r;
}
struct message_token { uint64_t magic; unsigned char nonce[16]; };
#define MESSAGE_MAGIC UINT64_C(0x4d44495043494431)
int md_ipc_credentials_claim(const struct md_identity *id, const struct md_pid_identity *process,
        pid_t peer, const struct ucred *claim, uint32_t *uid, uint32_t *gid) {
    *uid=md_user_namespace_into(id->user_namespace,0,claim->uid);
    *gid=md_user_namespace_into(id->user_namespace,1,claim->gid);
    if (*uid==UINT32_MAX || *gid==UINT32_MAX) return -EINVAL;
    pid_t self=process ? md_pid_identity_number(process,md_pid_identity_namespace(process)) : peer;
    if (claim->pid!=self
            || (!md_identity_capable(id,CAP_SETUID) && *uid!=id->uid.real
                && *uid!=id->uid.effective && *uid!=id->uid.saved)
            || (!md_identity_capable(id,CAP_SETGID) && *gid!=id->gid.real
                && *gid!=id->gid.effective && *gid!=id->gid.saved)) return -EPERM;
    return 0;
}
static int message_identity(struct md_ipc_credentials *s, const struct md_identity *id, const struct md_pid_identity *process,
        const struct md_fs_request *req, uint64_t key, struct md_fs_result *out) {
    struct md_ipc_connection connection;
    int r=connection_key(s,key,&connection,NULL);
    if (r) return r;
    sqlite3_stmt *q=NULL;
    struct message_token token = {.magic=MESSAGE_MAGIC};
    struct stat st;
    int fd = -1;
    if (req->flags == MD_IPC_MESSAGE_CREATE || req->flags == MD_IPC_MESSAGE_SENDER) {
        int implicit=req->flags==MD_IPC_MESSAGE_SENDER;
        uint32_t uid=id->uid.effective, gid=id->gid.effective;
        struct ucred claim={(pid_t)req->offset,req->attributes.uid,req->attributes.gid};
        if (!implicit && (r=md_ipc_credentials_claim(id,process,req->peer,&claim,&uid,&gid))) return r;
        if (getrandom(token.nonce, sizeof(token.nonce), 0) != sizeof(token.nonce)) return -EIO;
        fd = (int)syscall(SYS_memfd_create, "guest-ipc-message", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        if (fd < 0) return -errno;
        if (write(fd, &token, sizeof(token)) != sizeof(token)) r = -EIO;
        if (!r && fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) r = -errno;
        if (!r && fstat(fd, &st)) r = -errno;
        if (!r) r = statement(s, "INSERT INTO messages VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)", &q);
        if (!r) {
            sqlite3_bind_blob(q, 1, token.nonce, sizeof(token.nonce), SQLITE_STATIC);
            sqlite3_bind_blob(q, 2, connection.link, sizeof(connection.link), SQLITE_STATIC);
            sqlite3_bind_int64(q, 3, st.st_dev); sqlite3_bind_int64(q, 4, st.st_ino);
            sqlite3_bind_int(q, 5, req->peer); sqlite3_bind_int64(q, 6, uid); sqlite3_bind_int64(q, 7, gid);
            sqlite3_bind_int(q, 8, (int)connection.side);
            struct md_pid_number_value numbers[MD_PID_LEVELS];
            unsigned count=md_pid_identity_export(process,numbers);
            sqlite3_bind_blob(q,9,numbers,(int)(count*sizeof(*numbers)),SQLITE_TRANSIENT);
            r = sql(sqlite3_step(q));
        }
        if (!r) out->fd = fd; else close(fd);
    } else {
        fd = req->directory[1];
        int seals = fcntl(fd, F_GET_SEALS), required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
        if (seals < 0 || (seals & required) != required || fstat(fd, &st) || st.st_size != sizeof(token)
                || pread(fd, &token, sizeof(token), 0) != sizeof(token) || token.magic != MESSAGE_MAGIC) return -ENODATA;
        r = statement(s, "SELECT pid,uid,gid,process FROM messages WHERE nonce=?1 AND link=?2 AND device=?3 AND inode=?4 AND side=?5", &q);
        if (!r) {
            sqlite3_bind_blob(q, 1, token.nonce, sizeof(token.nonce), SQLITE_STATIC);
            sqlite3_bind_blob(q, 2, connection.link, sizeof(connection.link), SQLITE_STATIC);
            sqlite3_bind_int64(q, 3, st.st_dev); sqlite3_bind_int64(q, 4, st.st_ino);
            sqlite3_bind_int(q, 5, (int)(connection.side^1));
            int step = sqlite3_step(q);
            if (step != SQLITE_ROW) r = step == SQLITE_DONE ? -ENODATA : -EIO;
            else {
                int pid=md_pid_numbers_visible(sqlite3_column_blob(q,3),(size_t)sqlite3_column_bytes(q,3),
                    md_pid_identity_namespace(process),sqlite3_column_int(q,0));
                if (pid<0) r=pid;
                else out->position=pid;
                out->info.uid = md_identity_visible_id(id,0,(uint32_t)sqlite3_column_int64(q, 1));
                out->info.gid = md_identity_visible_id(id,1,(uint32_t)sqlite3_column_int64(q, 2));
            }
        }
    }
    sqlite3_finalize(q); return r;
}
void md_ipc_credentials_execute(struct md_ipc_credentials *s, const struct md_identity *identity, const struct md_pid_identity *process,
        const struct md_fs_request *q, struct md_fs_result *out, const struct md_fs_output *output) {
    *out = (struct md_fs_result){.fd=-1};
    if (!s) { out->error = -ENOTSUP; return; }
    uint64_t key;
    int r = socket_key(q->directory[0], &key);
    if (!r && flock(s->gate, LOCK_EX)) r = -errno;
    if (r) { out->error = r; return; }
    if (q->operation==MD_FS_IPC_PEER) {
        out->error=peer_snapshot(s,identity,process,q,key,out,output);
        flock(s->gate,LOCK_UN); return;
    }
    size_t bytes = 0;
    struct snapshot *self = NULL;
    if (q->flags == MD_IPC_LISTEN_BEGIN || q->flags == MD_IPC_CONNECT_BEGIN || q->flags == MD_IPC_PAIR) {
        self = snapshot(identity, process, q->peer, &bytes);
        if (!self) r = -ENOMEM;
    }
    int transaction=q->flags==MD_IPC_CONNECT_BEGIN || q->flags==MD_IPC_ACCEPT || q->flags==MD_IPC_PAIR;
    if (!r && transaction) r=execute(s,"BEGIN IMMEDIATE");
    if (!r) switch (q->flags) {
    case MD_IPC_LISTEN_BEGIN: case MD_IPC_LISTEN_END: r = listen_update(s, q, key, self, bytes); break;
    case MD_IPC_CONNECT_BEGIN: r = connect_begin(s, q, key, self, bytes, out); break;
    case MD_IPC_CONNECT_END: r = connect_end(s, q, key); break;
    case MD_IPC_ACCEPT: r = accept_peer(s, q->directory[0], key); break;
    case MD_IPC_PAIR: {
        uint64_t other;
        struct md_ipc_connection connection={0};
        r = socket_key(q->directory[1], &other);
        if (!r) {
            int native=native_socket(s,key);
            if (!native) native=native_socket(s,other);
            if (native) { r=native<0 ? native : 0; break; }
        }
        if (!r && getrandom(connection.link, sizeof(connection.link), 0) != sizeof(connection.link)) r = -EIO;
        if (!r) r = save_connection(s, key, NULL, 0, self, bytes, self, bytes, NULL, 0, 0, 0, 1, &connection,s->offer);
        connection.side=1;
        if (!r) r = save_connection(s, other, NULL, 0, self, bytes, self, bytes, NULL, 0, 0, 0, 1, &connection,s->offer);
        break;
    }
    case MD_IPC_MESSAGE_CREATE: case MD_IPC_MESSAGE_SENDER: case MD_IPC_MESSAGE_READ:
        r = message_identity(s, identity, process, q, key, out); break;
    case MD_IPC_NAME: {
        struct sockaddr_un name; int n;
        r = decode_name(q->path[0], &name, &n);
        sqlite3_stmt *query = NULL;
        if (!r) r = statement(s, "SELECT hidden FROM connections WHERE name=?1", &query);
        if (!r) {
            sqlite3_bind_blob(query, 1, name.sun_path, n, SQLITE_STATIC);
            int step = sqlite3_step(query);
            if (step == SQLITE_ROW) out->position = sqlite3_column_int(query, 0);
            else if (step != SQLITE_DONE) r = -EIO;
        }
        sqlite3_finalize(query); break;
    }
    default: r = -EINVAL; break;
    }
    if (transaction) {
        if (!r) r=execute(s,"COMMIT");
        if (r) execute(s,"ROLLBACK");
    }
    free(self); flock(s->gate, LOCK_UN); out->error = r;
}

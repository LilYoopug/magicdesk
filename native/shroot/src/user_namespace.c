#define _GNU_SOURCE
#include "user_namespace.h"
#include "namespace_identity.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

enum { MAGIC=0x4d44554e, VERSION=3,
    SEALS=F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_FUTURE_WRITE|F_SEAL_SEAL };
struct id_map { atomic_uint count; struct md_id_extent ranges[MD_USER_MAP_EXTENTS]; };
struct namespace_page {
    uint32_t magic, version, depth, owner, group, creator_setfcap;
    uint64_t inode;
    struct md_user_namespace_key parent;
    atomic_uint groups_allowed;
    atomic_uint max_user_namespaces;
    struct id_map maps[2];
};
_Static_assert(ATOMIC_INT_LOCK_FREE==2 && sizeof(atomic_uint)==4,
    "namespace policy requires shared lock-free publication");
struct md_user_namespace {
    atomic_uint references;
    struct md_user_namespace *parent;
    struct md_user_namespace_key id;
    int fd, writer;
    struct namespace_page *page;
    struct namespace_count *accounts, *charge;
};
struct namespace_count {
    struct namespace_count *next;
    struct md_user_namespace *space;
    uint32_t uid, count;
};
static pthread_mutex_t counts_lock=PTHREAD_MUTEX_INITIALIZER;
static struct namespace_count *initial_accounts;
static atomic_uint initial_max=INT_MAX;

uint32_t md_user_namespace_limit(const struct md_user_namespace *n) {
    return atomic_load_explicit(n ? &n->page->max_user_namespaces : &initial_max,memory_order_relaxed);
}
int md_user_namespace_set_limit(struct md_user_namespace *n,uint32_t limit) {
    if (limit>INT_MAX) return -EINVAL;
    if (n && !n->writer) return -EPERM;
    atomic_store_explicit(n ? &n->page->max_user_namespaces : &initial_max,limit,memory_order_relaxed);
    return 0;
}
static struct namespace_count *count_parent(struct namespace_count *c) {
    return c->space ? c->space->charge : NULL;
}
static void count_remove(struct namespace_count *c) {
    struct namespace_count **p=c->space ? &c->space->accounts : &initial_accounts;
    while (*p!=c) p=&(*p)->next;
    *p=c->next; free(c);
}
/* A namespace charges its creator in the parent and each ancestor's creator.
 * Parent references keep this chain alive; descriptor/worker references may
 * release the last charge outside the supervisor thread. */
static int count_acquire(struct md_user_namespace *n) {
    struct md_user_namespace *parent=n->parent;
    if (parent && !parent->writer) return -EOPNOTSUPP;
    pthread_mutex_lock(&counts_lock);
    struct namespace_count **head=parent ? &parent->accounts : &initial_accounts;
    struct namespace_count *c=*head;
    while (c && c->uid!=n->page->owner) c=c->next;
    if (!c) {
        c=calloc(1,sizeof(*c));
        if (!c) { pthread_mutex_unlock(&counts_lock); return -ENOMEM; }
        c->space=parent; c->uid=n->page->owner; c->next=*head; *head=c;
    }
    struct namespace_count *bad=NULL;
    for (struct namespace_count *p=c;p;p=count_parent(p)) {
        if (p->count>=md_user_namespace_limit(p->space)) { bad=p; break; }
        ++p->count;
    }
    if (bad) {
        for (struct namespace_count *p=c;p!=bad;p=count_parent(p)) --p->count;
        if (!c->count) count_remove(c);
    } else n->charge=c;
    pthread_mutex_unlock(&counts_lock);
    return bad ? -ENOSPC : 0;
}
static void count_release(struct md_user_namespace *n) {
    if (!n->charge) return;
    pthread_mutex_lock(&counts_lock);
    for (struct namespace_count *p=n->charge;p;p=count_parent(p)) --p->count;
    if (!n->charge->count) count_remove(n->charge);
    pthread_mutex_unlock(&counts_lock);
}
struct md_user_namespace_key md_user_namespace_key(const struct md_user_namespace *n) {
    return n ? n->id : (struct md_user_namespace_key){0};
}
static int same_id(struct md_user_namespace_key a, struct md_user_namespace_key b) {
    return a.device==b.device && a.inode==b.inode && a.generation==b.generation;
}
static int same(const struct md_user_namespace *a, const struct md_user_namespace *b) {
    return a==b || (a && b && same_id(a->id,b->id));
}
int md_user_namespace_same(const struct md_user_namespace *a, const struct md_user_namespace *b) {
    return same(a,b);
}
static unsigned map_count(const struct id_map *m) {
    return m ? atomic_load_explicit(&m->count,memory_order_acquire) : 0;
}
static struct md_user_namespace *allocate(int fd, int writer) {
    struct stat st;
    if (fstat(fd,&st)) return NULL;
    struct md_user_namespace *n=calloc(1,sizeof(*n));
    if (!n) return NULL;
    n->page=mmap(NULL,sizeof(*n->page),PROT_READ|(writer ? PROT_WRITE : 0),MAP_SHARED,fd,0);
    if (n->page==MAP_FAILED) { int error=errno; free(n); errno=error; return NULL; }
    atomic_init(&n->references,1); n->fd=fd; n->writer=writer;
    n->id=(struct md_user_namespace_key){st.st_dev,st.st_ino,n->page->inode}; return n;
}
struct md_user_namespace *md_user_namespace_new(struct md_user_namespace *parent,
        uint32_t owner, uint32_t group, int creator_setfcap) {
    if ((parent && parent->page->depth>=MD_USER_NAMESPACE_DEPTH) || owner==UINT32_MAX || group==UINT32_MAX) {
        errno=parent && parent->page->depth>=MD_USER_NAMESPACE_DEPTH ? ENOSPC : EINVAL; return NULL;
    }
    if (md_user_namespace_from(parent,0,owner)==UINT32_MAX
            || md_user_namespace_from(parent,1,group)==UINT32_MAX) { errno=EPERM; return NULL; }
    int fd=memfd_create("shroot-user-namespace",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    if (fd<0) return NULL;
    if (ftruncate(fd,sizeof(struct namespace_page))) { int error=errno; close(fd); errno=error; return NULL; }
    struct md_user_namespace *n=allocate(fd,1);
    if (!n) { int error=errno; close(fd); errno=error; return NULL; }
    *n->page=(struct namespace_page){.magic=MAGIC,.version=VERSION,
        .depth=parent ? parent->page->depth+1 : 1,.owner=owner,.group=group,
        .creator_setfcap=!!creator_setfcap,.parent=md_user_namespace_key(parent)};
    atomic_init(&n->page->groups_allowed,md_user_namespace_groups_allowed(parent));
    atomic_init(&n->page->max_user_namespaces,INT_MAX);
    atomic_init(&n->page->maps[0].count,0); atomic_init(&n->page->maps[1].count,0);
    int identity_error=md_namespace_identity_new(&n->page->inode);
    if (identity_error) { md_user_namespace_release(n); errno=-identity_error; return NULL; }
    n->id.generation=n->page->inode;
    if (fcntl(fd,F_ADD_SEALS,SEALS)) {
        int error=errno; md_user_namespace_release(n); errno=error; return NULL;
    }
    n->parent=md_user_namespace_retain(parent);
    int error=count_acquire(n);
    if (error) { md_user_namespace_release(n); errno=-error; return NULL; }
    return n;
}
struct md_user_namespace *md_user_namespace_retain(struct md_user_namespace *n) {
    if (n) atomic_fetch_add_explicit(&n->references,1,memory_order_relaxed);
    return n;
}
uint64_t md_user_namespace_inode(const struct md_user_namespace *n) { return n ? n->page->inode : 1; }
uint32_t md_user_namespace_creator(const struct md_user_namespace *n) { return n ? n->page->owner : 0; }
void md_user_namespace_release(struct md_user_namespace *n) {
    if (!n || atomic_fetch_sub_explicit(&n->references,1,memory_order_acq_rel)!=1) return;
    count_release(n);
    md_user_namespace_release(n->parent);
    munmap(n->page,sizeof(*n->page)); close(n->fd); free(n);
}
static uint32_t translate(const struct id_map *map, uint32_t id, int reverse) {
    if (!map || id==UINT32_MAX) return UINT32_MAX;
    unsigned count=map_count(map);
    for (unsigned i=0;i<count;++i) {
        const struct md_id_extent *r=map->ranges+i;
        uint32_t start=reverse ? r->outside : r->inside;
        if (id>=start && id-start<r->count) return (reverse ? r->inside : r->outside)+(id-start);
    }
    return UINT32_MAX;
}
uint32_t md_user_namespace_into(const struct md_user_namespace *n, int group, uint32_t id) {
    for (; n && id!=UINT32_MAX; n=n->parent)
        id=translate(&n->page->maps[!!group],id,0);
    return id;
}
uint32_t md_user_namespace_from(const struct md_user_namespace *n, int group, uint32_t id) {
    if (!n || id==UINT32_MAX) return id;
    id=md_user_namespace_from(n->parent,group,id);
    return translate(&n->page->maps[!!group],id,1);
}
int md_user_namespace_contains(const struct md_user_namespace *ancestor, const struct md_user_namespace *n) {
    for (;;) {
        if (same(n,ancestor)) return 1;
        if (!n) return 0;
        n=n->parent;
    }
}
int md_user_namespace_capable(const struct md_user_namespace *actor, uint32_t uid, uint64_t caps,
        const struct md_user_namespace *target, unsigned cap) {
    if (cap>=64) return 0;
    for (;;) {
        if (same(actor,target)) return !!(caps&(UINT64_C(1)<<cap));
        if (!target) return 0;
        if (same(target->parent,actor) && target->page->owner==uid) return 1;
        target=target->parent;
    }
}
static int overlap(uint32_t a, uint32_t an, uint32_t b, uint32_t bn) {
    return (uint64_t)a+an>b && (uint64_t)b+bn>a;
}
/* Linux maps each extent through one parent extent; adjacent ranges do not
 * permit a single child extent to cross their boundary. */
static int covered(const struct md_user_namespace *n, int group, uint32_t start, uint32_t count) {
    if (!n) return 1;
    const struct id_map *map=&n->page->maps[!!group];
    unsigned count_maps=map_count(map);
    for (unsigned i=0;i<count_maps;++i) {
        const struct md_id_extent *r=map->ranges+i;
        if (start>=r->inside && (uint64_t)start+count<=(uint64_t)r->inside+r->count)
            return covered(n->parent,group,r->outside+(start-r->inside),count);
    }
    return 0;
}
static int capable(const struct md_user_authority *a, const struct md_user_namespace *n, unsigned cap) {
    return a && md_user_namespace_capable(a->namespace,a->uid,a->caps,n,cap);
}
int md_user_namespace_map_admit(const struct md_user_namespace *n, int group,
        const struct md_user_authority *opener) {
    if (!n || !n->writer || !opener
            || (!same(opener->namespace,n) && !same(opener->namespace,n->parent))) return -EPERM;
    if (map_count(&n->page->maps[!!group])) return -EPERM;
    if (!capable(opener,n,CAP_SYS_ADMIN)) return -EPERM;
    return 0;
}
int md_user_namespace_map(struct md_user_namespace *n, int group,
        const struct md_user_authority *opener, const struct md_user_authority *writer,
        const struct md_id_extent *ranges, unsigned count) {
    int error=md_user_namespace_map_admit(n,group,opener);
    if (error) return error;
    group=!!group;
    if (!ranges || !count || count>MD_USER_MAP_EXTENTS) return -EINVAL;
    for (unsigned i=0;i<count;++i) {
        const struct md_id_extent *r=ranges+i;
        if (!r->count || (uint64_t)r->inside+r->count>UINT32_MAX
                || (uint64_t)r->outside+r->count>UINT32_MAX) return -EINVAL;
        for (unsigned j=0;j<i;++j)
            if (overlap(r->inside,r->count,ranges[j].inside,ranges[j].count)
                    || overlap(r->outside,r->count,ranges[j].outside,ranges[j].count)) return -EINVAL;
    }
    unsigned cap=group ? CAP_SETGID : CAP_SETUID;
    int privileged=capable(opener,n->parent,cap) && capable(writer,n->parent,cap);
    if (!privileged && (count!=1 || ranges[0].count!=1 || n->page->owner!=opener->uid
            || md_user_namespace_into(n->parent,group,ranges[0].outside)!=(group ? opener->gid : opener->uid)
            || (group && md_user_namespace_groups_allowed(n)))) return -EPERM;
    for (unsigned i=0;i<count;++i) {
        const struct md_id_extent *r=ranges+i;
        if (!group && !r->outside && !(same(opener->namespace,n) ? n->page->creator_setfcap
                : capable(opener,n->parent,CAP_SETFCAP))) return -EPERM;
        if (!covered(n->parent,group,r->outside,r->count)) return -EPERM;
    }
    struct id_map *map=&n->page->maps[group];
    for (unsigned i=0;i<count;++i) map->ranges[i]=ranges[i];
    /* The creating supervisor serializes map writers. Readers, including
     * imported filesystem owners, acquire only the fully published extents. */
    atomic_store_explicit(&map->count,count,memory_order_release);
    return 0;
}
int md_user_namespace_setgroups(struct md_user_namespace *n, int allowed) {
    if (!n || !n->writer) return -EPERM;
    if (allowed) return md_user_namespace_groups_allowed(n) ? 0 : -EPERM;
    if (map_count(&n->page->maps[1])) return -EPERM;
    atomic_store_explicit(&n->page->groups_allowed,0,memory_order_release);
    return 0;
}
int md_user_namespace_groups_allowed(const struct md_user_namespace *n) {
    return !n || atomic_load_explicit(&n->page->groups_allowed,memory_order_acquire);
}
int md_user_namespace_may_setgroups(const struct md_user_namespace *n) {
    return !n || (md_user_namespace_groups_allowed(n)
        && map_count(&n->page->maps[1]));
}
const struct md_user_namespace *md_user_namespace_parent(const struct md_user_namespace *n) {
    return n ? n->parent : NULL;
}
int md_user_namespace_extents(const struct md_user_namespace *n, int group, struct md_id_extent *out, unsigned capacity) {
    const struct id_map *map=n ? &n->page->maps[!!group] : NULL;
    unsigned count=n ? map_count(map) : 1;
    if (capacity<count) return -ERANGE;
    if (!n) *out=(struct md_id_extent){0,0,UINT32_MAX};
    else for (unsigned i=0;i<count;++i) out[i]=map->ranges[i];
    return (int)count;
}

unsigned md_user_namespace_depth(const struct md_user_namespace *n) {
    return n ? n->page->depth : 0;
}
int md_user_namespace_export(const struct md_user_namespace *n, int *fds, unsigned capacity) {
    unsigned count=md_user_namespace_depth(n);
    if (capacity<count || (count && !fds)) return -ERANGE;
    unsigned i=count;
    for (;n;n=n->parent) {
        int fd=fcntl(n->fd,F_DUPFD_CLOEXEC,3);
        if (fd<0) { int error=-errno; while (i<count) close(fds[i++]); return error; }
        fds[--i]=fd;
    }
    return (int)count;
}
static int valid_page(const struct md_user_namespace *n, unsigned depth,
        const struct md_user_namespace *parent) {
    const struct namespace_page *p=n->page;
    if (p->magic!=MAGIC || p->version!=VERSION || p->depth!=depth
            || p->owner==UINT32_MAX || p->group==UINT32_MAX || p->creator_setfcap>1
            || atomic_load_explicit(&p->groups_allowed,memory_order_acquire)>1
            || md_user_namespace_limit(n)>INT_MAX
            || !same_id(p->parent,md_user_namespace_key(parent))) return -EPROTO;
    for (unsigned group=0;group<2;++group) {
        const struct id_map *m=&p->maps[group];
        unsigned count=map_count(m);
        if (count>MD_USER_MAP_EXTENTS) return -EPROTO;
        for (unsigned i=0;i<count;++i) {
            const struct md_id_extent *r=&m->ranges[i];
            if (!r->count || (uint64_t)r->inside+r->count>UINT32_MAX
                    || (uint64_t)r->outside+r->count>UINT32_MAX
                    || !covered(parent,group,r->outside,r->count)) return -EPROTO;
            for (unsigned j=0;j<i;++j)
                if (overlap(r->inside,r->count,m->ranges[j].inside,m->ranges[j].count)
                        || overlap(r->outside,r->count,m->ranges[j].outside,m->ranges[j].count)) return -EPROTO;
        }
    }
    return 0;
}
int md_user_namespace_import(const int *fds, unsigned count, struct md_user_namespace **out) {
    if (!out || *out || count>MD_USER_NAMESPACE_DEPTH || (count && !fds)) return -EINVAL;
    struct md_user_namespace *parent=NULL;
    int error=0;
    for (unsigned i=0;!error && i<count;++i) {
        struct stat st;
        if (fstat(fds[i],&st)) { error=-errno; break; }
        int seals=fcntl(fds[i],F_GET_SEALS);
        if (!S_ISREG(st.st_mode) || st.st_size!=sizeof(struct namespace_page)
                || seals<0 || (seals&SEALS)!=SEALS) { error=-EPROTO; break; }
        int fd=fcntl(fds[i],F_DUPFD_CLOEXEC,3);
        if (fd<0) { error=-errno; break; }
        struct md_user_namespace *n=allocate(fd,0);
        if (!n) { error=-errno; close(fd); break; }
        error=valid_page(n,i+1,parent);
        if (error) md_user_namespace_release(n);
        else { n->parent=parent; parent=n; }
    }
    if (error) md_user_namespace_release(parent); else *out=parent;
    return error;
}

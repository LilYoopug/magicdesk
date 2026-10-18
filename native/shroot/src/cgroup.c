#define _GNU_SOURCE
#include "cgroup.h"
#include "cgroup_program.h"
#include "task_resources.h"
#include "temporary_directory.h"
#include "file_permissions.h"
#include "mount_policy.h"
#include "namespace_identity.h"
#include "inode_watch.h"
#include "watch_source.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/magic.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/inotify.h>

enum { PROCS, THREADS, EVENTS, CONTROLLERS, SUBTREE, TYPE, FREEZE,
    ALLOW, DENY, LIST, TASKS, NOTIFY, RELEASE, PIDS_MAX, PIDS_CURRENT, PIDS_EVENTS, FILES };
struct control { const char *name; mode_t mode; unsigned views; };
static const struct control controls[FILES]={
    [PROCS]={"cgroup.procs",0644,3}, [THREADS]={"cgroup.threads",0644,1},
    [EVENTS]={"cgroup.events",0444,1}, [CONTROLLERS]={"cgroup.controllers",0444,1},
    [SUBTREE]={"cgroup.subtree_control",0644,1}, [TYPE]={"cgroup.type",0644,1},
    [FREEZE]={"cgroup.freeze",0644,1}, [ALLOW]={"devices.allow",0200,2},
    [DENY]={"devices.deny",0200,2}, [LIST]={"devices.list",0444,2},
    [TASKS]={"tasks",0644,2}, [NOTIFY]={"notify_on_release",0644,2},
    [RELEASE]={"release_agent",0644,2},
    [PIDS_MAX]={"pids.max",0644,1}, [PIDS_CURRENT]={"pids.current",0444,1},
    [PIDS_EVENTS]={"pids.events",0444,1}
};
struct group {
    struct group *next,*parent;
    int fd,removed;
    struct stat identity,files[FILES];
    struct opened *opened;
    uid_t uid; gid_t gid;
    char name[256];
    struct md_cgroup_program **programs;
    unsigned program_count,program_flags;
    unsigned subtree;
    uint64_t pids_max;
    uint64_t populated, event_id, generation;
};
struct world {
    atomic_uint refs;
    pthread_mutex_t lock;
    struct md_cgroup_member *members;
    struct md_cgroup_view *views[2];
    struct md_cgroup_programs *programs;
};
struct md_cgroup_view {
    struct world *world;
    int devices,storage;
    struct group *groups,*root;
    struct md_watch_source *events;
    uint64_t next_event_id;
};
struct md_cgroup_member {
    atomic_uint refs;
    struct md_cgroup_member *next;
    struct world *world;
    struct group *groups[2];
    pid_t tid,tgid;
    int departed;
    struct md_pid_identity *pid,*pid_group;
};
struct md_cgroup_namespace {
    atomic_uint refs;
    uint64_t inode;
    struct md_user_namespace *owner;
    struct world *world;
    /* NULL captures the hierarchy root before its first mount, not the
     * member's future position. Groups live as long as their world. */
    struct group *roots[2];
};
struct opened {
    atomic_uint refs;
    struct md_cgroup_view *view;
    struct opened *next;
    struct group *group;
    unsigned file;
    struct stat stat;
    struct md_fs_anchor *origin;
    struct md_watch_listener *listener;
    uint64_t observed;
};
static void group_event(struct md_cgroup_view *v,struct group *g,unsigned mask) {
    ++g->generation;
    if (v->events) md_watch_source_emit(v->events,g->event_id,mask,0,NULL,0);
}
/* Membership changes touch only the two branches below their common ancestor.
 * Fork/exit in a populated branch cannot manufacture an empty notification. */
static void membership_change(struct md_cgroup_view *v,struct group *old,struct group *next) {
    if (!v || v->devices || old==next) return;
    struct group *common=old;
    while (common) {
        struct group *at=next;
        while (at && at!=common) at=at->parent;
        if (at) break;
        common=common->parent;
    }
    for (struct group *g=old;g!=common;g=g->parent)
        if (!--g->populated) group_event(v,g,IN_MODIFY);
    for (struct group *g=next;g!=common;g=g->parent)
        if (!g->populated++) group_event(v,g,IN_MODIFY);
}
static struct world *retain(struct world *w) { atomic_fetch_add(&w->refs,1); return w; }
static void clear_programs(struct group *g) {
    for (unsigned i=0;i<g->program_count;++i) md_cgroup_program_release(g->programs[i]);
    free(g->programs); g->programs=NULL; g->program_count=g->program_flags=0;
}
static void release(struct world *w) {
    if (atomic_fetch_sub(&w->refs,1)!=1) return;
    for (unsigned i=0;i<2;++i) if (w->views[i]) {
        struct md_cgroup_view *v=w->views[i];
        while (v->groups) { struct group *g=v->groups; v->groups=g->next; clear_programs(g); if (g->fd>=0) close(g->fd); free(g); }
        md_watch_source_release(v->events); md_temporary_directory_release(v->storage); free(v);
    }
    md_cgroup_programs_release(w->programs);
    pthread_mutex_destroy(&w->lock); free(w);
}
struct md_cgroup_programs *md_cgroup_program_registry(struct md_cgroup_member *m,int create) {
    if (!m) { errno=EINVAL; return NULL; }
    struct world *w=m->world;
    pthread_mutex_lock(&w->lock);
    if (!w->programs && create) w->programs=md_cgroup_programs_new();
    struct md_cgroup_programs *p=md_cgroup_programs_retain(w->programs);
    pthread_mutex_unlock(&w->lock); return p;
}
struct md_cgroup_namespace *md_cgroup_namespace_new(struct md_cgroup_member *m,struct md_user_namespace *owner) {
    if (!m) { errno=EINVAL; return NULL; }
    struct md_cgroup_namespace *ns=calloc(1,sizeof(*ns));
    if (!ns) return NULL;
    int r=md_namespace_identity_new(&ns->inode);
    if (r) { free(ns); errno=-r; return NULL; }
    atomic_init(&ns->refs,1); ns->owner=md_user_namespace_retain(owner); ns->world=retain(m->world);
    pthread_mutex_lock(&m->world->lock);
    memcpy(ns->roots,m->groups,sizeof(ns->roots));
    pthread_mutex_unlock(&m->world->lock); return ns;
}
struct md_cgroup_namespace *md_cgroup_namespace_retain(struct md_cgroup_namespace *ns) {
    if (ns) atomic_fetch_add(&ns->refs,1); return ns;
}
void md_cgroup_namespace_release(struct md_cgroup_namespace *ns) {
    if (!ns || atomic_fetch_sub(&ns->refs,1)!=1) return;
    md_user_namespace_release(ns->owner); release(ns->world); free(ns);
}
uint64_t md_cgroup_namespace_inode(const struct md_cgroup_namespace *ns) { return ns ? ns->inode : 0; }
const struct md_user_namespace *md_cgroup_namespace_owner(const struct md_cgroup_namespace *ns) { return ns ? ns->owner : NULL; }
struct md_cgroup_member *md_cgroup_member_new(void) {
    struct world *w=calloc(1,sizeof(*w)); if (!w) return NULL;
    atomic_init(&w->refs,1);
    int error=pthread_mutex_init(&w->lock,NULL);
    if (error) { free(w); errno=error; return NULL; }
    struct md_cgroup_member *m=calloc(1,sizeof(*m));
    if (!m) { release(w); return NULL; }
    atomic_init(&m->refs,1); m->world=w; w->members=m; return m;
}
struct md_cgroup_member *md_cgroup_member_fork(struct md_cgroup_member *old) {
    if (!old) return NULL;
    struct md_cgroup_member *m=calloc(1,sizeof(*m)); if (!m) return NULL;
    atomic_init(&m->refs,1); m->world=retain(old->world);
    pthread_mutex_lock(&m->world->lock);
    memcpy(m->groups,old->groups,sizeof(m->groups));
    m->next=m->world->members; m->world->members=m;
    pthread_mutex_unlock(&m->world->lock); return m;
}
struct md_cgroup_member *md_cgroup_member_retain(struct md_cgroup_member *m) {
    if (m) atomic_fetch_add(&m->refs,1); return m;
}
void md_cgroup_member_release(struct md_cgroup_member *m) {
    if (!m || atomic_fetch_sub(&m->refs,1)!=1) return;
    struct world *w=m->world; pthread_mutex_lock(&w->lock);
    if (m->tid) membership_change(w->views[0],m->groups[0],NULL);
    struct md_cgroup_member **at=&w->members;
    while (*at!=m) at=&(*at)->next;
    *at=m->next;
    pthread_mutex_unlock(&w->lock);
    md_pid_identity_release(m->pid); md_pid_identity_release(m->pid_group); free(m); release(w);
}
void md_cgroup_member_publish(struct md_cgroup_member *m,pid_t tid,pid_t tgid,
        struct md_pid_identity *pid,struct md_pid_identity *group) {
    if (!m) return;
    pthread_mutex_lock(&m->world->lock);
    struct md_pid_identity *old=m->pid,*old_group=m->pid_group;
    if (!m->tid && tid) membership_change(m->world->views[0],NULL,m->groups[0]);
    else if (m->tid && !tid) membership_change(m->world->views[0],m->groups[0],NULL);
    m->tid=tid; m->tgid=tgid; m->departed=0; m->pid=md_pid_identity_retain(pid);
    m->pid_group=md_pid_identity_retain(group);
    pthread_mutex_unlock(&m->world->lock); md_pid_identity_release(old); md_pid_identity_release(old_group);
}
void md_cgroup_member_depart(struct md_cgroup_member *m,pid_t tid) {
    if (!m) return;
    pthread_mutex_lock(&m->world->lock);
    if (m->tid==tid && tid) {
        membership_change(m->world->views[0],m->groups[0],NULL);
        m->tid=0; m->departed=1;
    }
    pthread_mutex_unlock(&m->world->lock);
}
enum { CONTROLLER_PIDS=1 };
static unsigned available(const struct group *g) {
    return g->parent ? g->parent->subtree : CONTROLLER_PIDS;
}
static int enabled(const struct group *g,unsigned file) {
    return file<PIDS_MAX || (g->parent && (available(g)&CONTROLLER_PIDS));
}
static int control_create(struct group *g,unsigned i) {
    int fd=openat(g->fd,controls[i].name,O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600);
    if (fd<0) return -errno;
    int error=fstat(fd,&g->files[i]) ? -errno : 0; close(fd);
    if (!error) {
        g->files[i].st_mode=S_IFREG|controls[i].mode;
        g->files[i].st_uid=g->uid; g->files[i].st_gid=g->gid;
        g->files[i].st_size=g->files[i].st_blocks=0;
    }
    if (error) unlinkat(g->fd,controls[i].name,0);
    return error;
}
static int populate(struct md_cgroup_view *v,struct group *g) {
    if (v->next_event_id==UINT64_MAX) return -EOVERFLOW;
    g->event_id=++v->next_event_id;
    g->pids_max=UINT64_MAX;
    for (unsigned i=0;i<FILES;++i) if (controls[i].views&(1U<<v->devices)) {
        if ((i==RELEASE && g->parent) || !enabled(g,i)) continue;
        int error=control_create(g,i); if (error) return error;
    }
    if (fstat(g->fd,&g->identity)) return -errno;
    g->identity.st_mode=S_IFDIR|0755;
    g->identity.st_uid=g->uid; g->identity.st_gid=g->gid;
    g->identity.st_size=g->identity.st_blocks=0;
    return 0;
}
static void depopulate(struct group *g) {
    for (unsigned i=0;i<FILES;++i) if (g->files[i].st_ino) unlinkat(g->fd,controls[i].name,0);
}
struct md_cgroup_view *md_cgroup_mount(struct md_cgroup_member *member,int parent,int devices,const struct md_identity *id) {
    if (!member || !id || devices<0 || devices>1) { errno=EINVAL; return NULL; }
    struct world *w=member->world; pthread_mutex_lock(&w->lock);
    if (w->views[devices]) {
        struct md_cgroup_view *v=md_cgroup_retain(w->views[devices]); pthread_mutex_unlock(&w->lock); return v;
    }
    struct md_cgroup_view *v=calloc(1,sizeof(*v));
    struct group *g=calloc(1,sizeof(*g));
    int error=(!v || !g) ? -ENOMEM : 0;
    if (v) { v->world=w; v->storage=-1; v->devices=devices; }
    if (g) g->fd=-1;
    if (!error && (v->storage=md_temporary_directory_new(parent))<0) error=v->storage;
    if (!error && mkdirat(v->storage,"cgroup",0700)) error=-errno;
    if (!error && (g->fd=openat(v->storage,"cgroup",O_RDONLY|O_DIRECTORY|O_CLOEXEC))<0) error=-errno;
    if (!error) { g->uid=id->uid.fs; g->gid=id->gid.fs; error=populate(v,g); }
    if (!error) {
        v->root=v->groups=g; w->views[devices]=v;
        for (struct md_cgroup_member *m=w->members;m;m=m->next) {
            m->groups[devices]=g;
            if (!devices && m->tid) ++g->populated;
        }
        md_cgroup_retain(v);
    } else {
        if (g) { if (g->fd>=0) close(g->fd); free(g); }
        if (v) { if (v->storage>=0) md_temporary_directory_release(v->storage); free(v); }
        v=NULL;
    }
    pthread_mutex_unlock(&w->lock); if (error) errno=-error; return v;
}
struct md_cgroup_view *md_cgroup_retain(struct md_cgroup_view *v) { if (v) retain(v->world); return v; }
void md_cgroup_release(struct md_cgroup_view *v) { if (v) release(v->world); }
int md_cgroup_open_root(struct md_cgroup_view *v,const struct md_cgroup_namespace *ns) {
    if (!ns || ns->world!=v->world) { errno=EXDEV; return -1; }
    pthread_mutex_lock(&v->world->lock);
    struct group *g=ns->roots[v->devices] ? ns->roots[v->devices] : v->root;
    int fd;
    if (g->removed) { errno=ENOENT; fd=-1; }
    else fd=openat(g->fd,".",O_PATH|O_DIRECTORY|O_CLOEXEC);
    int error=errno; pthread_mutex_unlock(&v->world->lock); errno=error; return fd;
}
int md_cgroup_devices(const struct md_cgroup_view *v) { return v->devices; }
unsigned long md_cgroup_filesystem(struct md_cgroup_view *v) { return v->devices ? CGROUP_SUPER_MAGIC : CGROUP2_SUPER_MAGIC; }
static struct group *lookup(struct md_cgroup_view *v,const struct stat *st,unsigned *file) {
    for (struct group *g=v->groups;g;g=g->next) {
        if (st->st_dev!=g->identity.st_dev) continue;
        if (st->st_ino==g->identity.st_ino) { *file=FILES; return g; }
        for (unsigned i=0;i<FILES;++i) if (g->files[i].st_ino==st->st_ino) { *file=i; return g; }
    }
    return NULL;
}
int md_cgroup_stat(struct md_cgroup_view *v,int fd,struct stat *st) {
    if (fstat(fd,st)) return -errno;
    pthread_mutex_lock(&v->world->lock); unsigned file;
    struct group *g=lookup(v,st,&file);
    if (g) {
        *st=file==FILES ? g->identity : g->files[file];
        if (g->removed) st->st_nlink=0;
    } else {
        /* Disabled controllers can replace a control inode while an old FD
         * still exists. Its last attributes belong to that retired inode. */
        for (struct group *at=v->groups;at && !g;at=at->next)
            for (struct opened *o=at->opened;o;o=o->next)
                if (st->st_dev==o->stat.st_dev && st->st_ino==o->stat.st_ino) {
                    *st=o->stat; st->st_nlink=0; g=at; break;
                }
    }
    pthread_mutex_unlock(&v->world->lock); return g ? 0 : -ENOENT;
}
static int attributes(struct md_cgroup_view *v,int fd,const struct md_identity *id,
        int ownership,mode_t mode,uint32_t uid,uint32_t gid) {
    struct stat physical;
    if (fstat(fd,&physical)) return -errno;
    pthread_mutex_lock(&v->world->lock); unsigned file;
    struct group *g=lookup(v,&physical,&file);
    int r=!g || g->removed ? -ENOENT : 0;
    struct stat *st=!r ? (file==FILES ? &g->identity : &g->files[file]) : NULL;
    if (!r && ownership) {
        if (uid==UINT32_MAX) uid=st->st_uid;
        if (gid==UINT32_MAX) gid=st->st_gid;
        if (!md_identity_file_capable(id,st->st_uid,st->st_gid,CAP_CHOWN)
                && !(id->uid.fs==st->st_uid && uid==st->st_uid
                    && (gid==st->st_gid || md_identity_in_group(id,gid)))) r=-EPERM;
        if (!r) {
            st->st_uid=uid; st->st_gid=gid;
            if (!S_ISDIR(st->st_mode)) st->st_mode&=~(S_ISUID|S_ISGID);
            if (file==FILES) { g->uid=uid; g->gid=gid; }
        }
    } else if (!r) {
        if (id->uid.fs!=st->st_uid && !md_identity_file_capable(id,st->st_uid,st->st_gid,CAP_FOWNER)) r=-EPERM;
        if (!r) {
            st->st_mode=(st->st_mode&S_IFMT)|(mode&07777);
            if (!md_identity_in_group(id,st->st_gid)
                    && !md_identity_file_capable(id,st->st_uid,st->st_gid,CAP_FSETID)) st->st_mode&=~S_ISGID;
        }
    }
    if (!r) {
        clock_gettime(CLOCK_REALTIME,&st->st_ctim);
        for (struct opened *o=g->opened;o;o=o->next)
            if (o->stat.st_ino==st->st_ino) o->stat=*st;
    }
    pthread_mutex_unlock(&v->world->lock); return r;
}
int md_cgroup_chmod(struct md_cgroup_view *v,int fd,mode_t mode,const struct md_identity *id) {
    return attributes(v,fd,id,0,mode,0,0);
}
int md_cgroup_chown(struct md_cgroup_view *v,int fd,uint32_t uid,uint32_t gid,const struct md_identity *id) {
    return attributes(v,fd,id,1,0,uid,gid);
}
static int capable(const struct md_identity *id,struct group *g) {
    return id->uid.fs==g->uid || md_identity_file_capable(id,g->uid,g->gid,CAP_DAC_OVERRIDE);
}
int md_cgroup_program_query(struct md_cgroup_view *v,int fd,struct md_cgroup_member *member,
        const struct md_identity *id,unsigned flags,uint32_t *ids,unsigned capacity,unsigned *count,unsigned *attach_flags) {
    if (!member || member->world!=v->world) return -EXDEV;
    if (v->devices) return -EINVAL;
    if (flags&~BPF_F_QUERY_EFFECTIVE) return -EINVAL;
    struct stat st; if (fstat(fd,&st)) return -errno;
    pthread_mutex_lock(&v->world->lock); unsigned file;
    struct group *g=lookup(v,&st,&file);
    int r=!g || g->removed ? -ENODEV : file!=FILES ? -EINVAL : !capable(id,g) ? -EACCES : 0;
    *count=*attach_flags=0;
    if (!r) {
        *attach_flags=flags ? 0 : g->program_flags;
        for (;g;g=flags ? g->parent : NULL) for (unsigned i=0;i<g->program_count;++i) {
            if (*count<capacity) ids[*count]=md_cgroup_program_id(g->programs[i]);
            ++*count;
        }
    }
    pthread_mutex_unlock(&v->world->lock); return r;
}
int md_cgroup_program_attach(struct md_cgroup_view *v,int fd,struct md_cgroup_member *member,
        const struct md_identity *id,struct md_cgroup_program *program,unsigned flags,int detach) {
    if (!member || member->world!=v->world) return -EXDEV;
    if (v->devices || flags&~BPF_F_ALLOW_MULTI || (detach && flags)) return -EINVAL;
    if (md_cgroup_program_type(program)!=BPF_PROG_TYPE_CGROUP_DEVICE) return -EINVAL;
    struct stat st; if (fstat(fd,&st)) return -errno;
    pthread_mutex_lock(&v->world->lock); unsigned file;
    struct group *g=lookup(v,&st,&file);
    int r=!g || g->removed ? -ENODEV : file!=FILES ? -EINVAL : !capable(id,g) ? -EACCES : 0;
    if (!r && !md_cgroup_program_belongs(program,v->world->programs)) r=-EINVAL;
    if (!r) {
        unsigned index=0;
        while (index<g->program_count && g->programs[index]!=program) ++index;
        if (detach) {
            if (index==g->program_count) r=-ENOENT;
            else {
                md_cgroup_program_release(g->programs[index]);
                memmove(g->programs+index,g->programs+index+1,(--g->program_count-index)*sizeof(*g->programs));
                if (!g->program_count) clear_programs(g);
            }
        } else if (g->program_count && g->program_flags!=flags) r=-EINVAL;
        else if (index<g->program_count) r=-EEXIST;
        else if (!flags && g->program_count) {
            md_cgroup_program_release(g->programs[0]); g->programs[0]=md_cgroup_program_retain(program);
        } else if (g->program_count==MD_CGROUP_PROGRAM_ATTACHMENTS) r=-E2BIG;
        else {
            void *next=realloc(g->programs,(g->program_count+1)*sizeof(*g->programs));
            if (!next) r=-ENOMEM;
            else { g->programs=next; g->programs[g->program_count++]=md_cgroup_program_retain(program); g->program_flags=flags; }
        }
    }
    pthread_mutex_unlock(&v->world->lock); return r;
}
int md_cgroup_mkdir(struct md_cgroup_view *v,int parent,const char *name,const struct md_identity *id) {
    struct stat st; if (fstat(parent,&st)) return -errno;
    if (strchr(name,'/') || strlen(name)>=256 || !*name || !strcmp(name,".") || !strcmp(name,"..")) return -EINVAL;
    pthread_mutex_lock(&v->world->lock); unsigned file;
    struct group *base=lookup(v,&st,&file);
    int r=!base || base->removed ? -ENOENT : file!=FILES ? -ENOTDIR
        : md_file_permissions(&base->identity,W_OK|X_OK,id);
    struct group *g=NULL;
    if (!r && !(g=calloc(1,sizeof(*g)))) r=-ENOMEM;
    int created=0;
    if (!r) { g->fd=-1; g->parent=base; g->uid=id->uid.fs; g->gid=id->gid.fs; strcpy(g->name,name); }
    if (!r) { if (mkdirat(base->fd,name,0700)) r=-errno; else created=1; }
    if (!r && (g->fd=openat(base->fd,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC))<0) r=-errno;
    if (!r) r=populate(v,g);
    if (!r) { g->next=v->groups; v->groups=g; }
    else if (g) {
        if (g->fd>=0) { depopulate(g); close(g->fd); }
        if (created) unlinkat(base->fd,name,AT_REMOVEDIR);
        free(g);
    }
    pthread_mutex_unlock(&v->world->lock); return r;
}
int md_cgroup_rmdir(struct md_cgroup_view *v,int fd,const char *name,const struct md_identity *id) {
    struct stat st; if (fstatat(fd,name,&st,AT_SYMLINK_NOFOLLOW)) return -errno;
    pthread_mutex_lock(&v->world->lock); unsigned file;
    struct group *g=lookup(v,&st,&file);
    int r=!g || g->removed ? -ENOENT : file!=FILES ? -ENOTDIR : !g->parent ? -EBUSY
        : md_file_permissions(&g->parent->identity,W_OK|X_OK,id);
    for (struct group *child=v->groups; !r && child; child=child->next)
        if (!child->removed && child->parent==g) r=-EBUSY;
    for (struct md_cgroup_member *m=v->world->members; !r && m; m=m->next)
        if (m->tid && m->groups[v->devices]==g) r=-EBUSY;
    if (!r) {
        depopulate(g);
        if (unlinkat(fd,name,AT_REMOVEDIR)) r=-errno;
        else {
            g->removed=1;
            group_event(v,g,IN_DELETE_SELF);
            clear_programs(g);
            /* Open controls and captured task snapshots may still refer to
             * the logical group; they do not need its backing directory FD. */
            close(g->fd); g->fd=-1;
        }
    }
    pthread_mutex_unlock(&v->world->lock); return r;
}
static void *opened_retain(void *ctx) { struct opened *o=ctx; atomic_fetch_add(&o->refs,1); return o; }
static void opened_release(void *ctx) {
    struct opened *o=ctx;
    if (atomic_fetch_sub(&o->refs,1)==1) {
        pthread_mutex_lock(&o->view->world->lock);
        struct opened **link=&o->group->opened;
        while (*link!=o) link=&(*link)->next;
        *link=o->next;
        pthread_mutex_unlock(&o->view->world->lock);
        md_watch_source_unsubscribe(o->listener);
        md_fs_anchor_release(o->origin); md_cgroup_release(o->view); free(o);
    }
}
static int retired(const struct opened *o) {
    return o->group->removed || o->stat.st_ino!=o->group->files[o->file].st_ino || !enabled(o->group,o->file);
}
static int opened_stat(void *ctx,struct stat *st) {
    struct opened *o=ctx; struct world *w=o->view->world; pthread_mutex_lock(&w->lock);
    *st=o->stat;
    if (retired(o)) st->st_nlink=0;
    pthread_mutex_unlock(&w->lock); return 0;
}
static int below(struct group *g,struct group *parent) {
    for (;g;g=g->parent) if (g==parent) return 1;
    return 0;
}
static int subtree_write(struct md_cgroup_view *v,struct group *g,char *text) {
    unsigned next=g->subtree;
    char *cursor=NULL;
    for (char *word=strtok_r(text," \t\n",&cursor);word;word=strtok_r(NULL," \t\n",&cursor)) {
        if ((*word!='+' && *word!='-') || !word[1]) return -EINVAL;
        if (strcmp(word+1,"pids")) return -EOPNOTSUPP;
        if (*word=='+') next|=CONTROLLER_PIDS; else next&=~CONTROLLER_PIDS;
    }
    if (next&~available(g)) return -ENOENT;
    if (next==g->subtree) return 0;
    if (next) {
        if (g->parent) for (struct md_cgroup_member *m=v->world->members;m;m=m->next)
            if (m->tid && m->groups[0]==g) return -EBUSY;
        int error=0;
        struct group *failed=NULL;
        unsigned last=PIDS_MAX;
        for (struct group *c=v->groups;c && !error;c=c->next) if (!c->removed && c->parent==g) {
            for (unsigned i=PIDS_MAX;i<FILES;++i) {
                error=control_create(c,i);
                if (error) { failed=c; last=i; break; }
            }
        }
        if (error) {
            for (struct group *c=v->groups;c;c=c->next) if (!c->removed && c->parent==g) {
                for (unsigned i=PIDS_MAX;i<(c==failed ? last : FILES);++i) {
                    unlinkat(c->fd,controls[i].name,0); c->files[i]=(struct stat){0};
                }
                if (c==failed) break;
            }
            return error;
        }
    } else {
        for (struct group *c=v->groups;c;c=c->next)
            if (!c->removed && c->parent==g && c->subtree) return -EBUSY;
        for (struct group *c=v->groups;c;c=c->next) if (!c->removed && c->parent==g) {
            for (unsigned i=PIDS_MAX;i<FILES;++i) {
                if (unlinkat(c->fd,controls[i].name,0)) return -errno;
                c->files[i]=(struct stat){0};
            }
            c->pids_max=UINT64_MAX;
        }
    }
    g->subtree=next; return 0;
}
static int opened_access(void *ctx,const struct md_identity *id,unsigned mode) {
    struct opened *o=ctx; struct stat st;
    if ((mode&W_OK) && (md_fs_anchor_policy(o->origin)&MD_MOUNT_READONLY)) return -EROFS;
    int r=opened_stat(ctx,&st);
    return r ? r : md_file_permissions(&st,mode,id);
}
static long control_read(void *ctx,const struct md_control_actor *actor,void *data,size_t size,int64_t offset) {
    if (offset<0 || !actor || !actor->resources) return -EINVAL;
    struct opened *o=ctx; struct md_cgroup_view *v=o->view;
    pthread_mutex_lock(&v->world->lock);
    if (retired(o)) { pthread_mutex_unlock(&v->world->lock); return -ENODEV; }
    char *text=NULL; size_t length=0;
    FILE *stream=open_memstream(&text,&length);
    if (!stream) { pthread_mutex_unlock(&v->world->lock); return -errno; }
    int error=0;
    switch (o->file) {
    case PROCS: case THREADS: case TASKS: {
        struct md_pid_namespace *visible=md_pid_identity_namespace(actor->resources->pid);
        for (struct md_cgroup_member *m=v->world->members;m;m=m->next) {
            if (!m->tid || m->groups[v->devices]!=o->group) continue;
            if (o->file==PROCS) {
                struct md_cgroup_member *previous=v->world->members;
                while (previous!=m && !(previous->tid && previous->tgid==m->tgid
                        && previous->groups[v->devices]==o->group)) previous=previous->next;
                if (previous!=m) continue;
            }
            pid_t number=visible ? md_pid_identity_number(o->file==PROCS ? m->pid_group : m->pid,visible)
                : o->file==PROCS ? m->tgid : m->tid;
            if (number>0) fprintf(stream,"%d\n",number);
        }
        break;
    }
    case EVENTS:
        fprintf(stream,"populated %d\nfrozen 0\n",o->group->populated!=0);
        break;
    case TYPE: fputs("domain\n",stream); break;
    case CONTROLLERS: case SUBTREE:
        fputs((o->file==CONTROLLERS ? available(o->group) : o->group->subtree)&CONTROLLER_PIDS
            ? "pids\n" : "\n",stream); break;
    case RELEASE: fputc('\n',stream); break;
    case PIDS_MAX:
        if (o->group->pids_max==UINT64_MAX) fputs("max\n",stream);
        else fprintf(stream,"%" PRIu64 "\n",o->group->pids_max);
        break;
    case PIDS_CURRENT: {
        uint64_t count=0;
        for (struct md_cgroup_member *m=v->world->members;m;m=m->next)
            if (m->tid && below(m->groups[0],o->group)) ++count;
        fprintf(stream,"%" PRIu64 "\n",count); break;
    }
    case PIDS_EVENTS: fputs("max 0\n",stream); break;
    case FREEZE: case NOTIFY: fputs("0\n",stream); break;
    case LIST: fputs("a *:* rwm\n",stream); break;
    default: error=-EACCES; break;
    }
    if (ferror(stream)) error=-EIO;
    if (fclose(stream) && !error) error=-errno;
    if (!error && o->file==EVENTS && !offset && size) o->observed=o->group->generation;
    pthread_mutex_unlock(&v->world->lock);
    if (!error) {
        if ((uint64_t)offset>=length) size=0;
        else { if (size>length-(size_t)offset) size=length-(size_t)offset; memcpy(data,text+offset,size); }
    }
    free(text); return error ? error : (long)size;
}
static long control_write(void *ctx,const struct md_control_actor *actor,const void *data,size_t size,int64_t offset) {
    (void)offset;
    if (!actor || !actor->resources || !actor->identity || size>=4096) return -EINVAL;
    struct opened *o=ctx; struct md_cgroup_view *v=o->view;
    if (!actor->resources->cgroup || actor->resources->cgroup->world!=v->world) return -EXDEV;
    if (md_fs_anchor_policy(o->origin)&MD_MOUNT_READONLY) return -EROFS;
    char text[4096]; memcpy(text,data,size); text[size]=0;
    if (memchr(text,0,size)) return -EINVAL;
    size_t n=size; while (n && (text[n-1]==' ' || text[n-1]=='\n' || text[n-1]=='\t')) text[--n]=0;
    pthread_mutex_lock(&v->world->lock);
    int r=retired(o) ? -ENODEV : md_file_permissions(&o->group->files[o->file],W_OK,actor->identity);
    if (!r) switch (o->file) {
    case PROCS: case THREADS: case TASKS: {
        if (!n || strspn(text,"0123456789")!=n) { r=-EINVAL; break; }
        char *end; unsigned long value=strtoul(text,&end,10);
        if (*end || value>INT32_MAX) { r=-EINVAL; break; }
        struct md_pid_namespace *visible=md_pid_identity_namespace(actor->resources->pid);
        struct md_cgroup_member *target=NULL;
        for (struct md_cgroup_member *m=v->world->members;m;m=m->next)
            if (m->tid && (!value ? m->tid==actor->pid
                    : (visible ? md_pid_identity_number(m->pid,visible) : m->tid)==(pid_t)value
                        || (o->file==PROCS && (visible ? md_pid_identity_number(m->pid_group,visible) : m->tgid)==(pid_t)value))) {
                target=m; break;
            }
        if (!target) { r=-ESRCH; break; }
        if (!v->devices && o->group->parent && o->group->subtree) { r=-EBUSY; break; }
        for (struct md_cgroup_member *m=v->world->members;m;m=m->next)
            if (m==target || (o->file==PROCS && m->tid && m->tgid==target->tgid)) {
                if (m->tid) membership_change(v,m->groups[v->devices],o->group);
                m->groups[v->devices]=o->group;
            }
        break;
    }
    /* Resource values are retained compatibility policy, not host enforcement.
     * No fork-path accounting or Android cgroup mutation is introduced. */
    case SUBTREE: r=subtree_write(v,o->group,text); break;
    case PIDS_MAX:
        if (!strcmp(text,"max")) o->group->pids_max=UINT64_MAX;
        else if (!n || strspn(text,"0123456789")!=n) r=-EINVAL;
        else {
            errno=0; unsigned long long value=strtoull(text,NULL,10);
            if (errno || value>INT64_MAX) r=-ERANGE;
            else o->group->pids_max=value;
        }
        break;
    case TYPE: r=strcmp(text,"domain") ? -EOPNOTSUPP : 0; break;
    case FREEZE: case NOTIFY: r=strcmp(text,"0") ? -EOPNOTSUPP : 0; break;
    case RELEASE: r=n ? -EOPNOTSUPP : 0; break;
    case ALLOW: r=strcmp(text,"a") && strcmp(text,"a *:* rwm") ? -EOPNOTSUPP : 0; break;
    case DENY: r=-EOPNOTSUPP; break;
    default: r=-EACCES; break;
    }
    pthread_mutex_unlock(&v->world->lock); return r ? r : (long)size;
}
static int events_poll_descriptor(void *ctx,int *descriptor) {
    struct opened *o=ctx; struct md_cgroup_view *v=o->view;
    pthread_mutex_lock(&v->world->lock);
    int r=0;
    if (!o->listener) {
        if (!v->events) r=md_watch_source_new(&v->events);
        if (!r) r=md_watch_source_subscribe(v->events,&o->listener);
        struct md_watch_interest *interest; uint64_t sequence;
        if (!r) r=md_watch_listener_admit(o->listener,o->group->event_id,
            IN_MODIFY|IN_DELETE_SELF,&interest,&sequence);
        if (r) { md_watch_source_unsubscribe(o->listener); o->listener=NULL; }
    }
    *descriptor=r ? -1 : md_watch_listener_descriptor(o->listener);
    pthread_mutex_unlock(&v->world->lock); return r;
}
static long events_poll(void *ctx) {
    struct opened *o=ctx;
    pthread_mutex_lock(&o->view->world->lock);
    struct md_watch_event event;
    if (o->listener) while (md_watch_listener_next(o->listener,&event)) {}
    long result=POLLIN|POLLRDNORM;
    if (o->observed!=o->group->generation) result|=POLLPRI|POLLERR;
    if (retired(o)) result|=POLLHUP|POLLERR;
    pthread_mutex_unlock(&o->view->world->lock); return result;
}
int md_cgroup_watch(struct md_cgroup_view *v,struct md_inode_store *store,
        int instance,int object,unsigned flags) {
    struct stat st; if (fstat(object,&st)) return -errno;
    pthread_mutex_lock(&v->world->lock); unsigned file;
    struct group *g=lookup(v,&st,&file);
    int r=!g || g->removed ? -ENOENT : file!=EVENTS ? -EOPNOTSUPP : 0;
    if (!r && !v->events) r=md_watch_source_new(&v->events);
    if (!r) r=md_inode_watch_add_provider(store,instance,v->events,g->event_id,S_IFREG,flags);
    pthread_mutex_unlock(&v->world->lock); return r;
}
static struct md_fs_anchor *opened_origin(void *ctx) { return ((struct opened *)ctx)->origin; }
static const struct md_control_file_ops ops[3]={
    {.retain=opened_retain,.release=opened_release,.stat=opened_stat,.read=control_read,
        .write=control_write,.filesystem=CGROUP2_SUPER_MAGIC,.access=opened_access,.origin=opened_origin},
    {.retain=opened_retain,.release=opened_release,.stat=opened_stat,.read=control_read,
        .write=control_write,.filesystem=CGROUP_SUPER_MAGIC,.access=opened_access,.origin=opened_origin},
    {.retain=opened_retain,.release=opened_release,.stat=opened_stat,.read=control_read,
        .filesystem=CGROUP2_SUPER_MAGIC,.access=opened_access,.origin=opened_origin,
        .poll_descriptor=events_poll_descriptor,.poll=events_poll}
};
int md_cgroup_open(struct md_cgroup_view *v,int fd,int flags,const struct md_identity *id,struct md_fs_anchor *origin,
        const struct md_control_file_ops **out,void **context) {
    *out=NULL; *context=NULL;
    struct stat st; if (fstat(fd,&st)) return -errno;
    pthread_mutex_lock(&v->world->lock); unsigned file;
    struct group *g=lookup(v,&st,&file);
    int r=!g || g->removed ? -ENOENT : 0;
    if (!r && file==FILES) {
        if (!(flags&O_PATH) && (flags&O_ACCMODE)!=O_RDONLY) r=-EISDIR;
        else if (!(flags&O_PATH)) r=md_file_permissions(&g->identity,R_OK,id);
    } else if (!r) {
        int access=flags&O_ACCMODE;
        if (flags&O_DIRECTORY) r=-ENOTDIR;
        else if (!(flags&O_PATH) && ((access!=O_RDONLY && !(controls[file].mode&0200))
                || (access!=O_WRONLY && !(controls[file].mode&0444)))) r=-EACCES;
        if (!r && !(flags&O_PATH)) r=md_file_permissions(&g->files[file],
            (access!=O_WRONLY ? R_OK : 0)|(access!=O_RDONLY ? W_OK : 0),id);
        if (!r) {
            struct opened *o=calloc(1,sizeof(*o));
            if (!o) r=-ENOMEM;
            else {
                atomic_init(&o->refs,1); o->view=md_cgroup_retain(v); o->group=g; o->file=file;
                o->stat=g->files[file]; o->observed=g->generation;
                o->next=g->opened; g->opened=o;
                o->origin=md_fs_anchor_retain(origin); *out=&ops[file==EVENTS ? 2 : v->devices]; *context=o;
            }
        }
    }
    pthread_mutex_unlock(&v->world->lock); return r;
}
static int group_path(struct group *g,struct group *root,char *text,size_t size) {
    struct group *common=root;
    size_t up=0;
    while (common && !below(g,common)) { common=common->parent; ++up; }
    size_t length=up*3;
    if (length>=size) return -ENAMETOOLONG;
    for (struct group *at=g;at && at!=common;at=at->parent) {
        if (!at->parent) break;
        size_t n=strlen(at->name)+1;
        if (n>=size || length>=size-n) return -ENAMETOOLONG;
        length+=n;
    }
    if (!length) { if (size<2) return -ENAMETOOLONG; memcpy(text,"/",2); return 1; }
    text[length]=0; size_t at=length;
    for (;g && g->parent && g!=common;g=g->parent) {
        size_t n=strlen(g->name); at-=n; memcpy(text+at,g->name,n); text[--at]='/';
    }
    for (size_t i=0;i<up;++i) memcpy(text+i*3,"/..",3);
    return (int)length;
}
long md_cgroup_member_text(struct md_cgroup_member *m,const struct md_cgroup_namespace *ns,char *text,size_t capacity) {
    if (!m) return -ESRCH;
    if (!ns || ns->world!=m->world) return -EXDEV;
    if (!capacity || !text) return -EINVAL;
    pthread_mutex_lock(&m->world->lock); size_t length=0; int r=0;
    for (unsigned i=0;i<2 && !r;++i) {
        if (i && !m->world->views[i]) continue;
        struct group *root=ns->roots[i] ? ns->roots[i] : m->world->views[i] ? m->world->views[i]->root : NULL;
        struct group *group=i && m->departed ? m->world->views[i]->root : m->groups[i];
        char path[4096]; r=group_path(group,root,path,sizeof(path));
        if (r<0) break;
        int n=snprintf(text+length,capacity-length,"%s%s%s\n",i ? "1:devices:" : "0::",path,
            !i && group && group->removed ? " (deleted)" : "");
        r=n<0 || (size_t)n>=capacity-length ? -ERANGE : 0;
        if (!r) length+=(size_t)n;
    }
    pthread_mutex_unlock(&m->world->lock); return r ? r : (long)length;
}
long md_cgroup_controllers_text(struct md_cgroup_member *m,char *text,size_t capacity) {
    if (!m) return -ESRCH;
    pthread_mutex_lock(&m->world->lock);
    struct md_cgroup_view *v=m->world->views[1]; unsigned count=0;
    for (struct group *g=v ? v->groups : NULL;g;g=g->next) if (!g->removed) ++count;
    unsigned unified=0;
    for (struct group *g=m->world->views[0] ? m->world->views[0]->groups : NULL;g;g=g->next)
        if (!g->removed) ++unified;
    int n=snprintf(text,capacity,"#subsys_name\thierarchy\tnum_cgroups\tenabled\ndevices\t%u\t%u\t1\npids\t0\t%u\t1\n",
        v ? 1 : 0,count ? count : 1,unified ? unified : 1);
    pthread_mutex_unlock(&m->world->lock);
    return n<0 ? -EIO : (size_t)n>=capacity ? -ERANGE : n;
}

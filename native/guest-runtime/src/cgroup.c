#define _GNU_SOURCE
#include "cgroup.h"
#include "task_resources.h"
#include "temporary_directory.h"
#include "file_permissions.h"
#include "mount_policy.h"
#include "namespace_identity.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { PROCS, THREADS, EVENTS, CONTROLLERS, SUBTREE, TYPE, FREEZE,
    ALLOW, DENY, LIST, TASKS, NOTIFY, RELEASE, FILES };
struct control { const char *name; mode_t mode; unsigned views; };
static const struct control controls[FILES]={
    [PROCS]={"cgroup.procs",0644,3}, [THREADS]={"cgroup.threads",0644,1},
    [EVENTS]={"cgroup.events",0444,1}, [CONTROLLERS]={"cgroup.controllers",0444,1},
    [SUBTREE]={"cgroup.subtree_control",0644,1}, [TYPE]={"cgroup.type",0644,1},
    [FREEZE]={"cgroup.freeze",0644,1}, [ALLOW]={"devices.allow",0200,2},
    [DENY]={"devices.deny",0200,2}, [LIST]={"devices.list",0444,2},
    [TASKS]={"tasks",0644,2}, [NOTIFY]={"notify_on_release",0644,2},
    [RELEASE]={"release_agent",0644,2}
};
struct group {
    struct group *next,*parent;
    int fd,removed;
    struct stat identity,files[FILES];
    uid_t uid; gid_t gid;
    char name[256];
};
struct world {
    atomic_uint refs;
    pthread_mutex_t lock;
    struct md_cgroup_member *members;
    struct md_cgroup_view *views[2];
};
struct md_cgroup_view {
    struct world *world;
    int devices,storage;
    struct group *groups,*root;
};
struct md_cgroup_member {
    atomic_uint refs;
    struct md_cgroup_member *next;
    struct world *world;
    struct group *groups[2];
    pid_t tid,tgid;
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
    struct group *group;
    unsigned file;
    struct md_fs_anchor *origin;
};
static struct world *retain(struct world *w) { atomic_fetch_add(&w->refs,1); return w; }
static void release(struct world *w) {
    if (atomic_fetch_sub(&w->refs,1)!=1) return;
    for (unsigned i=0;i<2;++i) if (w->views[i]) {
        struct md_cgroup_view *v=w->views[i];
        while (v->groups) { struct group *g=v->groups; v->groups=g->next; if (g->fd>=0) close(g->fd); free(g); }
        md_temporary_directory_release(v->storage); free(v);
    }
    pthread_mutex_destroy(&w->lock); free(w);
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
    m->tid=tid; m->tgid=tgid; m->pid=md_pid_identity_retain(pid);
    m->pid_group=md_pid_identity_retain(group);
    pthread_mutex_unlock(&m->world->lock); md_pid_identity_release(old); md_pid_identity_release(old_group);
}
void md_cgroup_member_depart(struct md_cgroup_member *m,pid_t tid) {
    if (!m) return;
    pthread_mutex_lock(&m->world->lock);
    if (m->tid==tid) m->tid=0;
    pthread_mutex_unlock(&m->world->lock);
}
static int populate(struct md_cgroup_view *v,struct group *g) {
    for (unsigned i=0;i<FILES;++i) if (controls[i].views&(1U<<v->devices)) {
        if (i==RELEASE && g->parent) continue;
        int fd=openat(g->fd,controls[i].name,O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600);
        if (fd<0) return -errno;
        int error=fstat(fd,&g->files[i]) ? -errno : 0; close(fd); if (error) return error;
    }
    return fstat(g->fd,&g->identity) ? -errno : 0;
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
        for (struct md_cgroup_member *m=w->members;m;m=m->next) m->groups[devices]=g;
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
        st->st_mode=file==FILES ? S_IFDIR|0755 : S_IFREG|controls[file].mode;
        st->st_uid=g->uid; st->st_gid=g->gid; st->st_size=0; st->st_blocks=0;
    }
    pthread_mutex_unlock(&v->world->lock); return g ? 0 : -ENOENT;
}
static int capable(const struct md_identity *id,struct group *g) {
    return id->uid.fs==g->uid || md_identity_file_capable(id,g->uid,g->gid,CAP_DAC_OVERRIDE);
}
int md_cgroup_mkdir(struct md_cgroup_view *v,int parent,const char *name,const struct md_identity *id) {
    struct stat st; if (fstat(parent,&st)) return -errno;
    if (strchr(name,'/') || strlen(name)>=256 || !*name || !strcmp(name,".") || !strcmp(name,"..")) return -EINVAL;
    pthread_mutex_lock(&v->world->lock); unsigned file;
    struct group *base=lookup(v,&st,&file);
    int r=!base || base->removed ? -ENOENT : file!=FILES ? -ENOTDIR : !capable(id,base) ? -EACCES : 0;
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
    int r=!g || g->removed ? -ENOENT : file!=FILES ? -ENOTDIR : !g->parent ? -EBUSY : !capable(id,g->parent) ? -EACCES : 0;
    for (struct group *child=v->groups; !r && child; child=child->next)
        if (!child->removed && child->parent==g) r=-EBUSY;
    for (struct md_cgroup_member *m=v->world->members; !r && m; m=m->next)
        if (m->tid && m->groups[v->devices]==g) r=-EBUSY;
    if (!r) {
        depopulate(g);
        if (unlinkat(fd,name,AT_REMOVEDIR)) r=-errno;
        else {
            g->removed=1;
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
        md_fs_anchor_release(o->origin); md_cgroup_release(o->view); free(o);
    }
}
static int opened_stat(void *ctx,struct stat *st) {
    struct opened *o=ctx; struct world *w=o->view->world; pthread_mutex_lock(&w->lock);
    *st=o->group->files[o->file]; st->st_mode=S_IFREG|controls[o->file].mode;
    st->st_uid=o->group->uid; st->st_gid=o->group->gid; st->st_size=0; st->st_blocks=0;
    if (o->group->removed) st->st_nlink=0;
    pthread_mutex_unlock(&w->lock); return 0;
}
static int below(struct group *g,struct group *parent) {
    for (;g;g=g->parent) if (g==parent) return 1;
    return 0;
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
    if (o->group->removed) { pthread_mutex_unlock(&v->world->lock); return -ENODEV; }
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
    case EVENTS: {
        int populated=0;
        for (struct md_cgroup_member *m=v->world->members;m;m=m->next)
            if (m->tid && below(m->groups[v->devices],o->group)) { populated=1; break; }
        fprintf(stream,"populated %d\nfrozen 0\n",populated); break;
    }
    case TYPE: fputs("domain\n",stream); break;
    case CONTROLLERS: case SUBTREE: case RELEASE: fputc('\n',stream); break;
    case FREEZE: case NOTIFY: fputs("0\n",stream); break;
    case LIST: fputs("a *:* rwm\n",stream); break;
    default: error=-EACCES; break;
    }
    if (ferror(stream)) error=-EIO;
    if (fclose(stream) && !error) error=-errno;
    pthread_mutex_unlock(&v->world->lock);
    if (!error) {
        if ((uint64_t)offset>=length) size=0;
        else { if (size>length-(size_t)offset) size=length-(size_t)offset; memcpy(data,text+offset,size); }
    }
    free(text); return error ? error : (long)size;
}
static long control_write(void *ctx,const struct md_control_actor *actor,const void *data,size_t size) {
    if (!actor || !actor->resources || !actor->identity || size>=4096) return -EINVAL;
    struct opened *o=ctx; struct md_cgroup_view *v=o->view;
    if (!actor->resources->cgroup || actor->resources->cgroup->world!=v->world) return -EXDEV;
    if (md_fs_anchor_policy(o->origin)&MD_MOUNT_READONLY) return -EROFS;
    char text[4096]; memcpy(text,data,size); text[size]=0;
    if (memchr(text,0,size)) return -EINVAL;
    size_t n=size; while (n && (text[n-1]==' ' || text[n-1]=='\n' || text[n-1]=='\t')) text[--n]=0;
    pthread_mutex_lock(&v->world->lock);
    int r=o->group->removed ? -ENODEV : !capable(actor->identity,o->group) ? -EACCES : 0;
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
        for (struct md_cgroup_member *m=v->world->members;m;m=m->next)
            if (m==target || (o->file==PROCS && m->tgid==target->tgid)) m->groups[v->devices]=o->group;
        break;
    }
    /* No controllers are advertised. Never acknowledge an enforced limit,
     * freeze or release-agent execution that this backend cannot provide. */
    case SUBTREE: r=n ? -EOPNOTSUPP : 0; break;
    case TYPE: r=strcmp(text,"domain") ? -EOPNOTSUPP : 0; break;
    case FREEZE: case NOTIFY: r=strcmp(text,"0") ? -EOPNOTSUPP : 0; break;
    case RELEASE: r=n ? -EOPNOTSUPP : 0; break;
    case ALLOW: r=strcmp(text,"a") && strcmp(text,"a *:* rwm") ? -EOPNOTSUPP : 0; break;
    case DENY: r=-EOPNOTSUPP; break;
    default: r=-EACCES; break;
    }
    pthread_mutex_unlock(&v->world->lock); return r ? r : (long)size;
}
static const struct md_control_file_ops ops[2]={
    {.retain=opened_retain,.release=opened_release,.stat=opened_stat,.read=control_read,
        .write=control_write,.filesystem=CGROUP2_SUPER_MAGIC,.access=opened_access},
    {.retain=opened_retain,.release=opened_release,.stat=opened_stat,.read=control_read,
        .write=control_write,.filesystem=CGROUP_SUPER_MAGIC,.access=opened_access}
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
    } else if (!r) {
        int access=flags&O_ACCMODE;
        if (flags&O_DIRECTORY) r=-ENOTDIR;
        else if (!(flags&O_PATH) && ((access!=O_RDONLY && !(controls[file].mode&0200))
                || (access!=O_WRONLY && !(controls[file].mode&0444))
                || (access!=O_RDONLY && !capable(id,g)))) r=-EACCES;
        if (!r) {
            struct opened *o=calloc(1,sizeof(*o));
            if (!o) r=-ENOMEM;
            else {
                atomic_init(&o->refs,1); o->view=md_cgroup_retain(v); o->group=g; o->file=file;
                o->origin=md_fs_anchor_retain(origin); *out=&ops[v->devices]; *context=o;
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
        char path[4096]; r=group_path(m->groups[i],root,path,sizeof(path));
        if (r<0) break;
        int n=snprintf(text+length,capacity-length,"%s%s\n",i ? "1:devices:" : "0::",path);
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
    int n=snprintf(text,capacity,"#subsys_name\thierarchy\tnum_cgroups\tenabled\ndevices\t%u\t%u\t1\n",v ? 1 : 0,count ? count : 1);
    pthread_mutex_unlock(&m->world->lock);
    return n<0 ? -EIO : (size_t)n>=capacity ? -ERANGE : n;
}

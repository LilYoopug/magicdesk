#define _GNU_SOURCE
#include "binfmt.h"
#include "provider_tree.h"
#include "fs_engine.h"
#include "fs_continuation.h"
#include "file_permissions.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct md_binfmt_entry {
    atomic_uint refs;
    struct md_binfmt_entry *next;
    struct md_binfmt_rule rule;
    struct md_program program;
    struct stat stat;
    int enabled, removed;
};
struct view {
    atomic_uint refs;
    pthread_mutex_t lock;
    struct md_user_namespace *owner;
    struct md_binfmt_entry *entries;
    struct stat status, registration;
    int root, enabled;
};
struct registry_mount {
    struct registry_mount *next;
    struct view *view;
    struct md_provider_tree *provider;
};
struct md_binfmt_registry { struct registry_mount *mounts; };
struct opened {
    atomic_uint refs;
    struct view *view;
    struct md_binfmt_entry *entry;
    struct md_fs_anchor *origin;
    int registration;
};
struct change {
    struct opened *file;
    struct md_binfmt_entry *entry;
    size_t size;
    int command;
};
static struct md_binfmt_entry *entry_retain(struct md_binfmt_entry *e) {
    if (e) atomic_fetch_add_explicit(&e->refs,1,memory_order_relaxed);
    return e;
}
void md_binfmt_entry_release(struct md_binfmt_entry *e) {
    if (!e || atomic_fetch_sub_explicit(&e->refs,1,memory_order_acq_rel)!=1) return;
    if (e->program.fd>=0) close(e->program.fd);
    md_fs_anchor_release(e->program.origin); free(e);
}
const struct md_binfmt_rule *md_binfmt_entry_rule(const struct md_binfmt_entry *e) { return &e->rule; }
const struct md_program *md_binfmt_entry_program(const struct md_binfmt_entry *e) {
    return e->program.fd>=0 ? &e->program : NULL;
}
static void *view_retain(void *data) {
    struct view *v=data;
    atomic_fetch_add_explicit(&v->refs,1,memory_order_relaxed); return v;
}
static void view_release(void *data) {
    struct view *v=data;
    if (atomic_fetch_sub_explicit(&v->refs,1,memory_order_acq_rel)!=1) return;
    while (v->entries) {
        struct md_binfmt_entry *e=v->entries; v->entries=e->next; md_binfmt_entry_release(e);
    }
    if (v->root>=0) close(v->root);
    md_user_namespace_release(v->owner); pthread_mutex_destroy(&v->lock); free(v);
}
struct md_binfmt_registry *md_binfmt_registry_new(void) { return calloc(1,sizeof(struct md_binfmt_registry)); }
void md_binfmt_registry_destroy(struct md_binfmt_registry *r) {
    if (!r) return;
    while (r->mounts) {
        struct registry_mount *m=r->mounts; r->mounts=m->next;
        md_provider_tree_release(m->provider); free(m);
    }
    free(r);
}
struct md_binfmt_entry *md_binfmt_match(struct md_binfmt_registry *r,const struct md_user_namespace *ns,
        const char *path,const void *header,size_t size) {
    if (!r || !r->mounts) return NULL;
    for (;;) {
        for (struct registry_mount *m=r->mounts;m;m=m->next) {
            struct view *v=m->view;
            if (!md_user_namespace_same(v->owner,ns)) continue;
            struct md_binfmt_entry *result=NULL;
            pthread_mutex_lock(&v->lock);
            if (v->enabled) for (struct md_binfmt_entry *e=v->entries;e;e=e->next) {
                if (e->enabled && md_binfmt_rule_matches(&e->rule,path,header,size)) {
                    result=entry_retain(e); break;
                }
            }
            pthread_mutex_unlock(&v->lock); return result;
        }
        if (!ns) return NULL;
        ns=md_user_namespace_parent(ns);
    }
}
static void *opened_retain(void *data) {
    struct opened *f=data; atomic_fetch_add_explicit(&f->refs,1,memory_order_relaxed); return f;
}
static void opened_release(void *data) {
    struct opened *f=data;
    if (atomic_fetch_sub_explicit(&f->refs,1,memory_order_acq_rel)!=1) return;
    md_fs_anchor_release(f->origin); md_binfmt_entry_release(f->entry); view_release(f->view); free(f);
}
static int opened_stat(void *data,struct stat *st) {
    struct opened *f=data;
    *st=f->entry ? f->entry->stat : f->registration ? f->view->registration : f->view->status;
    return 0;
}
static int opened_access(void *data,const struct md_identity *id,unsigned mode) {
    struct stat st; opened_stat(data,&st); return md_file_permissions(&st,mode,id);
}
static void *opened_at(void *data,struct md_fs_anchor *origin) {
    struct opened *f=data,*copy=malloc(sizeof(*copy));
    if (!copy) return NULL;
    *copy=*f; atomic_init(&copy->refs,1);
    copy->view=view_retain(f->view); copy->entry=entry_retain(f->entry);
    copy->origin=md_fs_anchor_retain(origin); return copy;
}
static struct md_fs_anchor *opened_origin(void *data) { return ((struct opened *)data)->origin; }
static long read_file(struct opened *f,void *data,size_t size,int64_t offset) {
    if (f->registration) return -EINVAL;
    if (offset<0) return -EINVAL;
    char text[MD_BINFMT_REGISTER_MAX+MD_BINFMT_HEADER*4+128];
    pthread_mutex_lock(&f->view->lock);
    int n=f->entry ? (f->entry->removed ? -ENOENT : md_binfmt_rule_format(&f->entry->rule,f->entry->enabled,text,sizeof(text)))
        : snprintf(text,sizeof(text),"%s\n",f->view->enabled ? "enabled" : "disabled");
    pthread_mutex_unlock(&f->view->lock);
    if (n<0) return n;
    if ((uint64_t)offset>=(unsigned)n) return 0;
    if (size>(size_t)n-(size_t)offset) size=(size_t)n-(size_t)offset;
    memcpy(data,text+offset,size); return (long)size;
}
static int create_node(struct view *v,const char *name,mode_t mode,struct stat *st) {
    int fd=openat(v->root,name,O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600);
    if (fd<0) return -errno;
    int error=fstat(fd,st) ? -errno : 0; close(fd);
    if (error) { unlinkat(v->root,name,0); return error; }
    st->st_mode=S_IFREG|mode; st->st_size=0; st->st_blocks=0;
    st->st_uid=md_user_namespace_into(v->owner,0,0);
    st->st_gid=md_user_namespace_into(v->owner,1,0);
    return 0;
}
static void change_destroy(void *data) {
    struct change *c=data; md_binfmt_entry_release(c->entry); opened_release(c->file); free(c);
}
static long change_run(void *data,struct md_fs_context *context,struct md_fs_continuation **pending) {
    struct change *c=data;
    struct opened *f=c->file;
    struct view *v=f->view;
    if (md_fs_anchor_policy(f->origin)&MD_MOUNT_READONLY) return -EROFS;
    if (!md_identity_capable_in(&context->task.identity,v->owner,CAP_SYS_ADMIN)) return -EPERM;
    if (c->entry && (c->entry->rule.flags&MD_BINFMT_FIXED) && c->entry->program.fd<0) {
        struct md_program *p=&c->entry->program;
        const char *path=c->entry->rule.interpreter;
        struct md_fs_anchor *cwd=context->task.cwd;
        struct md_fs_request q={.actor=context->actor,.operation=MD_FS_OPEN_IMAGE,
            .directory={*path=='/' ? -1 : md_fs_anchor_fd(cwd),-1},
            .origin={*path=='/' ? NULL : cwd,NULL},.path={path,NULL}};
        struct md_fs_result result;
        struct md_fs_output output={.data=&p->identity,.capacity=sizeof(p->identity),.origin=&p->origin,.continuation=pending};
        struct md_fs_continuation *previous=*pending;
        if (previous) md_fs_context_resume(context,previous,&result,&output);
        else md_fs_context_execute(context,&q,&result,&output);
        md_fs_continuation_pending(previous,pending,&result);
        if (result.error) return result.error;
        if (result.host_path || result.open_completion.kind || result.fd<0) {
            if (result.fd>=0) close(result.fd);
            return -EOPNOTSUPP;
        }
        p->fd=result.fd; p->mount_flags=md_fs_anchor_policy(p->origin);
        struct stat st;
        if (fstat(p->fd,&st)) return -errno;
        if (!S_ISREG(st.st_mode) || (p->mount_flags&MD_MOUNT_NOEXEC)) return -EACCES;
    }
    pthread_mutex_lock(&v->lock);
    long result=(long)c->size;
    if (c->entry) {
        int error=create_node(v,c->entry->rule.name,0644,&c->entry->stat);
        if (error) result=error;
        else { c->entry->next=v->entries; v->entries=c->entry; c->entry=NULL; }
    } else if (f->entry && f->entry->removed) result=-ENOENT;
    else if (c->command>=0) {
        if (f->entry) f->entry->enabled=c->command; else v->enabled=c->command;
    } else {
        struct md_binfmt_entry **link=&v->entries;
        while (*link) {
            struct md_binfmt_entry *e=*link;
            if (f->entry && e!=f->entry) { link=&e->next; continue; }
            if (unlinkat(v->root,e->rule.name,0)) { result=-errno; break; }
            *link=e->next; e->removed=1; md_binfmt_entry_release(e);
            if (f->entry) break;
        }
    }
    pthread_mutex_unlock(&v->lock); return result;
}
static long opened_io(void *data,const struct md_control_actor *actor,unsigned operation,void *bytes,
        size_t size,int64_t offset,struct md_control_pending **pending) {
    struct opened *f=data;
    if (operation==MD_CONTROL_READ) return read_file(f,bytes,size,offset);
    if (operation!=MD_CONTROL_WRITE) return -EINVAL;
    if (!actor || !actor->submit) return -EOPNOTSUPP;
    if (size>MD_BINFMT_REGISTER_MAX || !size) return -EINVAL;
    struct change *c=calloc(1,sizeof(*c));
    if (!c) return -ENOMEM;
    c->file=opened_retain(f); c->size=size;
    int error=0;
    if (f->registration) {
        c->entry=calloc(1,sizeof(*c->entry));
        if (!c->entry) error=-ENOMEM;
        else {
            atomic_init(&c->entry->refs,1); c->entry->enabled=1; c->entry->program.fd=-1;
            error=md_binfmt_rule_parse(bytes,size,&c->entry->rule);
        }
    } else {
        size_t n=size;
        if (((char *)bytes)[n-1]=='\n') --n;
        c->command=n==1 && !memcmp(bytes,"0",1) ? 0 : n==1 && !memcmp(bytes,"1",1) ? 1
            : n==2 && !memcmp(bytes,"-1",2) ? -1 : -2;
        if (c->command==-2) error=-EINVAL;
    }
    if (!error) {
        struct md_control_fs_operation op={.run=change_run,.destroy=change_destroy,.context=c};
        long result=actor->submit(actor->filesystem,actor,op,pending);
        if (result==-EINPROGRESS) return result;
        error=(int)result;
    }
    change_destroy(c); return error;
}
static const struct md_control_file_ops file_ops={.retain=opened_retain,.release=opened_release,
    .stat=opened_stat,.access=opened_access,.io=opened_io,.at=opened_at,.origin=opened_origin,
    .filesystem=BINFMTFS_MAGIC};
static int control(void *data,int fd,struct md_control_file *out) {
    struct view *v=data;
    struct stat st;
    if (fstat(fd,&st)) return -errno;
    if (!S_ISREG(st.st_mode)) return 0;
    struct opened *f=calloc(1,sizeof(*f));
    if (!f) return -ENOMEM;
    atomic_init(&f->refs,1); f->view=view_retain(v);
    pthread_mutex_lock(&v->lock);
    if (st.st_dev==v->registration.st_dev && st.st_ino==v->registration.st_ino) f->registration=1;
    else if (st.st_dev!=v->status.st_dev || st.st_ino!=v->status.st_ino) {
        for (struct md_binfmt_entry *e=v->entries;e;e=e->next)
            if (st.st_dev==e->stat.st_dev && st.st_ino==e->stat.st_ino) { f->entry=entry_retain(e); break; }
        if (!f->entry) { pthread_mutex_unlock(&v->lock); opened_release(f); return -ENOENT; }
    }
    pthread_mutex_unlock(&v->lock);
    *out=(struct md_control_file){.ops=&file_ops,.context=f}; return 1;
}
static const struct md_provider_tree_ops tree_ops={.retain=view_retain,.release=view_release,
    .control=control,.filesystem=BINFMTFS_MAGIC,.readonly=1};
int md_binfmt_mount(struct md_binfmt_registry *r,int parent,const struct md_identity *id,struct md_provider_tree **out) {
    if (!r || !id) return -EINVAL;
    if (!md_identity_capable_in(id,id->user_namespace,CAP_SYS_ADMIN)) return -EPERM;
    for (struct registry_mount *m=r->mounts;m;m=m->next)
        if (md_user_namespace_same(m->view->owner,id->user_namespace)) { *out=md_provider_tree_retain(m->provider); return 0; }
    struct registry_mount *m=calloc(1,sizeof(*m));
    struct view *v=calloc(1,sizeof(*v));
    if (!m || !v) { free(m); free(v); return -ENOMEM; }
    int error=pthread_mutex_init(&v->lock,NULL);
    if (error) { free(m); free(v); return -error; }
    atomic_init(&v->refs,1); v->root=-1; v->enabled=1;
    v->owner=md_user_namespace_retain(id->user_namespace);
    m->provider=md_provider_tree_new(parent,-1,NULL,0,&tree_ops,v);
    if (!m->provider) error=-errno;
    else {
        v->root=fcntl(md_provider_tree_root(m->provider),F_DUPFD_CLOEXEC,3);
        if (v->root<0) error=-errno;
        else if (!(error=create_node(v,"status",0644,&v->status))) error=create_node(v,"register",0200,&v->registration);
    }
    if (!error) {
        md_provider_tree_set_owner(m->provider,id->user_namespace);
        m->view=v; m->next=r->mounts; r->mounts=m;
        *out=md_provider_tree_retain(m->provider);
    } else { md_provider_tree_release(m->provider); free(m); }
    view_release(v); return error;
}

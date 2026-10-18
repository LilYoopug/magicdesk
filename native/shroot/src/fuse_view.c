#define _GNU_SOURCE
#include "fuse_view_internal.h"
#include "fuse_device.h"
#include "fuse_xattr.h"
#include "fuse_image.h"
#include "image_identity.h"
#include "fs_mount_internal.h"
#include "fs_continuation.h"
#include "fs_control.h"
#include "inode_internal.h"
#include "file_permissions.h"
#include "temporary_directory.h"
#include "resource_order.h"
#include "linux_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <unistd.h>

static const struct md_provider_tree_ops view_ops;
int md_fuse_view_matches(struct md_provider_tree *p) { return md_provider_tree_matches(p,&view_ops); }
dev_t md_fuse_view_device(struct md_provider_tree *tree) {
    struct fuse_view *v=md_provider_tree_context(tree,&view_ops);
    return v ? v->device : 0;
}
int md_fuse_view_options(struct md_provider_tree *tree,const struct md_identity *id,char *out,size_t size) {
    struct fuse_view *v=md_provider_tree_context(tree,&view_ops);
    if (!v) return -EINVAL;
    const struct md_fuse_options *p=md_fuse_session_options(v->session);
    int n=snprintf(out,size,",user_id=%u,group_id=%u,max_read=%u%s%s",
        id ? md_identity_visible_id(id,0,p->uid) : p->uid,
        id ? md_identity_visible_id(id,1,p->gid) : p->gid,p->max_read,
        p->default_permissions ? ",default_permissions" : "",p->allow_other ? ",allow_other" : "");
    return n<0 || (size_t)n>=size ? -ENAMETOOLONG : 0;
}
void *md_fuse_view_retain(void *context) {
    struct fuse_view *v=context;
    atomic_fetch_add_explicit(&v->references,1,memory_order_relaxed); return v;
}
void md_fuse_view_release(void *context) {
    struct fuse_view *v=context;
    if (atomic_fetch_sub_explicit(&v->references,1,memory_order_acq_rel)!=1) return;
    if (v->notifications) {
        md_fuse_connection_notifications(v->notifications,NULL,NULL);
        md_fuse_connection_release(v->notifications);
    }
    for (unsigned i=0;i<NODE_BUCKETS;++i) while (v->by_id[i]) {
        struct fuse_node *n=v->by_id[i]; v->by_id[i]=n->id_next; free(n);
    }
    while (v->names) { struct fuse_name *n=v->names; v->names=n->next; free(n); }
    md_fuse_session_release(v->session);
    md_user_namespace_release(v->user_namespace); md_pid_namespace_release(v->pid_namespace);
    if (v->root>=0) md_temporary_directory_release(v->root);
    pthread_mutex_destroy(&v->lock); free(v);
}
static unsigned bucket(uint64_t n) { return (unsigned)(n^(n>>32))%NODE_BUCKETS; }
static struct fuse_node *node_fd(struct fuse_view *v,int fd) {
    struct stat st;
    if (fstat(fd,&st)) return NULL;
    for (struct fuse_node *n=v->by_fd[bucket(st.st_ino)];n;n=n->fd_next)
        if (n->carrier.st_ino==st.st_ino && n->carrier.st_dev==st.st_dev) return n;
    return NULL;
}
static struct fuse_node *node_id(struct fuse_view *v,uint64_t id,uint64_t generation) {
    for (struct fuse_node *n=v->by_id[bucket(id)];n;n=n->id_next)
        if (n->id==id && n->generation==generation) return n;
    return NULL;
}
static int view_notification(void *context,unsigned code,const void *data,size_t size) {
    struct fuse_view *v=context;
    uint64_t parent=0,child=0; unsigned length=0; const char *name=NULL;
    if (code==FUSE_NOTIFY_INVAL_INODE) {
        struct fuse_notify_inval_inode_out in;
        if (size!=sizeof(in)) return -EINVAL;
        memcpy(&in,data,sizeof(in));
        /* Ordinary IO always queries the daemon. Private mapping snapshots
         * may be reused only until this node's next invalidation. */
        pthread_mutex_lock(&v->lock);
        struct fuse_node *n=v->by_id[bucket(in.ino)];
        while (n && n->id!=in.ino) n=n->id_next;
        if (n) ++n->changes;
        pthread_mutex_unlock(&v->lock); return n ? 0 : -ENOENT;
    }
    if (code==FUSE_NOTIFY_INVAL_ENTRY) {
        struct fuse_notify_inval_entry_out in;
        if (size<sizeof(in)) return -EINVAL;
        memcpy(&in,data,sizeof(in)); parent=in.parent; length=in.namelen;
        name=(const char *)data+sizeof(in); size-=sizeof(in);
    } else if (code==FUSE_NOTIFY_DELETE) {
        struct fuse_notify_delete_out in;
        if (size<sizeof(in)) return -EINVAL;
        memcpy(&in,data,sizeof(in)); parent=in.parent; child=in.child; length=in.namelen;
        name=(const char *)data+sizeof(in); size-=sizeof(in);
    } else return -EOPNOTSUPP;
    if (!length || length>NAME_MAX || size!=(size_t)length+1 || name[length]
            || memchr(name,0,length) || memchr(name,'/',length)) return -EINVAL;
    pthread_mutex_lock(&v->lock);
    struct fuse_node *n=v->by_id[bucket(parent)];
    while (n && n->id!=parent) n=n->id_next;
    int error=!n ? -ENOENT : !S_ISDIR(n->type) ? -ENOTDIR : 0;
    if (!error) {
        struct fuse_name **at=&v->names;
        while (*at) {
            struct fuse_name *d=*at;
            if (d->parent==n && !strcmp(d->name,name) && (!child || d->node->id==child)) {
                *at=d->next; free(d); break;
            }
            at=&d->next;
        }
    }
    pthread_mutex_unlock(&v->lock); return error;
}
int md_fuse_view_attributes(struct fuse_view *v,const struct fuse_attr *a,struct stat *st) {
    mode_t type=a->mode&S_IFMT;
    if ((type!=S_IFREG && type!=S_IFDIR && type!=S_IFLNK) || a->size>INT64_MAX
            || a->atime>INT64_MAX || a->mtime>INT64_MAX || a->ctime>INT64_MAX
            || a->atimensec>=1000000000 || a->mtimensec>=1000000000 || a->ctimensec>=1000000000)
        return -EPROTO;
    uint32_t uid=md_user_namespace_into(v->user_namespace,0,a->uid);
    uint32_t gid=md_user_namespace_into(v->user_namespace,1,a->gid);
    if (uid==UINT32_MAX || gid==UINT32_MAX) return -EOVERFLOW;
    *st=(struct stat){.st_dev=v->device,.st_ino=a->ino,.st_mode=a->mode,.st_nlink=a->nlink,.st_uid=uid,.st_gid=gid,
        .st_size=a->size,.st_blocks=a->blocks,.st_blksize=a->blksize,.st_rdev=a->rdev,
        .st_atim={a->atime,a->atimensec},.st_mtim={a->mtime,a->mtimensec},.st_ctim={a->ctime,a->ctimensec}};
    return 0;
}
static void node_insert(struct fuse_view *v,struct fuse_node *n) {
    unsigned key=bucket(n->id); n->id_next=v->by_id[key]; v->by_id[key]=n;
    key=bucket(n->carrier.st_ino); n->fd_next=v->by_fd[key]; v->by_fd[key]=n; ++v->count;
}
int md_fuse_node_open(struct fuse_view *v,struct fuse_node *n,int flags) {
    int fd=openat(v->root,n->carrier_name,flags|O_CLOEXEC|O_NOFOLLOW);
    return fd<0 ? -errno : fd;
}
static int node_publish(struct fuse_view *v,struct fuse_node *parent,const char *name,
        const struct fuse_entry_out *entry,const char *link,struct fuse_node **out) {
    struct stat st;
    int error=md_fuse_view_attributes(v,&entry->attr,&st);
    if (error) return error;
    if (!entry->nodeid || entry->nodeid==FUSE_ROOT_ID) return -EIO;
    pthread_mutex_lock(&v->lock);
    struct fuse_node *n=node_id(v,entry->nodeid,entry->generation);
    if (n && n->type!=(st.st_mode&S_IFMT)) error=-EIO;
    if (!error && !n && v->count>=NODE_LIMIT) error=-ENOSPC;
    struct fuse_name *d=NULL;
    for (d=v->names;d;d=d->next) if (d->parent==parent && !strcmp(d->name,name)) break;
    int fresh_name=!d;
    if (!error && !d) {
        d=calloc(1,sizeof(*d)+strlen(name)+1);
        if (!d) error=-ENOMEM; else { d->parent=parent; strcpy(d->name,name); }
    }
    if (!error && !n) {
        n=calloc(1,sizeof(*n));
        if (!n) error=-ENOMEM;
        else {
            snprintf(n->carrier_name,sizeof(n->carrier_name),"node-%u",v->count);
            const char *carrier=n->carrier_name;
            n->id=entry->nodeid; n->generation=entry->generation; n->type=st.st_mode&S_IFMT;
            if (S_ISDIR(st.st_mode)) error=mkdirat(v->root,carrier,0700) ? -errno : 0;
            else if (S_ISLNK(st.st_mode)) error=!link ? -EINVAL : symlinkat(link,v->root,carrier) ? -errno : 0;
            else {
                int fd=openat(v->root,carrier,O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600);
                if (fd<0) error=-errno; else close(fd);
            }
            if (!error && fstatat(v->root,carrier,&n->carrier,AT_SYMLINK_NOFOLLOW)) error=-errno;
            if (error) {
                unlinkat(v->root,carrier,S_ISDIR(st.st_mode) ? AT_REMOVEDIR : 0); free(n); n=NULL;
            } else node_insert(v,n);
        }
    }
    if (!error && n->lookups==UINT64_MAX) error=-EOVERFLOW;
    if (!error) {
        ++n->lookups; n->attributes=st; d->node=n;
        if (fresh_name) { d->next=v->names; v->names=d; }
        *out=n;
    } else if (fresh_name) free(d);
    pthread_mutex_unlock(&v->lock); return error;
}
static int view_path(void *context,int fd,char *out,size_t capacity) {
    struct fuse_view *v=context;
    char path[PATH_MAX]; size_t at=sizeof(path)-1; path[at]=0;
    pthread_mutex_lock(&v->lock);
    struct fuse_node *n=node_fd(v,fd); int error=n ? 0 : -ESTALE;
    for (unsigned depth=0;!error && n!=v->root_node;++depth) {
        if (depth==PATH_MAX/2) { error=-ELOOP; break; }
        struct fuse_name *d=v->names;
        while (d && d->node!=n) d=d->next;
        if (!d) { error=-ENOENT; break; }
        size_t length=strlen(d->name);
        if (length+1>at) { error=-ENAMETOOLONG; break; }
        at-=length; memcpy(path+at,d->name,length); path[--at]='/'; n=d->parent;
    }
    if (!error) {
        if (at==sizeof(path)-1) path[--at]='/';
        size_t length=sizeof(path)-at;
        if (length>capacity) error=-ERANGE; else memcpy(out,path+at,length);
    }
    pthread_mutex_unlock(&v->lock); return error;
}
static int view_readonly(void *context,int fd) {
    struct fuse_view *v=context; pthread_mutex_lock(&v->lock);
    int result=node_fd(v,fd) ? 0 : -ESTALE;
    pthread_mutex_unlock(&v->lock); return result;
}
uint32_t md_fuse_view_pid(struct fuse_view *v,pid_t native) {
    if (!v->pid_namespace) return native;
    struct md_pid_identity *id=md_pid_namespace_find(v->pid_namespace,native);
    pid_t number=id ? md_pid_identity_number(id,v->pid_namespace) : 0;
    md_pid_identity_release(id); return number>0 ? (uint32_t)number : 0;
}
struct view_lookup {
    struct md_provider_lookup base;
    struct fuse_view *view;
    struct fuse_node *parent,*selected;
    struct md_identity identity;
    struct md_resource_wakeup *wakeup;
    struct md_fuse_request *request;
    struct fuse_entry_out entry;
    uint32_t pid;
    unsigned stage;
    int error,delivered;
    char name[NAME_MAX+1];
};
static void forget_node(struct fuse_view *v,const struct md_identity *id,uint32_t pid,
        uint64_t node,struct md_resource_wakeup *wakeup) {
    if (!node) return;
    struct fuse_forget_in in={.nlookup=1}; struct md_fuse_request *request=NULL;
    int error=md_fuse_session_request(v->session,id,pid,FUSE_FORGET,
        node,&in,sizeof(in),0,1,wakeup,&request);
    if (!error) md_fuse_request_release(request);
    /* A full queue must not silently lose a daemon's lookup reference. */
    else if (error==-EAGAIN) md_fuse_session_abort(v->session,error);
}
static void lookup_destroy(struct md_provider_lookup *);
static void lookup_abandoned(void *context,int error,const void *data,size_t size) {
    struct view_lookup *p=context;
    if (!error && size==sizeof(p->entry)) memcpy(&p->entry,data,size);
    p->stage=0; lookup_destroy(&p->base);
}
static void lookup_destroy(struct md_provider_lookup *base) {
    struct view_lookup *p=(void *)base;
    if (p->request && p->stage==1 && !p->entry.nodeid) {
        md_fuse_request_abandon(p->request,lookup_abandoned,p); return;
    }
    if (!p->delivered) forget_node(p->view,&p->identity,p->pid,p->entry.nodeid,p->wakeup);
    md_fuse_request_cancel(p->request); md_fuse_request_release(p->request);
    md_identity_release(&p->identity); md_resource_wakeup_release(p->wakeup); md_fuse_view_release(p->view); free(p);
}
static int lookup_ready(struct md_provider_lookup *base) {
    struct view_lookup *p=(void *)base;
    return p->error ? 1 : p->request ? md_fuse_request_ready(p->request) : md_fuse_session_ready(p->view->session);
}
static int lookup_complete(struct md_provider_lookup *base) {
    struct view_lookup *p=(void *)base;
    if (p->error) return p->error;
    struct fuse_view *v=p->view;
    if (p->stage==4) {
        struct fuse_attr_out response;
        long n=md_fuse_request_result(p->request,&response,sizeof(response));
        if (n<0) return n;
        struct stat st;
        int error=n!=sizeof(response) ? -EPROTO : md_fuse_view_attributes(v,&response.attr,&st);
        if (!error && !S_ISDIR(st.st_mode)) error=-ENOTDIR;
        if (!error) error=md_file_permissions(&st,X_OK,&p->identity);
        if (error) return error;
        pthread_mutex_lock(&v->lock);
        p->parent->attributes=st; pthread_mutex_unlock(&v->lock);
        md_fuse_request_release(p->request); p->request=NULL; p->stage=5;
    }
    if (p->stage==5 && p->selected) {
        return md_fuse_node_open(v,p->selected,O_PATH);
    }
    if (!p->stage || p->stage==5) {
        int ready=md_fuse_session_ready(v->session);
        if (ready<=0) return ready ? ready : -EINPROGRESS;
        if (!p->stage && md_fuse_session_options(v->session)->default_permissions) {
            struct fuse_getattr_in in={0};
            p->error=md_fuse_session_request(v->session,&p->identity,p->pid,FUSE_GETATTR,p->parent->id,
                &in,sizeof(in),sizeof(struct fuse_attr_out),0,p->wakeup,&p->request);
            if (p->error) return p->error;
            p->stage=4; return -EINPROGRESS;
        }
        if (p->selected) {
            return md_fuse_node_open(v,p->selected,O_PATH);
        }
        p->error=md_fuse_session_request(v->session,&p->identity,p->pid,FUSE_LOOKUP,p->parent->id,
            p->name,strlen(p->name)+1,sizeof(p->entry),0,p->wakeup,&p->request);
        if (p->error) return p->error;
        p->stage=1; return -EINPROGRESS;
    }
    char link[PATH_MAX];
    if (p->stage==1) {
        long n=md_fuse_request_result(p->request,&p->entry,sizeof(p->entry));
        if (n<0) return n;
        if (n!=sizeof(p->entry)) return -EPROTO;
        if (!p->entry.nodeid) return -ENOENT;
        md_fuse_request_release(p->request); p->request=NULL;
        if (S_ISLNK(p->entry.attr.mode)) {
            int error=md_fuse_session_request(v->session,&p->identity,p->pid,FUSE_READLINK,p->entry.nodeid,
                NULL,0,sizeof(link)-1,0,p->wakeup,&p->request);
            if (error) return error;
            p->stage=2; return -EINPROGRESS;
        }
        p->stage=3;
    }
    if (p->stage==2) {
        long n=md_fuse_request_result(p->request,link,sizeof(link)-1);
        if (n<0) return n;
        if (!n || memchr(link,0,n)) return -EPROTO;
        link[n]=0;
    }
    struct fuse_node *node=NULL;
    int error=node_publish(v,p->parent,p->name,&p->entry,p->stage==2 ? link : NULL,&node);
    if (!error) {
        p->delivered=1;
        return md_fuse_node_open(v,node,O_PATH);
    }
    return error;
}
static int view_lookup(void *context,int directory,const char *name,const struct md_control_actor *actor,
        struct md_provider_lookup **out) {
    struct fuse_view *v=context;
    if (!actor || !actor->identity) return -EACCES;
    int admission=md_fuse_session_access(v->session,actor->identity);
    if (admission) return admission;
    if (!*name || strchr(name,'/') || strlen(name)>NAME_MAX) return -EINVAL;
    pthread_mutex_lock(&v->lock);
    struct fuse_node *parent=node_fd(v,directory),*selected=NULL;
    if (parent && !strcmp(name,".")) selected=parent;
    if (parent && !strcmp(name,"..")) {
        if (parent==v->root_node) selected=parent;
        else for (struct fuse_name *d=v->names;d;d=d->next) if (d->node==parent) { selected=d->parent; break; }
    }
    int error=!parent ? -ESTALE : !S_ISDIR(parent->type) ? -ENOTDIR : 0;
    pthread_mutex_unlock(&v->lock);
    if (error) return error;
    struct view_lookup *p=calloc(1,sizeof(*p)); if (!p) return -ENOMEM;
    p->base=(struct md_provider_lookup){lookup_ready,lookup_complete,lookup_destroy};
    p->view=md_fuse_view_retain(v); p->parent=parent; p->selected=selected; p->identity=md_identity_copy(actor->identity);
    p->wakeup=md_resource_wakeup_retain(actor->wakeup); p->pid=md_fuse_view_pid(v,actor->pid); strcpy(p->name,name);
    int result=lookup_complete(&p->base);
    if (result==-EINPROGRESS) *out=&p->base; else lookup_destroy(&p->base);
    return result;
}
static const struct md_provider_tree_ops view_ops={.retain=md_fuse_view_retain,.release=md_fuse_view_release,
    .lookup=view_lookup,.path=view_path,.readonly_node=view_readonly,.filesystem=FUSE_SUPER_MAGIC};

int md_fuse_view_source(struct md_filesystem *fs,const struct md_fs_request *q,struct md_mount_source *out) {
    if (q->flags&~MD_FS_MOUNT_FLAGS) return -EOPNOTSUPP;
    struct md_fuse_connection *connection=md_fuse_device_connection(q->control);
    if (!connection) return -EINVAL;
    struct md_fuse_options options;
    int error=md_fuse_options_parse(q->value_size ? q->value : NULL,&options);
    if (error) return error;
    struct fuse_view *v=calloc(1,sizeof(*v)); if (!v) return -ENOMEM;
    error=pthread_mutex_init(&v->lock,NULL); if (error) { free(v); return -error; }
    atomic_init(&v->references,1); v->root=-1;
    /* A superblock has its own public device identity. Carriers only locate
     * private nodes; bind mounts retain this identity across namespaces. */
    unsigned device;
    error=md_mount_id_allocate(&device);
    if (error) { md_fuse_view_release(v); return error; }
    v->device=makedev(0xfffbU,device);
    v->user_namespace=md_user_namespace_retain(fs->store->identity->user_namespace);
    v->pid_namespace=md_pid_namespace_retain(fs->actor ? md_pid_identity_namespace(fs->actor->pid) : NULL);
    int parent=md_fs_private_mounts_parent(fs->store);
    struct md_provider_tree *tree=NULL;
    if (parent<0) error=parent;
    else { tree=md_provider_tree_new(parent,-1,NULL,0,&view_ops,v); close(parent); if (!tree) error=-errno; }
    if (!error) { v->root=fcntl(md_provider_tree_root(tree),F_DUPFD_CLOEXEC,3); if (v->root<0) error=-errno; }
    if (!error) {
        struct fuse_node *root=calloc(1,sizeof(*root));
        if (!root) error=-ENOMEM;
        else {
            root->id=FUSE_ROOT_ID; root->type=options.rootmode&S_IFMT; strcpy(root->carrier_name,".");
            if (fstat(v->root,&root->carrier)) {
                error=-errno; free(root);
            } else {
                root->attributes=root->carrier; root->attributes.st_dev=v->device;
                root->attributes.st_ino=FUSE_ROOT_ID; root->attributes.st_mode=options.rootmode;
                root->attributes.st_uid=md_user_namespace_into(v->user_namespace,0,options.uid);
                root->attributes.st_gid=md_user_namespace_into(v->user_namespace,1,options.gid);
                node_insert(v,root); v->root_node=root;
            }
        }
    }
    int fd=!error ? openat(v->root,".",O_PATH|O_DIRECTORY|O_CLOEXEC) : -1;
    if (!error && fd<0) error=-errno;
    if (!error) error=md_fuse_session_new(connection,&options,fs->store->identity,
        md_fuse_view_pid(v,q->actor),fs->wakeup,&v->session);
    if (!error) {
        v->notifications=md_fuse_connection_retain(connection);
        md_fuse_connection_notifications(connection,view_notification,v);
        *out=(struct md_mount_source){.fd=fd,.backing=MD_MOUNT_PROVIDER,.provider=tree,
            .policy=md_fs_mount_flags(q->flags)|MD_MOUNT_NOSUID|MD_MOUNT_NODEV};
    } else { if (fd>=0) close(fd); md_provider_tree_release(tree); }
    md_fuse_view_release(v); return error;
}

struct view_operation {
    struct md_fs_continuation base;
    struct fuse_view *view;
    struct fuse_node *node,*parent,*destination,*replaced;
    struct md_fs_anchor *origin;
    struct md_fuse_request *request;
    struct md_fuse_image *image;
    struct fuse_attr attributes;
    uint64_t image_handle;
    int executable,image_opened,access_checked;
    struct md_identity identity;
    unsigned opcode;
    unsigned open_flags;
    int metadata_checked,truncated,mutation,checking,entry_registered;
    unsigned checked;
    char name[NAME_MAX+1],target[NAME_MAX+1];
    struct fuse_name *renamed;
};
static int opening(const struct view_operation *p) {
    return p->base.request.operation==MD_FS_OPEN || p->base.request.operation==MD_FS_REOPEN
        || p->base.request.operation==MD_FS_CREATE || p->base.request.operation==MD_FS_OPEN_IMAGE;
}
static int publish_file(struct view_operation *p,struct md_fs_result *out,const struct md_fs_output *output,
        const struct fuse_open_out *opened) {
    if (p->open_flags&O_PATH) {
        int fd=md_fuse_node_open(p->view,p->node,p->open_flags&(O_PATH|O_DIRECTORY));
        if (fd<0) return fd;
        out->fd=fd;
        if (output->origin) *output->origin=md_fs_anchor_retain(p->origin);
        return 0;
    }
    p->opcode=0; /* The file owner takes the remote handle, including failure. */
    return md_fuse_file_publish(p->view,p->node,p->origin,&p->identity,p->open_flags,opened,out,output);
}
static int operation_ready(struct md_fs_continuation *base) {
    struct view_operation *p=(void *)base;
    if (p->image) return md_fuse_image_ready(p->image);
    return p->request ? md_fuse_request_ready(p->request) : md_fuse_session_ready(p->view->session);
}
static void operation_destroy(struct md_fs_continuation *);
static void operation_abandoned(void *context,int error,const void *data,size_t size) {
    struct view_operation *p=context;
    if (!error) {
        if ((p->opcode==FUSE_OPEN || p->opcode==FUSE_OPENDIR) && size==sizeof(struct fuse_open_out)) {
            struct fuse_open_out open; memcpy(&open,data,sizeof(open));
            md_fuse_file_release_handle(p->view,p->node,&p->identity,open.fh,p->open_flags);
        } else if (size==sizeof(struct fuse_entry_out)+(p->opcode==FUSE_CREATE ? sizeof(struct fuse_open_out) : 0)) {
            struct fuse_entry_out entry; memcpy(&entry,data,sizeof(entry));
            if (p->opcode==FUSE_CREATE) {
                struct fuse_open_out open; memcpy(&open,(const char *)data+sizeof(entry),sizeof(open));
                md_fuse_file_release_remote(p->view,entry.nodeid,0,&p->identity,open.fh,p->open_flags);
            }
            if (!p->entry_registered) forget_node(p->view,&p->identity,0,entry.nodeid,NULL);
        }
    }
    p->opcode=0; operation_destroy(&p->base);
}
static void operation_destroy(struct md_fs_continuation *base) {
    struct view_operation *p=(void *)base;
    if (p->request && (p->opcode==FUSE_OPEN || p->opcode==FUSE_OPENDIR || p->opcode==FUSE_CREATE
            || p->opcode==FUSE_MKDIR || p->opcode==FUSE_SYMLINK || p->opcode==FUSE_MKNOD || p->opcode==FUSE_LINK)) {
        md_fuse_request_abandon(p->request,operation_abandoned,p); return;
    }
    md_fuse_request_cancel(p->request); md_fuse_request_release(p->request);
    md_fuse_image_destroy(p->image);
    if (p->image_opened) md_fuse_file_release_handle(p->view,p->node,&p->identity,p->image_handle,O_RDONLY);
    md_fs_anchor_release(p->origin); md_identity_release(&p->identity);
    free(p->renamed); md_fuse_view_release(p->view); md_fs_continuation_clear(base); free(p);
}
static void name_remove(struct fuse_view *v,struct fuse_node *parent,const char *name) {
    struct fuse_name **at=&v->names;
    while (*at) {
        struct fuse_name *d=*at;
        if (d->parent==parent && !strcmp(d->name,name)) { *at=d->next; free(d); return; }
        at=&d->next;
    }
}
static int sticky(const struct stat *directory,const struct stat *node,const struct md_identity *id) {
    return !(directory->st_mode&S_ISVTX) || id->uid.fs==directory->st_uid || id->uid.fs==node->st_uid
        || md_identity_file_capable(id,node->st_uid,node->st_gid,CAP_FOWNER) ? 0 : -EPERM;
}
static int mutation_permission(struct view_operation *p) {
    const struct md_fs_request *q=&p->base.request;
    const struct md_identity *id=&p->identity;
    struct stat st={0},parent={0},destination={0},replaced={0};
    pthread_mutex_lock(&p->view->lock);
    if (p->node) st=p->node->attributes;
    if (p->parent) parent=p->parent->attributes;
    if (p->destination) destination=p->destination->attributes;
    if (p->replaced) replaced=p->replaced->attributes;
    pthread_mutex_unlock(&p->view->lock);
    int error=0;
    switch (q->operation) {
    case MD_FS_OPEN: case MD_FS_CREATE: case MD_FS_MKDIR: case MD_FS_MKNOD: case MD_FS_SYMLINK:
    case MD_FS_UNLINK: case MD_FS_RENAME:
        error=md_file_permissions(&parent,W_OK|X_OK,id);
        if (!error && (q->operation==MD_FS_UNLINK || q->operation==MD_FS_RENAME)) error=sticky(&parent,&st,id);
        if (error || q->operation!=MD_FS_RENAME) break;
        /* Both directory authorities are checked before a single rename. */
        __attribute__((fallthrough));
    case MD_FS_LINK:
        error=md_file_permissions(&destination,W_OK|X_OK,id);
        if (!error && p->replaced) error=sticky(&destination,&replaced,id);
        break;
    case MD_FS_CHMOD:
        error=md_file_noatime(&st,id); break;
    case MD_FS_CHOWN: {
        uint32_t uid=q->attributes.uid==UINT32_MAX ? st.st_uid : q->attributes.uid;
        uint32_t gid=q->attributes.gid==UINT32_MAX ? st.st_gid : q->attributes.gid;
        if (!md_identity_file_capable(id,st.st_uid,st.st_gid,CAP_CHOWN)
                && (id->uid.fs!=st.st_uid || uid!=st.st_uid
                    || (gid!=st.st_gid && !md_identity_in_group(id,gid)))) error=-EPERM;
        break;
    }
    case MD_FS_UTIMENS:
        if (q->attributes.nanos[0]==UTIME_OMIT && q->attributes.nanos[1]==UTIME_OMIT) break;
        error=md_file_noatime(&st,id);
        if (error && q->attributes.nanos[0]==UTIME_NOW && q->attributes.nanos[1]==UTIME_NOW)
            error=md_file_permissions(&st,W_OK,id);
        break;
    }
    return error;
}
static struct fuse_node *check_node(struct view_operation *p,unsigned slot) {
    return slot==0 ? p->parent : slot==1 ? p->destination : slot==2 ? p->node : p->replaced;
}
static int mutation_submit(struct view_operation *p,struct md_filesystem *fs) {
    const struct md_fs_request *q=&p->base.request;
    unsigned char bytes[PATH_MAX+NAME_MAX+1+sizeof(struct fuse_setattr_in)];
    void *input=bytes; size_t size=0,capacity=0;
    uint64_t node=p->node ? p->node->id : p->parent->id;
    unsigned mode=q->mode&07777U,mask=q->attributes.creation_mask&0777U;
    switch (q->operation) {
    case MD_FS_CREATE: case MD_FS_OPEN: {
        struct fuse_create_in in={.flags=p->open_flags&~(O_CLOEXEC|O_NOCTTY),.mode=S_IFREG|(mode&~mask),.umask=mask};
        memcpy(bytes,&in,sizeof(in)); size=sizeof(in); p->opcode=FUSE_CREATE;
        capacity=sizeof(struct fuse_entry_out)+sizeof(struct fuse_open_out); node=p->parent->id; break;
    }
    case MD_FS_MKDIR: {
        struct fuse_mkdir_in in={.mode=S_IFDIR|(mode&~mask),.umask=mask};
        memcpy(bytes,&in,sizeof(in)); size=sizeof(in); p->opcode=FUSE_MKDIR;
        capacity=sizeof(struct fuse_entry_out); node=p->parent->id; break;
    }
    case MD_FS_MKNOD: {
        struct fuse_mknod_in in={.mode=q->mode&~mask,.rdev=q->offset,.umask=mask};
        memcpy(bytes,&in,sizeof(in)); size=sizeof(in); p->opcode=FUSE_MKNOD;
        capacity=sizeof(struct fuse_entry_out); node=p->parent->id; break;
    }
    case MD_FS_SYMLINK:
        p->opcode=FUSE_SYMLINK; node=p->parent->id; capacity=sizeof(struct fuse_entry_out); break;
    case MD_FS_UNLINK:
        p->opcode=q->flags&AT_REMOVEDIR ? FUSE_RMDIR : FUSE_UNLINK; node=p->parent->id; break;
    case MD_FS_LINK: {
        struct fuse_link_in in={.oldnodeid=p->node->id};
        memcpy(bytes,&in,sizeof(in)); size=sizeof(in); p->opcode=FUSE_LINK;
        capacity=sizeof(struct fuse_entry_out); node=p->destination->id; break;
    }
    case MD_FS_RENAME:
        if (q->flags) {
            if (md_fuse_session_minor(p->view->session)<23) return -EINVAL;
            struct fuse_rename2_in in={.newdir=p->destination->id,.flags=q->flags};
            memcpy(bytes,&in,sizeof(in)); size=sizeof(in); p->opcode=FUSE_RENAME2;
        } else {
            struct fuse_rename_in in={.newdir=p->destination->id};
            memcpy(bytes,&in,sizeof(in)); size=sizeof(in); p->opcode=FUSE_RENAME;
        }
        node=p->parent->id; break;
    case MD_FS_CHMOD: case MD_FS_CHOWN: case MD_FS_UTIMENS: {
        struct fuse_setattr_in in={0};
        if (q->operation==MD_FS_CHMOD) { in.valid=FATTR_MODE; in.mode=p->node->type|mode; }
        else if (q->operation==MD_FS_CHOWN) {
            if (q->attributes.uid!=UINT32_MAX) {
                in.valid|=FATTR_UID; in.uid=md_user_namespace_from(p->view->user_namespace,0,q->attributes.uid);
                if (in.uid==UINT32_MAX) return -EINVAL;
            }
            if (q->attributes.gid!=UINT32_MAX) {
                in.valid|=FATTR_GID; in.gid=md_user_namespace_from(p->view->user_namespace,1,q->attributes.gid);
                if (in.gid==UINT32_MAX) return -EINVAL;
            }
        } else {
            for (unsigned i=0;i<2;++i) {
                int64_t ns=q->attributes.nanos[i];
                if (ns==UTIME_OMIT) continue;
                in.valid|=i ? FATTR_MTIME : FATTR_ATIME;
                if (ns==UTIME_NOW) in.valid|=i ? FATTR_MTIME_NOW : FATTR_ATIME_NOW;
                else if (ns<0 || ns>=1000000000) return -EINVAL;
                else if (i) { in.mtime=q->attributes.seconds[i]; in.mtimensec=ns; }
                else { in.atime=q->attributes.seconds[i]; in.atimensec=ns; }
            }
        }
        memcpy(bytes,&in,sizeof(in)); size=sizeof(in); p->opcode=FUSE_SETATTR; capacity=sizeof(struct fuse_attr_out); break;
    }
    default: return -EOPNOTSUPP;
    }
    if (p->opcode!=FUSE_SETATTR) {
        const char *name=q->operation==MD_FS_LINK ? p->target : p->name;
        size_t n=strlen(name)+1; memcpy(bytes+size,name,n); size+=n;
        if (q->operation==MD_FS_RENAME || q->operation==MD_FS_SYMLINK) {
            name=q->operation==MD_FS_RENAME ? p->target : q->path[1];
            n=strlen(name)+1; if (n>sizeof(bytes)-size) return -ENAMETOOLONG;
            memcpy(bytes+size,name,n); size+=n;
        }
    }
    return md_fuse_session_request(p->view->session,&p->identity,md_fuse_view_pid(p->view,q->actor),
        p->opcode,node,input,size,capacity,0,fs->wakeup,&p->request);
}
static void mutation_resume(struct view_operation *p,struct md_filesystem *fs,
        struct md_fs_result *out,const struct md_fs_output *output) {
    const struct md_fs_request *q=&p->base.request;
    struct fuse_view *v=p->view;
    if (p->request && p->checking) {
        struct fuse_attr_out result;
        long n=md_fuse_request_result(p->request,&result,sizeof(result));
        if (n==-EINPROGRESS) goto pending;
        if (n<0) { out->error=n; return; }
        struct fuse_node *node=check_node(p,p->checking-1); struct stat st;
        out->error=n!=sizeof(result) ? -EPROTO : md_fuse_view_attributes(v,&result.attr,&st);
        if (out->error) return;
        if ((st.st_mode&S_IFMT)!=node->type) { out->error=-EIO; return; }
        pthread_mutex_lock(&v->lock); node->attributes=st; pthread_mutex_unlock(&v->lock);
        p->checked|=1U<<(p->checking-1); p->checking=0;
        md_fuse_request_release(p->request); p->request=NULL;
    }
    if (!p->request) {
        int ready=md_fuse_session_ready(v->session);
        if (ready<0) { out->error=ready; return; }
        if (!ready) goto pending;
        if (md_fuse_session_options(v->session)->default_permissions) {
            for (unsigned i=0;i<4;++i) if (!(p->checked&(1U<<i)) && check_node(p,i)) {
                struct fuse_getattr_in in={0};
                out->error=md_fuse_session_request(v->session,&p->identity,md_fuse_view_pid(v,q->actor),
                    FUSE_GETATTR,check_node(p,i)->id,&in,sizeof(in),sizeof(struct fuse_attr_out),0,fs->wakeup,&p->request);
                if (out->error) return;
                p->checking=i+1; goto pending;
            }
            out->error=mutation_permission(p); if (out->error) return;
        }
        out->error=mutation_submit(p,fs);
        if (!out->error) goto pending;
        return;
    }
    struct { struct fuse_entry_out entry; struct fuse_open_out opened; } result;
    long n=md_fuse_request_result(p->request,&result,sizeof(result));
    if (n==-EINPROGRESS) goto pending;
    if (n<0) { out->error=n; return; }
    unsigned opcode=p->opcode;
    if (opcode==FUSE_SETATTR) {
        struct fuse_attr_out attr; struct stat st;
        n=md_fuse_request_result(p->request,&attr,sizeof(attr));
        out->error=n!=sizeof(attr) ? -EPROTO : md_fuse_view_attributes(v,&attr.attr,&st);
        if (!out->error && (st.st_mode&S_IFMT)!=p->node->type) out->error=-EIO;
        if (!out->error) { pthread_mutex_lock(&v->lock);
            p->node->attributes=st; ++p->node->changes; pthread_mutex_unlock(&v->lock); }
    } else if (opcode==FUSE_CREATE || opcode==FUSE_MKDIR || opcode==FUSE_MKNOD || opcode==FUSE_SYMLINK || opcode==FUSE_LINK) {
        if (n!=(long)(sizeof(result.entry)+(opcode==FUSE_CREATE ? sizeof(result.opened) : 0))) { out->error=-EPROTO; return; }
        out->error=node_publish(v,opcode==FUSE_LINK ? p->destination : p->parent,
            opcode==FUSE_LINK ? p->target : p->name,&result.entry,opcode==FUSE_SYMLINK ? q->path[1] : NULL,&p->node);
        if (!out->error) { p->entry_registered=1; if (opcode!=FUSE_CREATE) p->opcode=0; }
        if (!out->error && opcode==FUSE_CREATE) {
            struct md_fs_anchor *origin=NULL;
            int fd=md_fuse_node_open(v,p->node,O_PATH);
            out->error=fd<0 ? fd : md_view_anchor_duplicate(fs,p->origin->view,p->origin->mount,fd,&origin);
            if (fd>=0) close(fd);
            if (!out->error) { md_fs_anchor_release(p->origin); p->origin=origin;
                out->error=publish_file(p,out,output,&result.opened); }
        }
    } else if (n) out->error=-EPROTO;
    else {
        pthread_mutex_lock(&v->lock);
        if (opcode==FUSE_UNLINK || opcode==FUSE_RMDIR) name_remove(v,p->parent,p->name);
        else if (opcode==FUSE_RENAME || opcode==FUSE_RENAME2) {
            if (!(p->node==p->replaced && !(q->flags&RENAME_EXCHANGE))) {
                if (q->flags&RENAME_EXCHANGE) {
                    for (struct fuse_name *d=v->names;d;d=d->next)
                        if (d->parent==p->parent && !strcmp(d->name,p->name)) d->node=p->replaced;
                } else name_remove(v,p->parent,p->name);
                name_remove(v,p->destination,p->target);
                p->renamed->next=v->names; v->names=p->renamed; p->renamed=NULL;
            }
        }
        pthread_mutex_unlock(&v->lock);
    }
    return;
pending:
    out->error=-EINPROGRESS; *output->continuation=&p->base;
}
static void operation_resume(struct md_fs_continuation *base,struct md_filesystem *fs,
        struct md_fs_result *out,const struct md_fs_output *output) {
    struct view_operation *p=(void *)base;
    const struct md_fs_request *q=&base->request;
    *out=(struct md_fs_result){.fd=-1};
    if (p->mutation) { mutation_resume(p,fs,out,output); return; }
    if (p->image) {
        int fd=md_fuse_image_advance(p->image,fs->wakeup);
        if (fd<0) {
            out->error=fd;
            if (fd==-EINPROGRESS) *output->continuation=base;
            return;
        }
        if (q->operation==MD_FS_OPEN_IMAGE) {
            if (!output->data || output->capacity<sizeof(struct md_image_identity)) out->error=-ERANGE;
            else {
                struct md_image_identity *identity=output->data;
                memset(identity,0,sizeof(*identity));
                out->error=md_view_path(fs,md_fs_anchor_fd(p->origin),p->origin->mount,identity->path,sizeof(identity->path));
            }
        }
        if (out->error) close(fd);
        else { out->fd=fd; if (output->origin) *output->origin=md_fs_anchor_retain(p->origin); }
        return;
    }
    if (!p->request) {
        int ready=md_fuse_session_ready(p->view->session);
        if (ready<0) { out->error=ready; return; }
        if (ready) {
            if (q->operation==MD_FS_XATTR_OBJECT && p->metadata_checked) {
                struct stat st;
                pthread_mutex_lock(&p->view->lock); st=p->node->attributes; pthread_mutex_unlock(&p->view->lock);
                out->error=md_fuse_xattr_request(p->view->session,&p->identity,md_fuse_view_pid(p->view,q->actor),
                    p->node->id,&st,q,fs->wakeup,&p->request);
                if (!out->error) { out->error=-EINPROGRESS; *output->continuation=base; }
                return;
            }
            size_t size=0,capacity=0; void *input=NULL;
            struct fuse_getattr_in getattr={0}; struct fuse_access_in access={.mask=q->mode};
            struct fuse_open_in open={.flags=p->open_flags&~(O_CREAT|O_EXCL|O_TRUNC|O_CLOEXEC)};
            int atomic_truncate=md_fuse_session_atomic_truncate(p->view->session);
            if (atomic_truncate) open.flags|=p->open_flags&O_TRUNC;
            struct fuse_setattr_in truncate={.valid=FATTR_SIZE,.size=0};
            p->opcode=q->operation==MD_FS_READLINK ? FUSE_READLINK : q->operation==MD_FS_STATFS ? FUSE_STATFS
                : q->operation==MD_FS_ACCESS && !md_fuse_session_options(p->view->session)->default_permissions
                ? FUSE_ACCESS : FUSE_GETATTR;
            if (opening(p) && p->metadata_checked) {
                if (p->open_flags&O_PATH) { out->error=publish_file(p,out,output,NULL); return; }
                p->opcode=p->executable && !p->access_checked ? FUSE_ACCESS
                    : (p->open_flags&O_TRUNC) && !p->truncated && !atomic_truncate ? FUSE_SETATTR
                    : S_ISDIR(p->node->type) ? FUSE_OPENDIR : FUSE_OPEN;
                if (p->executable) access.mask=X_OK;
            }
            if (p->opcode==FUSE_GETATTR) { input=&getattr; size=sizeof(getattr); capacity=sizeof(struct fuse_attr_out); }
            if (p->opcode==FUSE_ACCESS) { input=&access; size=sizeof(access); }
            if (p->opcode==FUSE_STATFS) capacity=sizeof(struct fuse_statfs_out);
            if (p->opcode==FUSE_READLINK) capacity=PATH_MAX-1;
            if (p->opcode==FUSE_OPEN || p->opcode==FUSE_OPENDIR) { input=&open; size=sizeof(open); capacity=sizeof(struct fuse_open_out); }
            if (p->opcode==FUSE_SETATTR) { input=&truncate; size=sizeof(truncate); capacity=sizeof(struct fuse_attr_out); }
            struct md_identity identity=md_identity_access(fs->store->identity,
                q->operation!=MD_FS_ACCESS || !!(q->flags&MD_AT_EACCESS));
            out->error=md_fuse_session_request(p->view->session,&identity,md_fuse_view_pid(p->view,q->actor),
                p->opcode,p->node->id,input,size,capacity,0,fs->wakeup,&p->request);
            if (out->error) return;
        }
        out->error=-EINPROGRESS; *output->continuation=base; return;
    }
    if (q->operation==MD_FS_XATTR_OBJECT && p->metadata_checked) {
        md_fuse_xattr_result(p->request,q,out,output);
        if (out->error==-EINPROGRESS) *output->continuation=base;
        return;
    }
    union { struct fuse_attr_out attr; struct fuse_statfs_out statfs; struct fuse_open_out open; char link[PATH_MAX]; } response;
    long n=md_fuse_request_result(p->request,&response,sizeof(response));
    if (n==-EINPROGRESS) { out->error=n; *output->continuation=base; return; }
    if (p->executable && p->opcode==FUSE_ACCESS && (n==0 || n==-ENOSYS)) {
        p->access_checked=1; md_fuse_request_release(p->request); p->request=NULL;
        operation_resume(base,fs,out,output); return;
    }
    if (n<0) { out->error=n==-ENOSYS && p->opcode==FUSE_ACCESS ? 0 : (int)n; return; }
    if (p->opcode==FUSE_GETATTR || p->opcode==FUSE_SETATTR) {
        struct stat st;
        out->error=n!=sizeof(response.attr) ? -EPROTO : md_fuse_view_attributes(p->view,&response.attr.attr,&st);
        if (!out->error && (st.st_mode&S_IFMT)!=p->node->type) out->error=-EIO;
        if (!out->error) {
            pthread_mutex_lock(&p->view->lock); p->node->attributes=st; pthread_mutex_unlock(&p->view->lock);
            if (q->operation==MD_FS_XATTR_OBJECT) {
                p->metadata_checked=1; md_fuse_request_release(p->request); p->request=NULL;
                operation_resume(base,fs,out,output); return;
            }
            if (opening(p)) {
                if (p->executable) {
                    p->attributes=response.attr.attr;
                    if (!S_ISREG(st.st_mode) || (md_fs_anchor_policy(p->origin)&MD_MOUNT_NOEXEC)) out->error=-EACCES;
                    else out->error=md_file_permissions(&st,X_OK,&p->identity);
                }
                if ((p->open_flags&O_DIRECTORY) && !S_ISDIR(st.st_mode)) out->error=-ENOTDIR;
                else if (!(p->open_flags&O_PATH) && S_ISLNK(st.st_mode)) out->error=-ELOOP;
                else if (!(p->open_flags&O_PATH) && (p->open_flags&(O_ACCMODE|O_TRUNC)) && S_ISDIR(st.st_mode)) out->error=-EISDIR;
                if (!out->error && !(p->open_flags&O_PATH) && md_fuse_session_options(p->view->session)->default_permissions) {
                    unsigned mode=(p->open_flags&O_ACCMODE)==O_RDWR ? R_OK|W_OK
                        : (p->open_flags&O_ACCMODE)==O_WRONLY ? W_OK : R_OK;
                    if (p->open_flags&O_TRUNC) mode|=W_OK;
                    out->error=md_file_permissions(&st,mode,&p->identity);
                }
                if (!out->error && (p->open_flags&O_NOATIME)) out->error=md_file_noatime(&st,&p->identity);
                if (!out->error) {
                    p->metadata_checked=1; if (p->opcode==FUSE_SETATTR) p->truncated=1;
                    md_fuse_request_release(p->request); p->request=NULL;
                    operation_resume(base,fs,out,output); return;
                }
            } else if (q->operation==MD_FS_ACCESS) {
                struct md_identity identity=md_identity_access(fs->store->identity,!!(q->flags&MD_AT_EACCESS));
                out->error=md_file_permissions(&st,q->mode,&identity);
            } else {
                md_fs_stat_info(&st,&out->info); out->info.mount_id=p->origin->mount->id;
            }
        }
    } else if (p->opcode==FUSE_OPEN || p->opcode==FUSE_OPENDIR) {
        if (n!=sizeof(response.open)) out->error=-EPROTO;
        else if (p->executable) {
            p->image_handle=response.open.fh; p->image_opened=1; p->opcode=0;
            md_fuse_request_release(p->request); p->request=NULL;
            out->error=md_fuse_image_new(p->view->session,&p->identity,md_fuse_view_pid(p->view,q->actor),
                p->node->id,p->image_handle,&p->attributes,&p->image);
            if (!out->error) operation_resume(base,fs,out,output);
        } else out->error=publish_file(p,out,output,&response.open);
    } else if (p->opcode==FUSE_STATFS) {
        if (n!=sizeof(response.statfs)) out->error=-EPROTO;
        else if (!output->data || output->capacity<sizeof(struct md_fs_statfs)) out->error=-ERANGE;
        else {
            struct fuse_kstatfs *s=&response.statfs.st;
            *(struct md_fs_statfs *)output->data=(struct md_fs_statfs){.type=FUSE_SUPER_MAGIC,
                .block_size=s->bsize,.blocks=s->blocks,.free_blocks=s->bfree,.available_blocks=s->bavail,
                .files=s->files,.free_files=s->ffree,.name_length=s->namelen,.fragment_size=s->frsize};
            out->size=sizeof(struct md_fs_statfs);
        }
    } else if (p->opcode==FUSE_READLINK) {
        if (!n || memchr(response.link,0,n)) out->error=-EPROTO;
        else if (!output->data || !output->capacity) out->error=-EINVAL;
        else { out->size=(size_t)n<output->capacity ? (size_t)n : output->capacity; memcpy(output->data,response.link,out->size); }
    } else if (n) out->error=-EPROTO;
}
int md_fs_fuse_operation(struct md_filesystem *fs,const struct md_fs_request *q,
        const struct md_view_location *a,const struct md_view_location *b,
        struct md_fs_result *out,const struct md_fs_output *output) {
    struct fuse_view *v=a->mount ? md_provider_tree_context(a->mount->provider,&view_ops) : NULL;
    if (!v) return 0;
    if (q->operation==MD_FS_PATH || q->operation==MD_FS_REALPATH || q->operation==MD_FS_OBJECT_ID) return 0;
    if (q->operation!=MD_FS_STAT && q->operation!=MD_FS_FSTAT && q->operation!=MD_FS_STATFS
            && q->operation!=MD_FS_READLINK && q->operation!=MD_FS_ACCESS
            && q->operation!=MD_FS_OPEN && q->operation!=MD_FS_REOPEN && q->operation!=MD_FS_CREATE
            && q->operation!=MD_FS_OPEN_IMAGE
            && q->operation!=MD_FS_MKDIR && q->operation!=MD_FS_MKNOD && q->operation!=MD_FS_SYMLINK
            && q->operation!=MD_FS_UNLINK && q->operation!=MD_FS_RENAME && q->operation!=MD_FS_LINK
            && q->operation!=MD_FS_CHMOD && q->operation!=MD_FS_CHOWN && q->operation!=MD_FS_UTIMENS
            && q->operation!=MD_FS_XATTR_OBJECT) {
        out->error=-EOPNOTSUPP; return 1;
    }
    if (!output || !output->continuation) { out->error=-EOPNOTSUPP; return 1; }
    int executable=q->operation==MD_FS_OPEN_IMAGE || (q->operation==MD_FS_REOPEN && (q->mode&MD_FS_REOPEN_EXECUTE));
    if (q->operation==MD_FS_OPEN || q->operation==MD_FS_REOPEN || q->operation==MD_FS_CREATE || executable) {
        if (q->operation==MD_FS_REOPEN && (q->mode&MD_FS_REOPEN_NATIVE) && !(q->flags&O_PATH)) {
            out->error=-EOPNOTSUPP; return 1;
        }
        if (!executable && !(q->flags&O_PATH) && !output->control) { out->requires_control=1; out->error=-EOPNOTSUPP; return 1; }
        unsigned known=O_ACCMODE|O_CLOEXEC|O_PATH|O_NOFOLLOW|O_DIRECTORY|O_CREAT|O_EXCL|O_TRUNC
            |O_NONBLOCK|O_NOCTTY|O_LARGEFILE|O_NOATIME|O_SYNC|O_DSYNC;
        if (q->flags&~known) { out->error=-EOPNOTSUPP; return 1; }
        if ((q->flags&O_ACCMODE)==O_ACCMODE) { out->error=-EINVAL; return 1; }
    }
    pthread_mutex_lock(&v->lock);
    struct fuse_node *n=a->fd<0 ? NULL : node_fd(v,a->fd);
    struct fuse_node *parent=a->parent<0 ? NULL : node_fd(v,a->parent);
    struct fuse_node *destination=b && b->parent>=0 ? node_fd(v,b->parent) : NULL;
    struct fuse_node *replaced=b && b->fd>=0 ? node_fd(v,b->fd) : NULL;
    pthread_mutex_unlock(&v->lock);
    if ((!n && !parent) || (b && !destination)) { out->error=-ESTALE; return 1; }
    if (q->operation==MD_FS_READLINK && n && !S_ISLNK(n->type)) {
        out->error=-EINVAL; return 1;
    }
    if (q->operation==MD_FS_MKNOD && (q->mode&S_IFMT)!=S_IFREG) { out->error=-EOPNOTSUPP; return 1; }
    if (q->operation==MD_FS_LINK && n && S_ISDIR(n->type)) { out->error=-EPERM; return 1; }
    if (q->operation==MD_FS_RENAME && q->flags&~(RENAME_NOREPLACE|RENAME_EXCHANGE)) { out->error=-EINVAL; return 1; }
    struct view_operation *p=calloc(1,sizeof(*p));
    if (!p) { out->error=-ENOMEM; return 1; }
    out->error=md_fs_continuation_capture(&p->base,q);
    if (out->error) { free(p); return 1; }
    p->base.ready=operation_ready; p->base.resume=operation_resume; p->base.destroy=operation_destroy;
    p->view=md_fuse_view_retain(v); p->node=n; p->parent=parent; p->destination=destination; p->replaced=replaced;
    p->identity=md_identity_copy(fs->store->identity);
    p->executable=executable;
    p->open_flags=executable ? O_RDONLY|O_CLOEXEC : q->operation==MD_FS_CREATE ? O_RDWR|O_CREAT|O_EXCL : q->flags;
    p->mutation=q->operation==MD_FS_MKDIR || q->operation==MD_FS_MKNOD || q->operation==MD_FS_SYMLINK
        || q->operation==MD_FS_UNLINK || q->operation==MD_FS_RENAME || q->operation==MD_FS_LINK
        || q->operation==MD_FS_CHMOD || q->operation==MD_FS_CHOWN || q->operation==MD_FS_UTIMENS
        || (opening(p) && !n);
    snprintf(p->name,sizeof(p->name),"%s",a->name);
    if (b) snprintf(p->target,sizeof(p->target),"%s",b->name);
    if (q->operation==MD_FS_RENAME) {
        p->renamed=calloc(1,sizeof(*p->renamed)+strlen(p->target)+1);
        if (!p->renamed) out->error=-ENOMEM;
        else { p->renamed->parent=destination; p->renamed->node=n; strcpy(p->renamed->name,p->target); }
    }
    if (!out->error) out->error=md_view_anchor_duplicate(fs,a->view,a->mount,a->fd<0 ? a->parent : a->fd,&p->origin);
    if (!out->error) operation_resume(&p->base,fs,out,output);
    if (out->error!=-EINPROGRESS) operation_destroy(&p->base);
    return 1;
}

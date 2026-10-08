#define _GNU_SOURCE
#include "descriptor_inode.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

enum { MAGIC=0x4d444449U, VERSION=1 };
struct state { uint32_t uid,gid,mode,has_change; int64_t seconds,nanos; };
struct shared {
    uint32_t magic,version,reserved;
    atomic_uint current;
    uint64_t device,inode;
    struct state value[2];
};
_Static_assert(ATOMIC_INT_LOCK_FREE==2 && sizeof(atomic_uint)==4,"shared inode commit");
struct descriptor_inode {
    struct md_fd_object object;
    pthread_mutex_t lock;
    struct state local;
    struct shared *shared;
    int fd;
};
static void destroy(struct md_fd_object *object) {
    struct descriptor_inode *node=(void *)object;
    if (node->shared) munmap(node->shared,sizeof(*node->shared));
    if (node->fd>=0) close(node->fd);
    pthread_mutex_destroy(&node->lock); free(node);
}
static const struct md_fd_object_type type={.destroy=destroy};
int md_descriptor_inode_is(const struct md_fd_object *object) { return object && object->type==&type; }
static struct descriptor_inode *allocate(void) {
    struct descriptor_inode *node=calloc(1,sizeof(*node)); if (!node) return NULL;
    node->fd=-1;
    int error=pthread_mutex_init(&node->lock,NULL);
    if (error) { free(node); errno=error; return NULL; }
    md_fd_object_init(&node->object,&type); return node;
}
struct md_fd_object *md_descriptor_inode_new(const struct md_identity *id, mode_t mode) {
    if (!id || !S_ISFIFO(mode)) { errno=EINVAL; return NULL; }
    struct descriptor_inode *node=allocate(); if (!node) return NULL;
    node->local=(struct state){.uid=id->uid.fs,.gid=id->gid.fs,.mode=mode};
    return &node->object;
}
static int begin(struct descriptor_inode *node, struct state *value) {
    int error=pthread_mutex_lock(&node->lock); if (error) return -error;
    if (node->shared) {
        struct flock lock={.l_type=F_WRLCK,.l_whence=SEEK_SET};
        /* EVENT_WAIT: a metadata publisher releases its OFD lock; interruption
         * fails the call and process death releases the lock in the kernel.
         * No guest IO or syscall runs inside this short transaction. */
        if (fcntl(node->fd,F_OFD_SETLKW,&lock)) error=errno;
        else {
            unsigned current=atomic_load_explicit(&node->shared->current,memory_order_acquire);
            if (current>1) {
                lock.l_type=F_UNLCK; fcntl(node->fd,F_OFD_SETLK,&lock); error=EPROTO;
            } else *value=node->shared->value[current];
        }
    } else *value=node->local;
    if (error) pthread_mutex_unlock(&node->lock);
    return -error;
}
static int end(struct descriptor_inode *node, const struct state *value) {
    int error=0;
    if (node->shared) {
        if (value) {
            unsigned next=atomic_load_explicit(&node->shared->current,memory_order_relaxed)^1U;
            node->shared->value[next]=*value;
            /* Death before this commit keeps the complete previous snapshot. */
            atomic_store_explicit(&node->shared->current,next,memory_order_release);
        }
        struct flock lock={.l_type=F_UNLCK,.l_whence=SEEK_SET};
        if (fcntl(node->fd,F_OFD_SETLK,&lock)) error=-errno;
    } else if (value) node->local=*value;
    pthread_mutex_unlock(&node->lock); return error;
}
int md_descriptor_inode_stat(struct md_fd_object *object, const struct md_identity *id, struct stat *st) {
    if (!md_descriptor_inode_is(object) || !id || !st) return -EINVAL;
    struct descriptor_inode *node=(void *)object; struct state value;
    int error=begin(node,&value); if (error) return error;
    error=end(node,NULL); if (error) return error;
    st->st_uid=md_identity_visible_id(id,0,value.uid);
    st->st_gid=md_identity_visible_id(id,1,value.gid); st->st_mode=value.mode;
    if (value.has_change) st->st_ctim=(struct timespec){value.seconds,value.nanos};
    return 0;
}
int md_descriptor_inode_access(struct md_fd_object *object, const struct md_identity *id, int mode) {
    if (!md_descriptor_inode_is(object) || !id || (mode&~(R_OK|W_OK|X_OK))) return -EINVAL;
    struct descriptor_inode *node=(void *)object; struct state value;
    int error=begin(node,&value); if (error) return error;
    error=end(node,NULL); if (error) return error;
    unsigned shift=id->uid.fs==value.uid ? 6 : md_identity_in_group(id,value.gid) ? 3 : 0;
    if (((value.mode>>shift)&mode)==(unsigned)mode) return 0;
    if (!(mode&X_OK) && md_identity_file_capable(id,value.uid,value.gid,CAP_DAC_OVERRIDE)) return 0;
    if (!(mode&(W_OK|X_OK)) && md_identity_file_capable(id,value.uid,value.gid,CAP_DAC_READ_SEARCH)) return 0;
    return -EACCES;
}
static int changed(struct state *value) {
    struct timespec now; if (clock_gettime(CLOCK_REALTIME,&now)) return -errno;
    value->seconds=now.tv_sec; value->nanos=now.tv_nsec; value->has_change=1; return 0;
}
int md_descriptor_inode_chown(struct md_fd_object *object, const struct md_identity *id, uint32_t uid, uint32_t gid) {
    if (!md_descriptor_inode_is(object) || !id) return -EINVAL;
    struct descriptor_inode *node=(void *)object; struct state value;
    int error=begin(node,&value); if (error) return error;
    if (uid!=UINT32_MAX) {
        uid=md_user_namespace_into(id->user_namespace,0,uid);
        if (uid==UINT32_MAX) error=-EINVAL;
    } else uid=value.uid;
    if (gid!=UINT32_MAX) {
        gid=md_user_namespace_into(id->user_namespace,1,gid);
        if (gid==UINT32_MAX) error=-EINVAL;
    } else gid=value.gid;
    if (!error && !md_identity_file_capable(id,value.uid,value.gid,CAP_CHOWN)
            && !(id->uid.fs==value.uid && uid==value.uid
                && (gid==value.gid || md_identity_in_group(id,gid)))) error=-EPERM;
    if (!error) error=changed(&value);
    if (!error) {
        value.uid=uid; value.gid=gid; value.mode&=~S_ISUID;
        if (value.mode&S_IXGRP) value.mode&=~S_ISGID;
    }
    int released=end(node,error ? NULL : &value); return error ? error : released;
}
int md_descriptor_inode_chmod(struct md_fd_object *object, const struct md_identity *id, mode_t mode) {
    if (!md_descriptor_inode_is(object) || !id) return -EINVAL;
    struct descriptor_inode *node=(void *)object; struct state value;
    int error=begin(node,&value); if (error) return error;
    if (id->uid.fs!=value.uid && !md_identity_file_capable(id,value.uid,value.gid,CAP_FOWNER)) error=-EPERM;
    mode&=07777;
    if (!md_identity_file_capable(id,value.uid,value.gid,CAP_FSETID) && !md_identity_in_group(id,value.gid)) mode&=~S_ISGID;
    if (!error) error=changed(&value);
    if (!error) value.mode=(value.mode&S_IFMT)|mode;
    int released=end(node,error ? NULL : &value); return error ? error : released;
}
static int data_identity(int fd, struct stat *out) {
    if (fstat(fd,out)) return -errno;
    return S_ISFIFO(out->st_mode) ? 0 : -EPROTO;
}
int md_descriptor_inode_export(struct md_fd_object *object, int data_fd, int directory, int *out) {
    if (!md_descriptor_inode_is(object) || !out || *out>=0) return -EINVAL;
    struct descriptor_inode *node=(void *)object; struct stat st;
    int error=data_identity(data_fd,&st); if (error) return error;
    struct shared *page=MAP_FAILED; int fd=-1;
    error=pthread_mutex_lock(&node->lock); if (error) return -error;
    if (!node->shared) {
        fd=openat(directory,".",O_TMPFILE|O_RDWR|O_CLOEXEC,0600);
        if (fd<0) error=-errno;
        if (!error && ftruncate(fd,sizeof(*page))) error=-errno;
        if (!error) {
            page=mmap(NULL,sizeof(*page),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
            if (page==MAP_FAILED) error=-errno;
        }
        if (!error) {
            *page=(struct shared){.magic=MAGIC,.version=VERSION,.device=st.st_dev,.inode=st.st_ino};
            atomic_init(&page->current,0); page->value[0]=node->local;
        }
        if (!error) { node->shared=page; node->fd=fd; page=MAP_FAILED; fd=-1; }
    }
    if (!error && (node->shared->device!=(uint64_t)st.st_dev || node->shared->inode!=(uint64_t)st.st_ino)) error=-ESTALE;
    if (!error) {
        /* Queued custody must not retain the writer's lock description after
         * its process dies. Each participant owns a separate native OFD. */
        char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d",node->fd);
        int result=open(path,O_RDWR|O_CLOEXEC);
        if (result<0) error=-errno; else *out=result;
    }
    pthread_mutex_unlock(&node->lock);
    if (page!=MAP_FAILED) munmap(page,sizeof(*page));
    if (fd>=0) close(fd);
    return error;
}
int md_descriptor_inode_import(int metadata_fd, int data_fd, struct md_fd_object **out) {
    if (!out || *out) return -EINVAL;
    struct stat st,meta;
    int error=data_identity(data_fd,&st); if (error) return error;
    if (fstat(metadata_fd,&meta)) return -errno;
    if (!S_ISREG(meta.st_mode) || meta.st_size!=sizeof(struct shared)
            || meta.st_nlink || meta.st_uid!=getuid() || (meta.st_mode&0777)!=0600) return -EPROTO;
    struct descriptor_inode *node=allocate(); if (!node) return -errno;
    char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d",metadata_fd);
    /* Independent OFD is essential: an SCM_RIGHTS duplicate shares its lock. */
    node->fd=open(path,O_RDWR|O_CLOEXEC);
    if (node->fd<0) error=-errno;
    if (!error) {
        node->shared=mmap(NULL,sizeof(*node->shared),PROT_READ|PROT_WRITE,MAP_SHARED,node->fd,0);
        if (node->shared==MAP_FAILED) { node->shared=NULL; error=-errno; }
    }
    if (!error && (node->shared->magic!=MAGIC || node->shared->version!=VERSION || node->shared->reserved
            || node->shared->device!=(uint64_t)st.st_dev || node->shared->inode!=(uint64_t)st.st_ino)) error=-EPROTO;
    if (!error) {
        struct state value;
        error=begin(node,&value);
        if (!error) {
            error=end(node,NULL);
            if (!error && (!S_ISFIFO(value.mode) || (value.mode&~(S_IFMT|07777U))
                    || value.uid==UINT32_MAX || value.gid==UINT32_MAX || value.has_change>1
                    || (value.has_change && (value.nanos<0 || value.nanos>=1000000000)))) error=-EPROTO;
        }
    }
    if (error) md_fd_object_release(&node->object); else *out=&node->object;
    return error;
}

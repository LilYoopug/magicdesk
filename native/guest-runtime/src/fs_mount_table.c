#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <unistd.h>

struct md_mount_identity { uint64_t native[4096]; unsigned guest[4096], count; };
static int ensure_view(struct md_filesystem *fs) {
    if (!fs->mounts) {
        fs->mounts=md_mount_namespace_new();
        if (!fs->mounts) return -errno;
    }
    return 0;
}
int md_fs_base_mount(struct md_filesystem *fs, int shared_memory, uint64_t *guest) {
    int r=ensure_view(fs);
    if (!r) *guest=shared_memory ? fs->mounts->shm_id : fs->mounts->root_id;
    return r;
}
int md_fs_native_mount(struct md_filesystem *fs, uint64_t native, uint64_t *guest) {
    if (!native) return -EINVAL;
    int r=ensure_view(fs);
    if (r) return r;
    if (!fs->mounts->native_ids) {
        fs->mounts->native_ids=calloc(1,sizeof(*fs->mounts->native_ids));
        if (!fs->mounts->native_ids) return -ENOMEM;
    }
    struct md_mount_identity *ids=fs->mounts->native_ids;
    unsigned i;
    for (i=0; i<ids->count; ++i) if (ids->native[i]==native) break;
    if (i==ids->count) {
        if (i==sizeof(ids->native)/sizeof(ids->native[0])) return -ENOSPC;
        r=md_mount_id_allocate(&ids->guest[i]);
        if (r) return r;
        ids->native[ids->count++]=native;
    }
    *guest=ids->guest[i];
    return 0;
}

static int below(const char *path, const char *root) {
    size_t n=strlen(root);
    return !strncmp(path,root,n) && (!path[n] || path[n]=='/');
}
/* Native mounts retain kernel IO and authority, but IDs identify instances in
 * the selected view, as for logical mounts. statx uses this same map. */
static int native_entries(struct md_filesystem *fs, FILE *out, unsigned info, unsigned *dev_id) {
    FILE *in=fopen("/proc/self/mountinfo","re");
    if (!in) return -errno;
    char *line=NULL; size_t capacity=0; int r=0;
    while (!r && getline(&line,&capacity,in)>=0) {
        unsigned long long raw, parent; int rest=0;
        char device[64], root[PATH_MAX], path[PATH_MAX], options[1024];
        if (sscanf(line,"%llu %llu %n%63s %4095s %4095s %1023s",
                &raw,&parent,&rest,device,root,path,options)!=6) { r=-EPROTO; break; }
        if ((!below(path,"/proc") && !below(path,"/dev")) || below(path,"/dev/shm")) continue;
        uint64_t id, owner=fs->mounts->root_id;
        r=md_fs_native_mount(fs,raw,&id);
        if (!r && strcmp(path,"/dev") && strcmp(path,"/proc"))
            r=md_fs_native_mount(fs,parent,&owner);
        if (r) break;
        if (!strcmp(path,"/dev")) *dev_id=(unsigned)id;
        if (info) fprintf(out,"%llu %llu %s",(unsigned long long)id,(unsigned long long)owner,line+rest);
        else {
            char type[128], source[PATH_MAX], *separator=strstr(line," - ");
            if (!separator || sscanf(separator+3,"%127s %4095s",type,source)!=2) { r=-EPROTO; break; }
            fprintf(out,"%s %s %s %s 0 0\n",source,path,type,options);
        }
    }
    if (!r && ferror(in)) r=-EIO;
    free(line); fclose(in); return r;
}

static void escaped(FILE *stream, const char *text) {
    for (const unsigned char *p=(const unsigned char *)text; *p; ++p) {
        if (*p==' ' || *p=='\t' || *p=='\n' || *p=='\\') fprintf(stream,"\\%03o",*p);
        else fputc(*p,stream);
    }
}
static void entry(FILE *stream, unsigned info, unsigned id, unsigned parent, dev_t device,
        const char *path, const char *type, const char *source, int readonly) {
    const char *options=readonly ? "ro" : "rw";
    if (info) {
        fprintf(stream,"%u %u %u:%u / ",id,parent,major(device),minor(device)); escaped(stream,path);
        fprintf(stream," %s - %s %s %s\n",options,type,source,options);
    } else {
        fprintf(stream,"%s ",source); escaped(stream,path); fprintf(stream," %s %s 0 0\n",type,options);
    }
}
int md_fs_mount_table(struct md_filesystem *fs, unsigned info, unsigned flags) {
    if (info>1 || (flags&~(O_PATH|O_CLOEXEC))) return -EINVAL;
    int r=ensure_view(fs);
    if (r) return r;
    int fd=md_inode_temporary(fs->store);
    if (fd<0) return fd;
    FILE *stream=fdopen(fd,"w+");
    if (!stream) { int error=-errno; close(fd); return error; }
    struct stat root;
    r=fs->native_root ? (fstat(fs->native_root->fd,&root) ? -errno : 0)
        : md_inode_stat(fs->store,-1,"/",0,&root);
    unsigned dev_id=fs->mounts->root_id;
    if (!r) {
        if (fs->native_root) {
            const struct md_view_mount *m=fs->native_root->mount;
            entry(stream,info,m->id,m->parent ? m->parent->id : fs->mounts->root_id,
                root.st_dev,"/","none","attachment",md_view_readonly(m));
        } else entry(stream,info,fs->mounts->root_id,fs->mounts->root_id,root.st_dev,"/","guestfs","guest",fs->store->readonly);
        if (!fs->store->root_id && !fs->native_root) {
            r=native_entries(fs,stream,info,&dev_id);
            if (!r) entry(stream,info,fs->mounts->shm_id,dev_id,root.st_dev,"/dev/shm","guestfs","guest",fs->store->readonly);
        }
    }
    struct md_fs_mounts *tree=fs->mounts ? fs->mounts->tree : NULL;
    if (tree) for (unsigned i=0; !r && i<tree->count; ++i) {
        const struct md_view_mount *m=&tree->mounts[i];
        char path[PATH_MAX]; r=md_view_path(fs,m->target,m->parent,path,sizeof(path));
        if (r == -ENOENT && (fs->store->root_id || fs->native_root)) { r=0; continue; }
        if (!r) entry(stream,info,m->id,m->parent ? m->parent->id : fs->mounts->root_id,
            m->native.st_dev,path,"none","attachment",md_view_readonly(m));
    }
    if (!r && (fflush(stream) || ferror(stream))) r=-EIO;
    int readable=-1;
    if (!r) {
        char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
        readable=open(path,(int)flags|O_CLOEXEC);
        if (readable<0) r=-errno;
    }
    if (fclose(stream) && !r) r=-errno;
    if (r && readable>=0) close(readable);
    return r ? r : readable;
}

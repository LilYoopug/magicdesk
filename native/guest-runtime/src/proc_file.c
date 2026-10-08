#define _GNU_SOURCE
#include "proc_file.h"
#include "proc_sysctl.h"
#include "proc_namespace.h"
#include "pid_namespace.h"
#include "fd_selector.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

struct md_proc_file {
    struct md_fd_object object;
    struct md_user_namespace *target;
    struct md_identity opener;
    struct md_identity process_identity;
    pid_t tracer;
    int process_state;
    enum md_proc_file_kind kind;
    int flags;
    int64_t position;
    struct md_resource_queue operations;
    struct md_proc_file_node node;
    struct md_namespace_reference namespace;
    void *directory;
    size_t directory_size, directory_capacity;
    struct md_pid_namespace *pid_view;
    char *content;
    size_t content_size;
};
static void destroy(struct md_fd_object *object) {
    struct md_proc_file *f=(void *)object;
    md_resource_queue_destroy(&f->operations);
    if (md_proc_file_namespace(f->kind)) md_namespace_reference_release(&f->namespace);
    md_pid_namespace_release(f->pid_view); free(f->content);
    if (f->process_state) md_identity_release(&f->process_identity);
    md_user_namespace_release(f->target); md_identity_release(&f->opener); free(f->directory); free(f);
}
static const struct md_fd_object_type type={.destroy=destroy,.selectors=1U<<MD_FD_SELECTOR_PROC};
struct md_fd_object *md_proc_file_object(struct md_proc_file *f) {
    return f ? &f->object : NULL;
}
struct md_proc_file *md_proc_file_from_object(struct md_fd_object *o) {
    return o && o->type==&type ? (void *)o : NULL;
}
struct md_proc_file *md_proc_file_open(struct md_user_namespace *target,
        enum md_proc_file_kind kind, const struct md_identity *opener, int flags) {
    int error=!opener || kind<MD_PROC_FILE_UID_MAP || kind>MD_PROC_FILE_STAT ? EINVAL : 0;
    int directory=md_proc_file_directory(kind);
    if (!error && (flags&O_DIRECTORY) && !directory) error=ENOTDIR;
    if (!error && directory && !(flags&O_PATH) && ((flags&O_ACCMODE)!=O_RDONLY || (flags&O_TRUNC))) error=EISDIR;
    if (!error && (flags&(O_CREAT|O_EXCL))==(O_CREAT|O_EXCL)) error=EEXIST;
    if (!error && !(flags&O_PATH) && (flags&O_ACCMODE)==O_ACCMODE) error=EINVAL;
    if (!error && !(flags&O_PATH) && (md_proc_file_namespace(kind) || md_proc_file_process(kind))
            && ((flags&O_ACCMODE)!=O_RDONLY || (flags&O_TRUNC))) error=EACCES;
    if (!error && !(flags&O_PATH) && (flags&O_ACCMODE)!=O_RDONLY && kind==MD_PROC_FILE_SETGROUPS
            && !md_identity_capable_in(opener,target,CAP_SYS_ADMIN)) error=EACCES;
    if (!error && !(flags&O_PATH) && md_proc_file_sysctl(kind))
        error=-md_proc_sysctl_access(kind,opener,(flags&O_ACCMODE)!=O_RDONLY || (flags&O_TRUNC) ? W_OK : R_OK,1);
    if (error) { errno=error; return NULL; }
    struct md_proc_file *f=calloc(1,sizeof(*f));
    if (!f) return NULL;
    error=md_resource_queue_init(&f->operations);
    if (error) { free(f); errno=-error; return NULL; }
    md_fd_object_init(&f->object,&type);
    f->target=md_proc_file_sysctl(kind) || md_proc_file_namespace(kind) || directory || md_proc_file_process(kind)
        ? NULL : md_user_namespace_retain(target);
    f->opener=md_identity_copy(opener); f->kind=kind; f->flags=flags;
    return f;
}
struct md_proc_file *md_proc_file_open_namespace(const struct md_namespace_reference *ref,
        const struct md_identity *opener, int flags) {
    struct md_proc_file *f=md_proc_file_open(NULL,
        (enum md_proc_file_kind)(MD_PROC_FILE_NS_USER+ref->kind),opener,flags);
    if (f) f->namespace=md_namespace_reference_copy(ref);
    return f;
}
const struct md_namespace_reference *md_proc_file_namespace_reference(const struct md_proc_file *f) {
    return f && md_proc_file_namespace(f->kind) ? &f->namespace : NULL;
}
struct md_proc_file *md_proc_file_retain(struct md_proc_file *f) {
    md_fd_object_retain(md_proc_file_object(f));
    return f;
}
void md_proc_file_release(struct md_proc_file *f) {
    md_fd_object_release(md_proc_file_object(f));
}
int md_proc_file_flags(const struct md_proc_file *f) { return f->flags; }
void md_proc_file_node(struct md_proc_file *f, struct md_proc_file_node node) { f->node=node; }
void md_proc_file_pid_view(struct md_proc_file *f, struct md_pid_namespace *view) {
    struct md_pid_namespace *old=f->pid_view;
    f->pid_view=md_pid_namespace_retain(view); md_pid_namespace_release(old);
}
void md_proc_file_process_state(struct md_proc_file *f,const struct md_identity *identity,pid_t tracer) {
    if (!md_proc_file_process(f->kind) || f->content) return;
    if (f->process_state) md_identity_release(&f->process_identity);
    f->process_identity=md_identity_copy(identity); f->process_state=1; f->tracer=tracer;
}
struct md_proc_file_node md_proc_file_get_node(const struct md_proc_file *f) { return f->node; }
enum md_proc_file_kind md_proc_file_kind(const struct md_proc_file *f) { return f->kind; }
struct md_proc_file *md_proc_file_reopen(const struct md_proc_file *f,
        const struct md_identity *opener, int flags) {
    struct md_proc_file *next=md_proc_file_namespace(f->kind)
        ? md_proc_file_open_namespace(&f->namespace,opener,flags)
        : md_proc_file_open(f->target,f->kind,opener,flags);
    if (next) { next->node=f->node; md_proc_file_pid_view(next,f->pid_view); }
    return next;
}
int md_proc_file_descriptor(const struct md_proc_file *f) {
    if (!f) return -EINVAL;
    if (md_proc_file_directory(f->kind)) {
        char path[64]; snprintf(path,sizeof(path),"/proc/%d%s",f->node.process,
            f->kind==MD_PROC_FILE_NS_DIRECTORY ? "/ns" : "");
        int fd=open(path,O_CLOEXEC|(f->flags&~(O_CREAT|O_EXCL|O_TRUNC)));
        if (fd<0) return -errno;
        struct stat st;
        int error=fstat(fd,&st) ? -errno : st.st_dev!=f->node.device || st.st_ino!=f->node.inode ? -ENOENT : 0;
        if (error) close(fd);
        return error ? error : fd;
    }
    /* An inert native carrier supplies access modes without requiring host
     * CONFIG_USER_NS or executable tmpfs access. All file semantics are typed. */
    int fd=open("/dev/null",O_CLOEXEC|(f->flags&~(O_CREAT|O_EXCL|O_TRUNC)));
    return fd<0 ? -errno : fd;
}
int md_proc_file_access(const struct md_proc_file *f, enum md_proc_file_operation operation) {
    if (!f || (f->flags&O_PATH)) return -EBADF;
    if (operation==MD_PROC_FILE_GETDENTS) return md_proc_file_directory(f->kind) ? 0 : -ENOTDIR;
    if (md_proc_file_directory(f->kind) && operation!=MD_PROC_FILE_SEEK) return -EISDIR;
    if (md_proc_file_namespace(f->kind)) return operation==MD_PROC_FILE_SEEK ? -ESPIPE : -EINVAL;
    int mode=f->flags&O_ACCMODE;
    return (operation==MD_PROC_FILE_READ && mode==O_WRONLY)
        || (operation==MD_PROC_FILE_WRITE && mode==O_RDONLY) ? -EBADF : 0;
}
static size_t slice(void *out, size_t capacity, uint64_t offset, const void *data, size_t size) {
    if (offset>=size) return 0;
    size-=offset;
    if (size>capacity) size=capacity;
    if (size) memcpy(out,(const char *)data+offset,size);
    return size;
}
static pid_t process_number(struct md_pid_namespace *view, long native) {
    if (native<=0 || !view) return (pid_t)native;
    struct md_pid_identity *id=md_pid_namespace_find(view,(pid_t)native);
    pid_t number=md_pid_identity_number(id,view);
    md_pid_identity_release(id); return number;
}
static void process_status_line(struct md_proc_file *f, FILE *out, const char *line) {
    if (f->process_state) {
        if (!strncmp(line,"TracerPid:",10)) {
            fprintf(out,"TracerPid:\t%d\n",process_number(f->pid_view,f->tracer)); return;
        }
        int group=!strncmp(line,"Gid:",4);
        if (group || !strncmp(line,"Uid:",4)) {
            const struct md_identity_ids *ids=group ? &f->process_identity.gid : &f->process_identity.uid;
            fprintf(out,"%s\t%u\t%u\t%u\t%u\n",group ? "Gid:" : "Uid:",
                md_identity_visible_id(&f->opener,group,ids->real),
                md_identity_visible_id(&f->opener,group,ids->effective),
                md_identity_visible_id(&f->opener,group,ids->saved),
                md_identity_visible_id(&f->opener,group,ids->fs)); return;
        }
        if (!strncmp(line,"Groups:",7)) {
            fputs("Groups:\t",out);
            const uint32_t *groups=md_identity_group_data(&f->process_identity);
            for (unsigned i=0;i<md_identity_group_count(&f->process_identity);++i)
                fprintf(out,"%u ",md_identity_visible_id(&f->opener,1,groups[i]));
            fputc('\n',out); return;
        }
        static const char *const names[]={"CapInh:","CapPrm:","CapEff:","CapBnd:","CapAmb:"};
        const struct md_capabilities *caps=&f->process_identity.caps;
        const uint64_t values[]={caps->inheritable,caps->permitted,caps->effective,caps->bounding,caps->ambient};
        for (unsigned i=0;i<5;++i) if (!strncmp(line,names[i],7)) {
            fprintf(out,"%s\t%016llx\n",names[i],(unsigned long long)values[i]); return;
        }
    }
    static const char *const ids[]={"Tgid:","Pid:","PPid:","TracerPid:"};
    static const char *const lists[]={"NStgid:","NSpid:","NSpgid:","NSsid:"};
    for (unsigned i=0;i<sizeof(ids)/sizeof(*ids);++i) {
        size_t n=strlen(ids[i]);
        if (!strncmp(line,ids[i],n)) {
            fprintf(out,"%s\t%d\n",ids[i],process_number(f->pid_view,strtol(line+n,NULL,10))); return;
        }
    }
    for (unsigned i=0;i<sizeof(lists)/sizeof(*lists);++i) {
        size_t n=strlen(lists[i]);
        if (strncmp(line,lists[i],n)) continue;
        pid_t native=(pid_t)strtol(line+n,NULL,10);
        struct md_pid_identity *id=md_pid_namespace_find(f->pid_view,native);
        struct md_pid_namespace *views[33], *view=md_pid_identity_namespace(id);
        unsigned count=0;
        while (view && view!=f->pid_view && count<32) {
            views[count++]=view; view=md_pid_namespace_parent(view);
        }
        fprintf(out,"%s\t%d",lists[i],process_number(f->pid_view,native));
        while (count) fprintf(out,"\t%d",md_pid_identity_number(id,views[--count]));
        fputc('\n',out); md_pid_identity_release(id); return;
    }
    fputs(line,out);
}
static int process_content(struct md_proc_file *f) {
    char path[64];
    snprintf(path,sizeof(path),"/proc/%d/%s",f->node.process,f->kind==MD_PROC_FILE_STAT ? "stat" : "status");
    int fd=open(path,O_RDONLY|O_CLOEXEC);
    if (fd<0) return -errno;
    struct stat st;
    int error=fstat(fd,&st) ? -errno : st.st_dev!=f->node.device || st.st_ino!=f->node.inode ? -ESRCH : 0;
    char source[16384]; size_t size=0;
    while (!error) {
        ssize_t n=read(fd,source+size,sizeof(source)-1-size);
        if (n<0) { if (errno==EINTR) continue; error=-errno; break; }
        if (!n) break;
        size+=(size_t)n;
        if (size==sizeof(source)-1) error=-EOVERFLOW;
    }
    close(fd);
    if (error) return error;
    source[size]=0;
    char *data=NULL; size_t length=0;
    FILE *out=open_memstream(&data,&length);
    if (!out) return -errno;
    if (f->kind==MD_PROC_FILE_STATUS) {
        int have_namespace_fields=strstr(source,"\nNSpid:")!=NULL;
        char *tgid_line=strstr(source,"\nTgid:");
        pid_t tgid=tgid_line ? (pid_t)strtol(tgid_line+6,NULL,10) : f->node.process;
        char *line=source;
        while (*line) {
            char *end=strchr(line,'\n');
            if (!end) { error=-EIO; break; }
            char saved=end[1]; end[1]=0; process_status_line(f,out,line); end[1]=saved; line=end+1;
        }
        /* CONFIG_PID_NS is optional on the host. The mounted guest proc view
         * still publishes its own namespace identity fields. */
        if (!have_namespace_fields) {
            static const char *const names[]={"NStgid:","NSpid:","NSpgid:","NSsid:"};
            pid_t ids[]={tgid,f->node.process,getpgid(tgid),getsid(tgid)};
            for (unsigned i=0;i<4;++i) {
                char value[64]; snprintf(value,sizeof(value),"%s\t%d\n",names[i],ids[i]<0 ? 0 : ids[i]);
                process_status_line(f,out,value);
            }
        }
    } else {
        /* comm may contain spaces and parentheses. Only the final ')' bounds
         * it; the remaining fields have the kernel's stable numeric grammar. */
        char *start=strchr(source,'('), *end=strrchr(source,')');
        if (!start || !end || end<start || end[1]!=' ') error=-EIO;
        else {
            fprintf(out,"%d %.*s",process_number(f->pid_view,f->node.process),(int)(end-start+1),start);
            char *save=NULL; unsigned field=3;
            for (char *value=strtok_r(end+2," \n",&save);value;value=strtok_r(NULL," \n",&save),++field) {
                if (field==4 || field==5 || field==6 || field==8)
                    fprintf(out," %d",process_number(f->pid_view,strtol(value,NULL,10)));
                else fprintf(out," %s",value);
            }
            fputc('\n',out);
        }
    }
    if (ferror(out)) error=-EIO;
    if (fclose(out) && !error) error=-errno;
    if (error) free(data); else { f->content=data; f->content_size=length; }
    return error;
}
long md_proc_file_read_at(struct md_proc_file *f, const struct md_uts_namespace *uts,
        void *out, size_t capacity, int64_t offset) {
    if (!f || (f->flags&O_PATH) || (f->flags&O_ACCMODE)==O_WRONLY) return -EBADF;
    if (offset<0) return -EINVAL;
    if (md_proc_file_directory(f->kind)) return -EISDIR;
    if (md_proc_file_namespace(f->kind)) return -EINVAL;
    if (md_proc_file_process(f->kind)) {
        if (!capacity) return 0;
        int error=f->content ? 0 : process_content(f);
        return error ? error : (long)slice(out,capacity,(uint64_t)offset,f->content,f->content_size);
    }
    if (md_proc_file_sysctl(f->kind)) return md_proc_sysctl_read(uts,f->kind,out,capacity,offset);
    if (f->kind==MD_PROC_FILE_SETGROUPS) {
        const char *s=md_user_namespace_groups_allowed(f->target) ? "allow\n" : "deny\n";
        return (long)slice(out,capacity,(uint64_t)offset,s,strlen(s));
    }
    struct md_id_extent ranges[MD_USER_MAP_EXTENTS];
    int group=f->kind==MD_PROC_FILE_GID_MAP;
    int count=md_user_namespace_extents(f->target,group,ranges,MD_USER_MAP_EXTENTS);
    if (count<0) return count;
    const struct md_user_namespace *observer=f->opener.user_namespace;
    const struct md_user_namespace *parent=md_user_namespace_parent(f->target);
    if (observer==f->target && f->target) observer=parent;
    size_t copied=0;
    for (int i=0;i<count && copied<capacity;++i) {
        uint32_t lower=md_user_namespace_into(parent,group,ranges[i].outside);
        lower=md_user_namespace_from(observer,group,lower);
        char line[34];
        int size=snprintf(line,sizeof(line),"%10u %10u %10u\n",ranges[i].inside,lower,ranges[i].count);
        if (size<0 || (size_t)size>=sizeof(line)) return -EOVERFLOW;
        if (offset>=size) { offset-=size; continue; }
        copied+=slice((char *)out+copied,capacity-copied,(uint64_t)offset,line,(size_t)size);
        offset=0;
    }
    return (long)copied;
}
static int space(unsigned char c) {
    return c==' ' || (c>='\t' && c<='\r');
}
static int number(const char **text, const char *end, uint32_t *out) {
    const char *p=*text;
    while (p<end && space(*p)) ++p;
    if (p==end || *p<'0' || *p>'9') return -EINVAL;
    uint64_t value=0;
    do {
        value=value*10+(unsigned)(*p++-'0');
        if (value>UINT32_MAX) return -EINVAL;
    } while (p<end && *p>='0' && *p<='9');
    *text=p; *out=(uint32_t)value; return 0;
}
static int parse(const char *text, size_t size, struct md_id_extent *ranges) {
    const char *end=memchr(text,0,size);
    if (!end) end=text+size;
    unsigned count=0;
    while (text<end) {
        if (count==MD_USER_MAP_EXTENTS) return -EINVAL;
        const char *line=memchr(text,'\n',(size_t)(end-text));
        if (!line) line=end;
        struct md_id_extent *r=ranges+count;
        if (number(&text,line,&r->inside) || text==line || !space(*text)
                || number(&text,line,&r->outside) || text==line || !space(*text)
                || number(&text,line,&r->count)) return -EINVAL;
        while (text<line && space(*text)) ++text;
        if (text!=line) return -EINVAL;
        text=line<end ? line+1 : end; ++count;
    }
    return count ? (int)count : -EINVAL;
}
static struct md_user_authority authority(const struct md_identity *id) {
    return (struct md_user_authority){id->user_namespace,id->uid.effective,id->gid.effective,id->caps.effective};
}
long md_proc_file_write_at(struct md_proc_file *f, const struct md_identity *writer, struct md_uts_namespace *uts,
        const void *data, size_t size, int64_t offset, size_t page_size) {
    if (!f || !writer || (f->flags&O_PATH) || (f->flags&O_ACCMODE)==O_RDONLY) return -EBADF;
    if (md_proc_file_namespace(f->kind)) return -EINVAL;
    if (md_proc_file_sysctl(f->kind)) return md_proc_sysctl_write(uts,f->kind,writer,data,size,&offset);
    if (offset || size>=(f->kind==MD_PROC_FILE_SETGROUPS ? 8 : page_size)) return -EINVAL;
    if (f->kind==MD_PROC_FILE_SETGROUPS) {
        const char *p=data; int allowed;
        if (size>=5 && !memcmp(p,"allow",5)) { p+=5; allowed=1; }
        else if (size>=4 && !memcmp(p,"deny",4)) { p+=4; allowed=0; }
        else return -EINVAL;
        const char *end=(const char *)data+size;
        while (p<end && space(*p)) ++p;
        if (p<end && *p) return -EINVAL;
        int error=md_user_namespace_setgroups(f->target,allowed);
        return error ? error : (long)size;
    }
    struct md_user_authority opened=authority(&f->opener), current=authority(writer);
    int error=md_user_namespace_map_admit(f->target,f->kind==MD_PROC_FILE_GID_MAP,&opened);
    if (error) return error;
    struct md_id_extent ranges[MD_USER_MAP_EXTENTS];
    int count=parse(data,size,ranges);
    if (count<0) return count;
    error=md_user_namespace_map(f->target,f->kind==MD_PROC_FILE_GID_MAP,&opened,&current,ranges,(unsigned)count);
    return error ? error : (long)size;
}
int md_proc_file_io_begin(struct md_proc_file_io *io, struct md_proc_file *file,
        enum md_proc_file_operation operation, int positional, int64_t offset, int whence,
        size_t length, struct md_resource_wakeup *wake) {
    if (!io || !file || operation<MD_PROC_FILE_READ || operation>MD_PROC_FILE_GETDENTS) return -EINVAL;
    if (io->file || io->turn.queue) return -EBUSY;
    int ready=md_resource_order_begin(&file->operations,&io->turn,wake);
    if (ready<0) return ready;
    io->file=md_proc_file_retain(file); io->operation=operation;
    io->positional=!!positional; io->offset=offset; io->whence=whence; io->length=length;
    return ready;
}
struct directory_entry { uint64_t inode; int64_t next; uint16_t length; unsigned char type; char name[]; };
static int directory_append(struct md_proc_file *f,const char *name,unsigned char type,uint64_t inode) {
    size_t length=strlen(name)+1;
    size_t record=(offsetof(struct directory_entry,name)+length+7)&~(size_t)7;
    if (record>65536 || f->directory_size>65536-record) return -EOVERFLOW;
    if (f->directory_size+record>f->directory_capacity) {
        size_t capacity=f->directory_capacity ? f->directory_capacity*2 : 4096;
        while (capacity<f->directory_size+record) capacity*=2;
        void *data=realloc(f->directory,capacity);
        if (!data) return -ENOMEM;
        f->directory=data; f->directory_capacity=capacity;
    }
    struct directory_entry *e=(void *)((char *)f->directory+f->directory_size);
    memset(e,0,record); e->inode=inode; e->type=type; e->length=(uint16_t)record;
    f->directory_size+=record; e->next=(int64_t)f->directory_size;
    memcpy(e->name,name,length); return 0;
}
static int process_directory(struct md_proc_file *f,const char *path) {
    if (f->directory) return 0;
    int fd=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if (fd<0) return -errno;
    struct stat st;
    int r=fstat(fd,&st) ? -errno : st.st_dev!=f->node.device || st.st_ino!=f->node.inode ? -ENOENT : 0;
    static const char *const names[]={"uid_map","gid_map","setgroups"};
    char data[4096];
    while (!r) {
        ssize_t size=syscall(SYS_getdents64,fd,data,sizeof(data));
        if (size<0) { r=-errno; break; }
        if (!size) break;
        for (size_t at=0; !r && at<(size_t)size;) {
            const struct directory_entry *e=(const void *)(data+at);
            size_t remaining=(size_t)size-at;
            if (remaining<=offsetof(struct directory_entry,name) || e->length>remaining
                    || e->length<=offsetof(struct directory_entry,name)
                    || !memchr(e->name,0,e->length- offsetof(struct directory_entry,name))) { r=-EIO; break; }
            int mapped=0;
            for (unsigned i=0;i<3;++i) mapped|=!strcmp(e->name,names[i]);
            if (!mapped) r=directory_append(f,e->name,e->type,e->inode);
            at+=e->length;
        }
    }
    if (!r && fstatat(fd,"status",&st,0)) r=-errno;
    for (unsigned i=0; !r && i<3; ++i) r=directory_append(f,names[i],DT_REG,
        ((uint64_t)st.st_ino<<2)|(i+1)|UINT64_C(0x8000000000000000));
    close(fd);
    if (r) { free(f->directory); f->directory=NULL; f->directory_size=f->directory_capacity=0; }
    return r;
}
static long directory_entries(struct md_proc_file_io *io, void *bytes, size_t capacity) {
    static const char *const names[]={".","..","user","mnt","uts","ipc","pid","pid_for_children"};
    struct md_proc_file *f=io->file;
    char path[64]; snprintf(path,sizeof(path),"/proc/%d%s",f->node.process,
        f->kind==MD_PROC_FILE_NS_DIRECTORY ? "/ns" : "");
    struct stat st;
    if (stat(path,&st)) return -errno;
    if (st.st_dev!=f->node.device || st.st_ino!=f->node.inode) return -ENOENT;
    if (capacity>io->length) capacity=io->length;
    size_t size=0;
    io->next_position=io->offset;
    if (f->kind==MD_PROC_FILE_PROCESS_DIRECTORY) {
        int r=process_directory(f,path);
        if (r) return r;
        size_t at=0;
        while (at<f->directory_size && at<(uint64_t)io->offset) {
            const struct directory_entry *e=(const void *)((const char *)f->directory+at);
            at+=e->length;
        }
        if (at<f->directory_size && at!=(uint64_t)io->offset) return -EINVAL;
        while (at<f->directory_size) {
            const struct directory_entry *e=(const void *)((const char *)f->directory+at);
            if (e->length>capacity-size) return size ? (long)size : -EINVAL;
            memcpy((char *)bytes+size,e,e->length);
            size+=e->length; at+=e->length; io->next_position=(int64_t)at;
        }
        return (long)size;
    }
    for (int64_t i=io->offset; i<(int64_t)(sizeof(names)/sizeof(*names)); ++i) {
        struct entry { uint64_t inode; int64_t next; uint16_t length; unsigned char type; char name[]; };
        size_t length=strlen(names[i])+1;
        size_t record=(offsetof(struct entry,name)+length+7)&~(size_t)7;
        if (record>capacity-size) return size ? (long)size : -EINVAL;
        struct entry *e=(void *)((char *)bytes+size);
        memset(e,0,record);
        e->inode=i ? (f->node.inode<<3)|(uint64_t)i : f->node.inode;
        e->next=i+1; e->length=(uint16_t)record; e->type=i<2 ? DT_DIR : DT_LNK;
        memcpy(e->name,names[i],length);
        size+=record; io->next_position=i+1;
    }
    return (long)size;
}
long md_proc_file_io_execute(struct md_proc_file_io *io, const struct md_identity *writer, struct md_uts_namespace *uts,
        void *bytes, size_t capacity, size_t page_size) {
    if (!io || !io->file || io->executed) return -EINVAL;
    int error=md_resource_order_start(&io->turn);
    if (error) return error;
    io->executed=1;
    struct md_proc_file *f=io->file;
    error=md_proc_file_access(f,io->operation);
    if (error) return io->result=error;
    if (io->operation==MD_PROC_FILE_SEEK) {
        int64_t offset=io->offset;
        if (f->flags&O_PATH) return io->result=-EBADF;
        if ((io->whence!=SEEK_SET && io->whence!=SEEK_CUR)
                || (io->whence==SEEK_CUR && __builtin_add_overflow(offset,f->position,&offset))
                || offset<0) return io->result=-EINVAL;
        if (!offset && md_proc_file_process(f->kind)) { free(f->content); f->content=NULL; f->content_size=0; }
        f->position=offset; return io->result=offset;
    }
    if (!io->positional) io->offset=f->position;
    if (io->offset<0) return io->result=-EINVAL;
    if (io->operation==MD_PROC_FILE_GETDENTS) {
        if (capacity && !bytes) return io->result=-EFAULT;
        return io->result=directory_entries(io,bytes,capacity);
    }
    if (io->operation==MD_PROC_FILE_WRITE) {
        /* Reject impossible proc writes before copying or allocating input. */
        size_t limit=f->kind==MD_PROC_FILE_SETGROUPS ? 8 : page_size;
        if ((f->flags&O_PATH) || (f->flags&O_ACCMODE)==O_RDONLY) return io->result=-EBADF;
        int sysctl=md_proc_file_sysctl(f->kind);
        if (!sysctl && (io->offset || io->length>=limit)) return io->result=-EINVAL;
        size_t required=sysctl && io->length>64 ? 64 : io->length;
        if (required>capacity || (required && !bytes)) return io->result=-EFAULT;
        int64_t next=io->offset;
        io->result=sysctl ? md_proc_sysctl_write(uts,f->kind,writer,bytes,io->length,&next)
            : md_proc_file_write_at(f,writer,uts,bytes,io->length,io->offset,page_size);
        if (io->result>0 && !io->positional) f->position=sysctl ? next : io->offset+io->result;
    } else {
        size_t length=io->length<capacity ? io->length : capacity;
        if (length && !bytes) return io->result=-EFAULT;
        io->result=md_proc_file_read_at(f,uts,bytes,length,io->offset);
    }
    return io->result;
}
int md_proc_file_io_offer(struct md_proc_file_io *io) {
    if (!io || !io->file || !io->executed || io->offered
            || md_resource_order_state(&io->turn)!=MD_RESOURCE_ORDER_RUNNING) return -EINVAL;
    io->offered=1; return 0;
}
int md_proc_file_io_finish(struct md_proc_file_io *io, long copied) {
    if (!io || !io->file || !io->executed) return -EINVAL;
    if (io->operation==MD_PROC_FILE_READ && io->result>=0) {
        if (copied>io->result || (copied>0 && !io->offered)) return -EINVAL;
        if (copied>0 && !io->positional) io->file->position=io->offset+copied;
    }
    if (io->operation==MD_PROC_FILE_GETDENTS && io->result>=0) {
        if (copied>0 && (!io->offered || copied!=io->result)) return -EINVAL;
        if (copied>0) io->file->position=io->next_position;
    }
    int error=md_resource_order_complete(&io->turn);
    if (io->turn.queue) return error;
    md_proc_file_release(io->file); *io=(struct md_proc_file_io){0}; return error;
}
int md_proc_file_io_cancel(struct md_proc_file_io *io) {
    if (!io || !io->file) return 0;
    int error=md_resource_order_cancel(&io->turn);
    if (error==1) return md_proc_file_io_finish(io,io->offered && io->result>0 ? io->result : 0);
    if (io->turn.queue) return error;
    md_proc_file_release(io->file); *io=(struct md_proc_file_io){0}; return error;
}

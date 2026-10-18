#define _GNU_SOURCE
#include "fs_mount_internal.h"
#include "fs_continuation.h"
#include "fuse_device.h"
#include "fuse_transport.h"
#include "proc_file.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

static unsigned requests;
static unsigned releases;
static char contents[32768]="initial contents";
static size_t content_size=42;
static struct { char name[256]; uint64_t node; mode_t mode; } entries[16];
static uint64_t next_node=10;
static char attribute[256];
static size_t attribute_size;
static int attribute_present,malformed_names;
static int capture(void *context,const struct md_control_file_ops *ops,void *node,
        const struct md_identity *id,int flags) {
    (void)id;
    void *opened=ops->open(node,flags); if (!opened) return -errno;
    *(struct md_control_file *)context=(struct md_control_file){ops,opened}; return 0;
}
static struct fuse_attr attr(uint64_t node) {
    for (unsigned i=0;i<16;++i) if (entries[i].node==node)
        return (struct fuse_attr){.ino=node,.mode=entries[i].mode,.nlink=1,.blksize=4096};
    return (struct fuse_attr){.ino=node,.mode=(node==1 ? S_IFDIR|0755 : node==3 ? S_IFLNK|0777 : S_IFREG|0644),
        .nlink=1,.uid=0,.gid=0,.size=node==2 ? content_size : 0,.blksize=4096};
}
static unsigned serve(struct md_fuse_connection *connection) {
    union { uint64_t align; char data[65536]; } input,output;
    long n=md_fuse_connection_read(connection,input.data,sizeof(input.data));
    if (n==-EAGAIN) return 0;
    assert(n>=(long)sizeof(struct fuse_in_header));
    struct fuse_in_header *h=(void *)input.data;
    assert(h->len==(unsigned)n && !h->uid && !h->gid);
    md_fuse_connection_read_commit(connection,n); ++requests;
    struct fuse_out_header *out=(void *)output.data;
    *out=(struct fuse_out_header){.len=sizeof(*out),.unique=h->unique};
    void *payload=out+1;
    switch (h->opcode) {
    case FUSE_INIT: {
        struct fuse_init_out init={.major=7,.minor=38,.max_write=16384};
        memcpy(payload,&init,sizeof(init)); out->len+=sizeof(init); break;
    }
    case FUSE_LOOKUP: {
        const char *name=(const char *)(h+1);
        struct fuse_entry_out entry={.generation=1};
        entry.nodeid=!strcmp(name,"file") ? 2 : !strcmp(name,"link") ? 3 : 0;
        if (!strncmp(name,"bulk-",5)) entry.nodeid=1000+strtoul(name+5,NULL,10);
        for (unsigned i=0;i<16;++i) if (!strcmp(entries[i].name,name)) entry.nodeid=entries[i].node;
        if (!entry.nodeid) out->error=-ENOENT;
        else { entry.attr=attr(entry.nodeid); memcpy(payload,&entry,sizeof(entry)); out->len+=sizeof(entry); }
        break;
    }
    case FUSE_GETATTR: {
        struct fuse_attr_out result={.attr=attr(h->nodeid)};
        memcpy(payload,&result,sizeof(result)); out->len+=sizeof(result); break;
    }
    case FUSE_READLINK: memcpy(payload,"file",4); out->len+=4; break;
    case FUSE_CREATE: case FUSE_MKDIR: case FUSE_SYMLINK: case FUSE_LINK: {
        const char *name=(const void *)(h+1); mode_t mode=0; uint64_t node=next_node++;
        if (h->opcode==FUSE_CREATE) { const struct fuse_create_in *in=(const void *)name;
            mode=in->mode; name=(const void *)(in+1); }
        else if (h->opcode==FUSE_MKDIR) { const struct fuse_mkdir_in *in=(const void *)name;
            mode=in->mode; name=(const void *)(in+1); }
        else if (h->opcode==FUSE_LINK) { const struct fuse_link_in *in=(const void *)name;
            node=in->oldnodeid; mode=attr(node).mode; name=(const void *)(in+1); }
        else mode=S_IFLNK|0777;
        unsigned slot=0; while (slot<16 && entries[slot].node) ++slot; assert(slot<16);
        entries[slot].node=node; entries[slot].mode=mode; strcpy(entries[slot].name,name);
        struct fuse_entry_out entry={.nodeid=node,.generation=1,.attr=attr(node)};
        memcpy(payload,&entry,sizeof(entry)); out->len+=sizeof(entry);
        if (h->opcode==FUSE_CREATE) { struct fuse_open_out opened={.fh=node*10};
            memcpy(output.data+out->len,&opened,sizeof(opened)); out->len+=sizeof(opened); }
        break;
    }
    case FUSE_UNLINK: case FUSE_RMDIR: {
        const char *name=(const void *)(h+1); int found=0;
        for (unsigned i=0;i<16;++i) if (entries[i].node && !strcmp(entries[i].name,name)) {
            entries[i].node=0; *entries[i].name=0; found=1; break;
        }
        if (!found) out->error=-ENOENT;
        break;
    }
    case FUSE_RENAME: case FUSE_RENAME2: {
        const char *name=(const char *)(h+1)+(h->opcode==FUSE_RENAME ? sizeof(struct fuse_rename_in) : sizeof(struct fuse_rename2_in));
        const char *target=name+strlen(name)+1; int found=0;
        for (unsigned i=0;i<16;++i) if (entries[i].node && !strcmp(entries[i].name,name)) {
            strcpy(entries[i].name,target); found=1; break;
        }
        if (!found) out->error=-ENOENT;
        break;
    }
    case FUSE_SETATTR: {
        const struct fuse_setattr_in *in=(const void *)(h+1);
        if (in->valid&FATTR_SIZE) {
            assert(in->fh==h->nodeid*10 && (in->valid&FATTR_FH) && in->size<=sizeof(contents));
            content_size=in->size;
        }
        for (unsigned i=0;i<16;++i) if (entries[i].node==h->nodeid && (in->valid&FATTR_MODE)) entries[i].mode=in->mode;
        struct fuse_attr_out result={.attr=attr(h->nodeid)};
        if (in->valid&FATTR_SIZE) result.attr.size=in->size;
        memcpy(payload,&result,sizeof(result)); out->len+=sizeof(result); break;
    }
    case FUSE_FSYNC: case FUSE_FSYNCDIR: {
        const struct fuse_fsync_in *in=(const void *)(h+1);
        assert(in->fh==h->nodeid*10 && in->fsync_flags<=1);
        if (in->fsync_flags) out->error=-ENOSYS;
        break;
    }
    case FUSE_ACCESS: break;
    case FUSE_SETXATTR: {
        const uint32_t *words=(const void *)(h+1);
        const char *name=(const char *)(h+1)+8;
        assert(!strcmp(name,"user.test") && words[0]<=sizeof(attribute));
        if ((words[1]&1) && attribute_present) out->error=-EEXIST;
        else if ((words[1]&2) && !attribute_present) out->error=-ENODATA;
        else { attribute_size=words[0]; attribute_present=1;
            memcpy(attribute,name+strlen(name)+1,attribute_size); }
        break;
    }
    case FUSE_GETXATTR: case FUSE_LISTXATTR: {
        const struct fuse_getxattr_in *in=(const void *)(h+1);
        int list=h->opcode==FUSE_LISTXATTR;
        const char *name=(const void *)(in+1);
        if (!list && !strcmp(name,"user.unsupported")) { out->error=-ENOSYS; break; }
        if (!list && !attribute_present) { out->error=-ENODATA; break; }
        size_t size=list ? (attribute_present ? sizeof("user.test") : 0) : attribute_size;
        if (!in->size) { struct fuse_getxattr_out result={.size=size};
            memcpy(payload,&result,sizeof(result)); out->len+=sizeof(result); }
        else if (in->size<size) out->error=-ERANGE;
        else { memcpy(payload,list ? "user.test" : attribute,size); out->len+=size;
            if (list && malformed_names && size) ((char *)payload)[size-1]='x'; }
        break;
    }
    case FUSE_REMOVEXATTR:
        if (!attribute_present) out->error=-ENODATA;
        else attribute_present=0;
        break;
    case FUSE_STATFS: {
        struct fuse_statfs_out result={.st={.blocks=100,.bfree=50,.bavail=40,.files=10,.ffree=5,.bsize=4096,.namelen=255,.frsize=4096}};
        memcpy(payload,&result,sizeof(result)); out->len+=sizeof(result); break;
    }
    case FUSE_OPEN: case FUSE_OPENDIR: {
        struct fuse_open_out result={.fh=h->nodeid*10};
        memcpy(payload,&result,sizeof(result)); out->len+=sizeof(result); break;
    }
    case FUSE_READ: {
        const struct fuse_read_in *in=(const void *)(h+1);
        assert(in->fh==20 && in->size<=16384);
        size_t size=in->offset>=content_size ? 0 : content_size-in->offset;
        if (size>in->size) size=in->size;
        memcpy(payload,contents+((in->offset<content_size) ? in->offset : 0),size); out->len+=size; break;
    }
    case FUSE_WRITE: {
        const struct fuse_write_in *in=(const void *)(h+1);
        assert(in->fh==20 && in->size<=16384 && in->offset+in->size<=sizeof(contents));
        assert(n==(long)(sizeof(*h)+sizeof(*in)+in->size));
        memcpy(contents+in->offset,in+1,in->size);
        if (content_size<in->offset+in->size) content_size=in->offset+in->size;
        struct fuse_write_out result={.size=in->size};
        memcpy(payload,&result,sizeof(result)); out->len+=sizeof(result); break;
    }
    case FUSE_READDIR: {
        const struct fuse_read_in *in=(const void *)(h+1);
        const char *names[]={".","..","file","link"};
        for (uint64_t i=in->offset;i<4;++i) {
            struct fuse_dirent *d=(void *)(output.data+out->len);
            *d=(struct fuse_dirent){.ino=i<2 ? 1 : i,.off=i+1,.namelen=strlen(names[i]),.type=i<2 ? 4 : i==2 ? 8 : 10};
            memcpy(d->name,names[i],d->namelen); out->len+=FUSE_DIRENT_SIZE(d);
        }
        break;
    }
    case FUSE_RELEASE: case FUSE_RELEASEDIR: ++releases; break;
    case FUSE_FORGET: return h->opcode;
    default: assert(!"unexpected FUSE request");
    }
    assert(md_fuse_connection_write(connection,output.data,out->len)==out->len);
    return h->opcode;
}
static struct md_fs_result run_request(struct md_fs_context *context,struct md_fuse_connection *connection,
        const struct md_fs_request *q,struct md_fs_output output) {
    struct md_fs_continuation *pending=NULL;
    output.continuation=&pending;
    struct md_fs_result r; md_fs_context_execute(context,q,&r,&output);
    for (unsigned step=0;r.error==-EINPROGRESS;++step) {
        assert(step<64 && pending);
        if (!pending->ready(pending)) assert(serve(connection));
        assert(pending->ready(pending));
        struct md_fs_continuation *old=pending; pending=NULL;
        md_fs_context_resume(context,old,&r,&output);
        assert(md_fs_continuation_pending(old,&pending,&r)==(r.error==-EINPROGRESS));
    }
    assert(!pending); return r;
}
static struct md_fs_result run(struct md_fs_context *context,struct md_fuse_connection *connection,
        unsigned operation,const char *path,unsigned flags,void *data,size_t capacity) {
    struct md_fs_request q={.operation=operation,.directory={-1,-1},.path={path,NULL},.flags=flags};
    return run_request(context,connection,&q,(struct md_fs_output){.data=data,.capacity=capacity});
}
static int capture_file(void *context,const struct md_control_file_ops *ops,void *node,
        const struct md_identity *id,int flags) {
    struct md_proc_file *file=md_proc_file_open_control(ops,node,id,flags);
    if (!file) return -errno;
    *(struct md_proc_file **)context=file; return 0;
}
static long io(struct md_proc_file *file,struct md_fs_context *context,struct md_fuse_connection *connection,
        enum md_proc_file_operation operation,void *data,size_t size,long acknowledge) {
    struct md_proc_file_io io={0};
    assert(md_proc_file_io_begin(&io,file,operation,0,0,0,size,NULL)==1);
    io.actor=(struct md_control_actor){.identity=&context->task.identity};
    long result=md_proc_file_io_execute(&io,&context->task.identity,NULL,data,size,4096);
    assert(result==-EINPROGRESS && io.pending);
    assert(serve(connection));
    result=md_proc_file_io_execute(&io,&context->task.identity,NULL,data,size,4096);
    assert(result>=0 && !io.pending);
    assert(!md_proc_file_io_offer(&io));
    assert(!md_proc_file_io_finish(&io,acknowledge<0 ? result : acknowledge));
    return result;
}
static long position(struct md_proc_file *file) {
    struct md_proc_file_io io={0};
    assert(md_proc_file_io_begin(&io,file,MD_PROC_FILE_SEEK,0,0,SEEK_CUR,0,NULL)==1);
    long result=md_proc_file_io_execute(&io,NULL,NULL,NULL,0,4096);
    assert(!md_proc_file_io_finish(&io,0)); return result;
}
static void command(struct md_proc_file *file,struct md_fs_context *context,
        struct md_fuse_connection *connection,unsigned command,int64_t value) {
    long before=position(file);
    struct md_proc_file_io io={0};
    assert(md_proc_file_io_begin(&io,file,MD_PROC_FILE_COMMAND,0,value,command,0,NULL)==1);
    io.actor=(struct md_control_actor){.identity=&context->task.identity};
    assert(md_proc_file_io_execute(&io,&context->task.identity,NULL,NULL,0,4096)==-EINPROGRESS);
    assert(serve(connection));
    assert(md_proc_file_io_execute(&io,&context->task.identity,NULL,NULL,0,4096)==0);
    assert(!md_proc_file_io_offer(&io) && !md_proc_file_io_finish(&io,0));
    assert(position(file)==before);
}
static int mapping(struct md_proc_file *file,struct md_fs_context *context,struct md_fuse_connection *connection) {
    struct md_control_file control=md_proc_file_control(file);
    struct md_control_actor actor={.identity=&context->task.identity};
    struct md_control_pending *pending=NULL;
    assert(control.ops->mapping(control.context,&actor,PROT_READ,MAP_SHARED,&pending)==-EOPNOTSUPP && !pending);
    assert(control.ops->mapping(control.context,&actor,PROT_READ,MAP_PRIVATE,&pending)==-EINPROGRESS && pending);
    long result;
    for (;;) {
        while (serve(connection)) {}
        result=pending->resume(pending,NULL,0);
        if (result!=-EINPROGRESS) break;
    }
    pending->dispose(pending);
    assert(result>=0); return (int)result;
}
static void files(struct md_fs_context *context,struct md_fuse_connection *connection) {
    char link[PATH_MAX];
    assert(run(context,connection,MD_FS_READLINK,"/fuse",0,link,sizeof(link)).error==-EINVAL);
    assert(run(context,connection,MD_FS_READLINK,"/fuse/file",0,link,sizeof(link)).error==-EINVAL);
    struct md_fs_anchor *origin=NULL;
    struct md_fs_request path={.operation=MD_FS_TASK_PATH,.directory={-1,-1},
        .path={"/fuse",NULL},.mode=MD_FS_TASK_CHDIR};
    struct md_fs_result opened=run_request(context,connection,&path,(struct md_fs_output){.origin=&origin});
    assert(!opened.error && opened.fd>=0 && origin);
    assert((fcntl(opened.fd,F_GETFL)&O_PATH)==O_PATH);
    close(opened.fd); md_fs_anchor_release(origin);
    struct md_proc_file *file=NULL;
    struct md_fs_request q={.operation=MD_FS_OPEN,.directory={-1,-1},.path={"/fuse/file",NULL},.flags=O_RDWR};
    struct md_fs_result r=run_request(context,connection,&q,(struct md_fs_output){.control=capture_file,.control_context=&file});
    assert(!r.error && r.fd>=0 && file); close(r.fd);
    char data[32768]={0};
    assert(io(file,context,connection,MD_PROC_FILE_READ,data,7,2)==7 && !memcmp(data,"initial",7));
    assert(position(file)==2);
    memset(data,'W',sizeof(data));
    assert(io(file,context,connection,MD_PROC_FILE_WRITE,data,sizeof(data),0)==16384);
    assert(position(file)==16386 && contents[0]=='i' && contents[1]=='n' && contents[2]=='W');
    command(file,context,connection,MD_CONTROL_TRUNCATE,6);
    assert(content_size==6);
    command(file,context,connection,MD_CONTROL_SYNC,0);
    command(file,context,connection,MD_CONTROL_DATASYNC,0);
    int snapshot=mapping(file,context,connection);
    char mapped[6]; assert(pread(snapshot,mapped,sizeof(mapped),0)==sizeof(mapped));
    assert(!memcmp(mapped,contents,sizeof(mapped)));
    unsigned before=requests;
    int copy=mapping(file,context,connection);
    assert(requests==before+1); /* fresh GETATTR, same sealed snapshot */
    close(copy);
    assert(io(file,context,connection,MD_PROC_FILE_WRITE,"Z",1,0)==1);
    copy=mapping(file,context,connection);
    assert(pread(copy,mapped,sizeof(mapped),0)==sizeof(mapped) && !memcmp(mapped,contents,sizeof(mapped)));
    close(copy);
    /* Notify invalidation must also defeat the cache when attrs are unchanged. */
    struct { struct fuse_out_header header; struct fuse_notify_inval_inode_out inode; } notification={
        .header={.len=sizeof(notification),.error=FUSE_NOTIFY_INVAL_INODE},.inode={.ino=2,.off=0,.len=0}};
    contents[0]='N';
    assert(md_fuse_connection_write(connection,&notification,sizeof(notification))==sizeof(notification));
    copy=mapping(file,context,connection);
    assert(pread(copy,mapped,sizeof(mapped),0)==sizeof(mapped) && !memcmp(mapped,contents,sizeof(mapped)));
    assert(pread(snapshot,mapped,sizeof(mapped),0)==sizeof(mapped) && mapped[0]!='N');
    close(copy); close(snapshot);
    md_proc_file_release(file); file=NULL;
    assert(serve(connection)==FUSE_RELEASE && releases==1);
    q.path[0]="/fuse"; q.flags=O_RDONLY|O_DIRECTORY;
    r=run_request(context,connection,&q,(struct md_fs_output){.control=capture_file,.control_context=&file});
    assert(!r.error && r.fd>=0 && file); close(r.fd);
    assert(io(file,context,connection,MD_PROC_FILE_GETDENTS,data,24,-1)==24 && position(file)==1);
    assert(io(file,context,connection,MD_PROC_FILE_GETDENTS,data,sizeof(data),0)>0 && position(file)==1);
    assert(io(file,context,connection,MD_PROC_FILE_GETDENTS,data,sizeof(data),-1)>0 && position(file)==4);
    assert(io(file,context,connection,MD_PROC_FILE_GETDENTS,data,sizeof(data),-1)==0);
    md_proc_file_release(file);
    assert(serve(connection)==FUSE_RELEASEDIR && releases==2);
}
static void carrier_capacity(struct md_fs_context *context,struct md_fuse_connection *connection) {
    struct rlimit saved;
    assert(!getrlimit(RLIMIT_NOFILE,&saved));
    struct rlimit bounded=saved; if (bounded.rlim_cur>256) bounded.rlim_cur=256;
    assert(!setrlimit(RLIMIT_NOFILE,&bounded));
    for (unsigned i=0;i<1024;++i) {
        char path[64]; snprintf(path,sizeof(path),"/fuse/bulk-%u",i);
        struct md_fs_result result=run(context,connection,MD_FS_STAT,path,0,NULL,0);
        assert(!result.error && result.info.inode==1000+i);
    }
    assert(!setrlimit(RLIMIT_NOFILE,&saved));
    puts("PASS FUSE carrier capacity: 1024 nodes with 256 native descriptors");
}
static void mutations(struct md_fs_context *context,struct md_fuse_connection *connection) {
    struct md_proc_file *file=NULL;
    struct md_fs_request q={.operation=MD_FS_OPEN,.directory={-1,-1},.path={"/fuse/created",NULL},
        .flags=O_RDWR|O_CREAT|O_EXCL,.mode=0666,.attributes={.creation_mask=0022}};
    struct md_fs_result r=run_request(context,connection,&q,(struct md_fs_output){.control=capture_file,.control_context=&file});
    if (r.error) fprintf(stderr,"FUSE create: %d\n",r.error);
    assert(!r.error && r.fd>=0 && file && md_proc_file_filesystem_paths(file)); close(r.fd);
    md_proc_file_release(file); assert(serve(connection)==FUSE_RELEASE);
    r=run(context,connection,MD_FS_STAT,"/fuse/created",0,NULL,0); assert(!r.error && (r.info.mode&0777)==0644);
    q=(struct md_fs_request){.operation=MD_FS_CHMOD,.directory={-1,-1},.path={"/fuse/created",NULL},.mode=0600};
    r=run_request(context,connection,&q,(struct md_fs_output){0}); assert(!r.error);
    r=run(context,connection,MD_FS_STAT,"/fuse/created",0,NULL,0); assert(!r.error && (r.info.mode&0777)==0600);
    uint64_t ino=r.info.inode;
    q=(struct md_fs_request){.operation=MD_FS_RENAME,.directory={-1,-1},.path={"/fuse/created","/fuse/renamed"}};
    r=run_request(context,connection,&q,(struct md_fs_output){0}); assert(!r.error);
    r=run(context,connection,MD_FS_STAT,"/fuse/created",0,NULL,0); assert(r.error==-ENOENT);
    r=run(context,connection,MD_FS_STAT,"/fuse/renamed",0,NULL,0); assert(!r.error && r.info.inode==ino);
    q=(struct md_fs_request){.operation=MD_FS_LINK,.directory={-1,-1},.path={"/fuse/renamed","/fuse/alias"}};
    r=run_request(context,connection,&q,(struct md_fs_output){0}); assert(!r.error);
    r=run(context,connection,MD_FS_STAT,"/fuse/alias",0,NULL,0); assert(!r.error && r.info.inode==ino);
    r=run(context,connection,MD_FS_UNLINK,"/fuse/alias",0,NULL,0); assert(!r.error);
    r=run(context,connection,MD_FS_UNLINK,"/fuse/renamed",0,NULL,0); assert(!r.error);
    q=(struct md_fs_request){.operation=MD_FS_MKDIR,.directory={-1,-1},.path={"/fuse/directory",NULL},.mode=0700};
    r=run_request(context,connection,&q,(struct md_fs_output){0}); assert(!r.error);
    r=run(context,connection,MD_FS_STAT,"/fuse/directory",0,NULL,0); assert(!r.error && S_ISDIR(r.info.mode));
    r=run(context,connection,MD_FS_UNLINK,"/fuse/directory",AT_REMOVEDIR,NULL,0); assert(!r.error);
    q=(struct md_fs_request){.operation=MD_FS_SYMLINK,.directory={-1,-1},.path={"/fuse/newlink","file"}};
    r=run_request(context,connection,&q,(struct md_fs_output){0}); assert(!r.error);
    r=run(context,connection,MD_FS_STAT,"/fuse/newlink",0,NULL,0); assert(!r.error && r.info.inode==2);
    r=run(context,connection,MD_FS_UNLINK,"/fuse/newlink",0,NULL,0); assert(!r.error);
}
static void xattrs(struct md_fs_context *context,struct md_fuse_connection *connection) {
    char data[256];
    struct md_fs_output output={.data=data,.capacity=sizeof(data)};
    struct md_fs_request q={.operation=MD_FS_XATTR,.directory={-1,-1},
        .path={"/fuse/file","user.test"},.mode=MD_FS_XATTR_SET,
        .flags=1,.value="value",.value_size=5,.capacity=5};
    struct md_fs_result r=run_request(context,connection,&q,output); assert(!r.error);
    r=run_request(context,connection,&q,output); assert(r.error==-EEXIST);
    q.mode=MD_FS_XATTR_GET; q.flags=0; q.value=NULL; q.value_size=q.capacity=0;
    r=run_request(context,connection,&q,output); assert(!r.error && r.position==5 && !r.size);
    q.capacity=2;
    r=run_request(context,connection,&q,output); assert(r.error==-ERANGE);
    q.capacity=sizeof(data);
    r=run_request(context,connection,&q,output); assert(!r.error && r.size==5 && !memcmp(data,"value",5));
    q.path[1]="user.unsupported";
    r=run_request(context,connection,&q,output); assert(r.error==-EOPNOTSUPP);
    q.mode=MD_FS_XATTR_LIST; q.path[1]="";
    r=run_request(context,connection,&q,output); assert(!r.error && r.size==sizeof("user.test") && !strcmp(data,"user.test"));
    malformed_names=1;
    r=run_request(context,connection,&q,output); assert(r.error==-EPROTO);
    malformed_names=0;
    q.mode=MD_FS_XATTR_REMOVE; q.path[1]="user.test"; q.capacity=0;
    r=run_request(context,connection,&q,output); assert(!r.error);
    q.mode=MD_FS_XATTR_GET;
    r=run_request(context,connection,&q,output); assert(r.error==-ENODATA);
}
static void notifications(struct md_fs_context *context,struct md_fuse_connection *connection) {
    struct {
        struct fuse_out_header header;
        struct fuse_notify_inval_inode_out inode;
    } inode={.header={.len=sizeof(inode),.error=FUSE_NOTIFY_INVAL_INODE},.inode={.ino=2,.off=0,.len=0}};
    assert(md_fuse_connection_write(connection,&inode,sizeof(inode))==sizeof(inode));
    inode.inode.ino=99999;
    assert(md_fuse_connection_write(connection,&inode,sizeof(inode))==-ENOENT);
    struct {
        struct fuse_out_header header;
        struct fuse_notify_inval_entry_out entry;
        char name[5];
    } entry={.header={.error=FUSE_NOTIFY_INVAL_ENTRY},.entry={.parent=1,.namelen=4},.name="file"};
    size_t size=offsetof(__typeof__(entry),name)+5; entry.header.len=size;
    assert(md_fuse_connection_write(connection,&entry,size)==(long)size);
    struct md_fs_result r=run(context,connection,MD_FS_STAT,"/fuse/file",0,NULL,0);
    assert(!r.error && r.info.inode==2);
    entry.name[4]='x';
    assert(md_fuse_connection_write(connection,&entry,size)==-EINVAL);
    entry.header.error=FUSE_NOTIFY_STORE;
    assert(md_fuse_connection_write(connection,&entry,size)==-EOPNOTSUPP);
    r=run(context,connection,MD_FS_STAT,"/fuse/file",0,NULL,0);
    assert(!r.error);
}
void md_test_fuse_filesystem(struct md_filesystem *fs) {
    struct md_fs_context context={.filesystem=fs,.has_identity=1,.task={.identity=md_identity_new(0,0)}};
    struct md_fs_request q={.operation=MD_FS_MKDIR,.directory={-1,-1},.path={"/fuse",NULL},.mode=0755};
    struct md_fs_result r; md_fs_context_execute(&context,&q,&r,NULL); assert(!r.error);
    struct md_control_file device={0};
    q=(struct md_fs_request){.operation=MD_FS_OPEN,.directory={-1,-1},.path={"/dev/fuse",NULL},.flags=O_RDWR};
    struct md_fs_output output={.control=capture,.control_context=&device};
    md_fs_context_execute(&context,&q,&r,&output); assert(!r.error && r.fd>=0 && device.ops);
    int fd=r.fd;
    char options[128]; snprintf(options,sizeof(options),"fd=%d,rootmode=40000,user_id=0,group_id=0",fd);
    q=(struct md_fs_request){.operation=MD_FS_MOUNT,.mode=MD_FS_MOUNT_FUSE,.directory={-1,fd},
        .path={"/fuse",""},.control=device,.value=options,.value_size=strlen(options)+1};
    assert(!md_fs_request_validate(&q));
    md_fs_context_execute(&context,&q,&r,NULL);
    if (r.error) fprintf(stderr,"FUSE mount: %d\n",r.error);
    assert(!r.error); close(fd);
    struct md_fuse_connection *connection=md_fuse_device_connection(device); assert(connection);
    r=run(&context,connection,MD_FS_STAT,"/fuse",0,NULL,0); assert(!r.error && S_ISDIR(r.info.mode));
    r=run(&context,connection,MD_FS_STAT,"/fuse/file",0,NULL,0); assert(!r.error && r.info.size==42 && r.info.inode==2);
    r=run(&context,connection,MD_FS_STAT,"/fuse/link",0,NULL,0); assert(!r.error && r.info.size==42);
    r=run(&context,connection,MD_FS_STAT,"/fuse/link",AT_SYMLINK_NOFOLLOW,NULL,0); assert(!r.error && S_ISLNK(r.info.mode));
    char link[128]; r=run(&context,connection,MD_FS_READLINK,"/fuse/link",0,link,sizeof(link));
    assert(!r.error && r.size==4 && !memcmp(link,"file",4));
    r=run(&context,connection,MD_FS_STAT,"/fuse/absent",0,NULL,0); assert(r.error==-ENOENT);
    struct md_fs_statfs statfs;
    r=run(&context,connection,MD_FS_STATFS,"/fuse",0,&statfs,sizeof(statfs));
    assert(!r.error && statfs.type==FUSE_SUPER_MAGIC && statfs.available_blocks==40);
    /* Until an operation has a protocol implementation it cannot use carriers. */
    r=run(&context,connection,MD_FS_OPEN,"/fuse/file",O_RDONLY,NULL,0); assert(r.error==-EOPNOTSUPP && r.fd<0);
    files(&context,connection);
    carrier_capacity(&context,connection);
    mutations(&context,connection);
    xattrs(&context,connection);
    notifications(&context,connection);
    q=(struct md_fs_request){.operation=MD_FS_STAT,.directory={-1,-1},.path={"/fuse/file",NULL}};
    struct md_fs_continuation *pending=NULL; output=(struct md_fs_output){.continuation=&pending};
    md_fs_context_execute(&context,&q,&r,&output); assert(r.error==-EINPROGRESS && pending);
    md_control_file_release(device);
    assert(pending->ready(pending));
    struct md_fs_continuation *old=pending; pending=NULL;
    md_fs_context_resume(&context,old,&r,&output);
    assert(!md_fs_continuation_pending(old,&pending,&r) && r.error==-ECONNABORTED);
    r=run(&context,NULL,MD_FS_STAT,"/",0,NULL,0); assert(!r.error);
    md_fs_context_end(&context);
    printf("PASS FUSE filesystem: mount, INIT, lookup, symlinks, metadata, statfs and daemon exit (%u packets)\n",requests);
}

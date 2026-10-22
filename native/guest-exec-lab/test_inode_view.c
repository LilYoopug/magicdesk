#define _GNU_SOURCE
#include "inode_internal.h"
#include "inode_view.h"
#include "inode_overlay.h"
#include "inode_custody.h"
#include "inode_xattr.h"
#include "inode_watch.h"
#include "fs_operation.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/xattr.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/inotify.h>
#include <unistd.h>

static unsigned views(struct md_inode_store *s) {
    assert(!mdi_begin(s,0));
    sqlite3_stmt *q=NULL;
    assert(!mdi_prepare(s,"SELECT count(*) FROM inode_views",&q));
    assert(mdi_step(s,q)==SQLITE_ROW);
    unsigned count=(unsigned)sqlite3_column_int(q,0);
    sqlite3_finalize(q); assert(!mdi_finish(s,0)); return count;
}
static void collect(struct md_inode_store *s) {
    assert(!mdi_begin(s,1));
    assert(!mdi_views_collect(s));
    assert(!mdi_commit(s,0));
}
static void text(int fd, const char *expected) {
    char data[32]; ssize_t n=pread(fd,data,sizeof(data),0);
    assert(n==(ssize_t)strlen(expected) && !memcmp(data,expected,(size_t)n));
}
static int listed(const char *names,size_t size,const char *name) {
    unsigned count=0;
    for (size_t at=0;at<size;at+=strlen(names+at)+1) count+=!strcmp(names+at,name);
    assert(count<=1); return count;
}
static int watched(struct md_inode_store *s,int watcher,const char *name,unsigned mask) {
    char data[8192];
    ssize_t size=md_inode_watch_read(s,watcher,data,sizeof(data),NULL,NULL);
    if (size==-EAGAIN) return 0;
    assert(size>=0); int found=0;
    for (size_t at=0;at<(size_t)size;) {
        const struct inotify_event *e=(const void *)(data+at);
        if ((e->mask&mask) && e->len && !strcmp(e->name,name)) ++found;
        at+=sizeof(*e)+e->len;
    }
    return found;
}
static void control_attributes(struct md_inode_store *s) {
    int fd=md_inode_open(s,-1,"/attributes",O_CREAT|O_RDWR,0600); assert(fd>=0);
    assert(!fsetxattr(fd,"user.overlay.opaque","y",1,0));
    struct mdi_node node;
    assert(!mdi_begin(s,1) && !mdi_fd(s,fd,&node));
    assert(!mdi_xattr_virtual_set(s,&node,"user.overlay.opaque",NULL,0));
    assert(mdi_xattr_get(s,&node,"user.overlay.opaque",NULL,0)==-ENODATA);
    assert(mdi_commit(s,-ECANCELED)==-ECANCELED);
    assert(!mdi_begin(s,0));
    char data[512];
    assert(mdi_xattr_get(s,&node,"user.overlay.opaque",data,sizeof(data))==1 && data[0]=='y');
    assert(!mdi_finish(s,0));
    struct md_identity root=md_identity_new(0,0);
    s->identity=&root;
    struct md_fs_request q={.operation=MD_FS_XATTR_OBJECT,.directory={fd,-1},
        .path={NULL,"user.overlay.opaque"},.mode=MD_FS_XATTR_REMOVE};
    struct md_fs_output output={.data=data,.capacity=sizeof(data)};
    struct md_fs_result result={.fd=-1};
    struct md_fs_request label={.operation=MD_FS_XATTR_OBJECT,.directory={fd,-1},
        .path={NULL,"security.selinux"},.mode=MD_FS_XATTR_GET,.capacity=sizeof(data)};
    md_inode_xattr(s,&label,&result,&output); assert(result.error==-ENODATA);
    label.mode=MD_FS_XATTR_SET; label.value="label"; label.value_size=5; label.capacity=5;
    md_inode_xattr(s,&label,&result,NULL); assert(result.error==-EOPNOTSUPP);
    label.mode=MD_FS_XATTR_REMOVE; label.value=NULL; label.value_size=label.capacity=0;
    md_inode_xattr(s,&label,&result,NULL); assert(result.error==-ENODATA);
    md_inode_xattr(s,&q,&result,NULL); assert(!result.error && result.fd<0);
    md_inode_xattr(s,&q,&result,NULL); assert(result.error==-ENODATA);
    q.mode=MD_FS_XATTR_SET; q.flags=XATTR_REPLACE;
    md_inode_xattr(s,&q,&result,NULL); assert(result.error==-ENODATA);
    q.flags=XATTR_CREATE;
    md_inode_xattr(s,&q,&result,NULL); assert(!result.error);
    md_inode_xattr(s,&q,&result,NULL); assert(result.error==-EEXIST);
    q.flags=0; q.path[1]="trusted.overlay.whiteout"; q.value="y"; q.capacity=q.value_size=1;
    md_inode_xattr(s,&q,&result,NULL); assert(!result.error);
    q.path[1]=NULL; q.mode=MD_FS_XATTR_LIST; q.capacity=sizeof(data); q.value_size=0; q.value=NULL;
    md_inode_xattr(s,&q,&result,&output);
    assert(!result.error && result.size>0 && listed(data,result.size,"user.overlay.opaque")
        && listed(data,result.size,"trusted.overlay.whiteout") && !listed(data,result.size,"security.selinux"));
    q.capacity=0;
    size_t length=result.size;
    md_inode_xattr(s,&q,&result,NULL); assert(!result.error && result.position==(ssize_t)length && !result.size);
    q.capacity=(unsigned)length-1;
    md_inode_xattr(s,&q,&result,&output); assert(result.error==-ERANGE && !result.size && !result.position);
    struct md_identity user=md_identity_new(1000,1000); s->identity=&user;
    q.capacity=sizeof(data);
    md_inode_xattr(s,&q,&result,&output);
    assert(!result.error && listed(data,result.size,"user.overlay.opaque") && !listed(data,result.size,"trusted.overlay.whiteout"));
    q.path[1]="trusted.overlay.whiteout"; q.mode=MD_FS_XATTR_GET;
    md_inode_xattr(s,&q,&result,&output); assert(result.error==-ENODATA);
    q.mode=MD_FS_XATTR_REMOVE; q.capacity=0;
    md_inode_xattr(s,&q,&result,NULL); assert(result.error==-EPERM);
    s->identity=NULL; md_identity_release(&user); md_identity_release(&root); close(fd);
    puts("PASS transactional overlay attributes: rollback, tombstones, exact listing, flags and permissions");
}
static void owned_metadata(struct md_inode_store *s,const char *path,uint32_t uid,uint32_t gid,unsigned mode) {
    int fd=md_inode_open(s,-1,path,O_PATH,0); assert(fd>=0);
    struct mdi_node node;
    assert(!mdi_begin(s,1) && !mdi_fd(s,fd,&node));
    assert(!mdi_metadata(s,&node,uid,gid,mode));
    assert(!mdi_commit(s,0)); close(fd);
}
static void trusted_attributes(struct md_inode_store *s) {
    struct md_identity root=md_identity_new(0,0),user=md_identity_new(1000,1000);
    s->identity=&root;
    assert(!md_inode_mkdir(s,-1,"/trusted-files",0755));
    int fd=md_inode_open(s,-1,"/trusted-files/file",O_CREAT|O_RDWR,0600); assert(fd>=0);
    struct mdi_node node;
    assert(!mdi_begin(s,0) && !mdi_fd(s,fd,&node) && node.native);
    assert(!mdi_finish(s,0));
    char name[256]; memset(name,'x',255); memcpy(name,"trusted.",8); name[255]=0;
    char data[1024]; const char value[]={0,'a',-1};
    struct md_fs_output output={.data=data,.capacity=sizeof(data)};
    struct md_fs_result result={.fd=-1};
    struct md_fs_request q={.operation=MD_FS_XATTR_OBJECT,.directory={fd,-1},.path={NULL,name},
        .mode=MD_FS_XATTR_SET,.flags=XATTR_REPLACE,.value=value,.value_size=sizeof(value)};
    md_inode_xattr(s,&q,&result,NULL); assert(result.error==-ENODATA);
    q.flags=XATTR_CREATE;
    md_inode_xattr(s,&q,&result,NULL); assert(!result.error);
    md_inode_xattr(s,&q,&result,NULL); assert(result.error==-EEXIST);
    assert(!mdi_begin(s,0) && !mdi_fd(s,fd,&node) && !node.native);
    assert(!mdi_finish(s,0));
    assert(!md_inode_link(s,-1,"/trusted-files/file",-1,"/trusted-alias",0));
    assert(!md_inode_unlink(s,-1,"/trusted-files/file",0));
    int alias=md_inode_open(s,-1,"/trusted-alias",O_RDONLY,0); assert(alias>=0);
    q.directory[0]=alias; q.mode=MD_FS_XATTR_GET; q.capacity=sizeof(data);
    q.value=NULL; q.value_size=0; q.flags=0;
    md_inode_xattr(s,&q,&result,&output);
    assert(!result.error && result.size==sizeof(value) && !memcmp(data,value,sizeof(value)));
    q.capacity=1; md_inode_xattr(s,&q,&result,&output); assert(result.error==-ERANGE);
    q.capacity=sizeof(data); q.mode=MD_FS_XATTR_LIST; q.path[1]=NULL;
    md_inode_xattr(s,&q,&result,&output); assert(!result.error && listed(data,result.size,name));
    s->identity=&user;
    md_inode_xattr(s,&q,&result,&output); assert(!result.error && !listed(data,result.size,name));
    q.mode=MD_FS_XATTR_GET; q.path[1]=name;
    md_inode_xattr(s,&q,&result,&output); assert(result.error==-ENODATA);
    q.mode=MD_FS_XATTR_REMOVE; q.capacity=0;
    md_inode_xattr(s,&q,&result,NULL); assert(result.error==-EPERM);
    s->identity=&root;
    md_inode_xattr(s,&q,&result,NULL); assert(!result.error);
    q.mode=MD_FS_XATTR_GET; q.directory[0]=fd;
    md_inode_xattr(s,&q,&result,NULL); assert(result.error==-ENODATA);
    close(alias); close(fd); s->identity=NULL;
    md_identity_release(&root); md_identity_release(&user);
    puts("PASS trusted xattrs: native promotion, hardlinks, retained FD, binary value, long name and capabilities");
}
static void overlay_credentials(struct md_inode_store *s) {
    struct md_identity root=md_identity_new(0,0),mounter=md_identity_new(1000,1000);
    uint32_t group=2345;
    assert(!md_identity_groups(&mounter,&group,1));
    s->identity=&root;
    const char *dirs[]={"/policy-lower","/policy-upper","/policy-work"};
    for (unsigned i=0;i<3;++i) {
        assert(!md_inode_mkdir(s,-1,dirs[i],0755));
        owned_metadata(s,dirs[i],1000,1000,i ? 0700 : 0755);
    }
    const char *files[]={"/policy-lower/secret","/policy-lower/owned","/policy-lower/group"};
    for (unsigned i=0;i<3;++i) {
        int fd=md_inode_open(s,-1,files[i],O_CREAT|O_RDWR,0600); assert(fd>=0); close(fd);
    }
    owned_metadata(s,files[1],1000,1000,0666);
    owned_metadata(s,files[2],0,2345,0040);
    assert(!md_inode_mkdir(s,-1,"/policy-upper/sticky",01777));
    owned_metadata(s,"/policy-upper/sticky",0,0,01777);
    int sticky=md_inode_open(s,-1,"/policy-upper/sticky/victim",O_CREAT|O_RDWR,0644);
    assert(sticky>=0); close(sticky);
    owned_metadata(s,"/policy-upper/sticky/victim",2000,2000,0644);
    int lower=md_inode_open(s,-1,dirs[0],O_RDONLY|O_DIRECTORY,0);
    int upper=md_inode_open(s,-1,dirs[1],O_RDONLY|O_DIRECTORY,0);
    int work=md_inode_open(s,-1,dirs[2],O_RDONLY|O_DIRECTORY,0);
    assert(lower>=0 && upper>=0 && work>=0);
    struct md_inode_store *view=NULL;
    assert(!md_inode_view_create(s,MD_FILESYSTEM_OVERLAY,&view));
    assert(!md_inode_overlay_layer(view,s,lower,1));
    assert(!md_inode_overlay_prepare_upper(view,s,upper,work,1));
    assert(!md_inode_overlay_activate(view));
    assert(!md_inode_overlay_stash(view,&mounter));
    assert(!md_identity_groups(&mounter,NULL,0));
    mounter.uid.fs=3000;
    assert(md_inode_open(view,-1,"/secret",O_RDONLY,0)==-EACCES);
    int fd=md_inode_open(view,-1,"/group",O_RDONLY,0); assert(fd>=0); close(fd);
    struct md_fs_request change={.operation=MD_FS_CHMOD,.directory={-1,-1},.path={"/group",NULL},.mode=0666};
    assert(md_inode_metadata(view,&change)==-EPERM);
    change.path[0]="/owned"; change.mode=0660;
    assert(!md_inode_metadata(view,&change));
    change.operation=MD_FS_CHOWN; change.attributes.uid=2345; change.attributes.gid=UINT32_MAX;
    assert(md_inode_metadata(view,&change)==-EPERM);
    fd=md_inode_open(view,-1,"/owned",O_PATH,0); assert(fd>=0);
    struct stat state;
    assert(!md_inode_fstat(view,fd,&state) && state.st_uid==1000 && (state.st_mode&0777)==0660);
    close(fd);
    fd=md_inode_open(view,-1,"/owned",O_RDWR,0); assert(fd>=0);
    assert(write(fd,"ok",2)==2); close(fd);
    owned_metadata(s,"/policy-upper/owned",1000,1000,0000);
    assert(md_inode_open(view,-1,"/owned",O_RDONLY,0)==-EACCES);
    owned_metadata(s,"/policy-upper/owned",1000,1000,0666);
    struct md_identity other=md_identity_new(2000,2000);
    view->identity=&other;
    assert(md_inode_open(view,-1,"/group",O_RDONLY,0)==-EACCES);
    view->identity=&root;
    struct md_inode_custody_parcel parcel={0};
    assert(!md_inode_custody_export(view->lifetime,&parcel) && parcel.count==4);
    struct md_inode_lifetime *lifetime=NULL;
    assert(!md_inode_custody_import(&parcel,s->lifetime->root,&lifetime));
    assert(lifetime->overlay_identity && lifetime->overlay_identity->uid.fs==1000
        && md_identity_in_group(lifetime->overlay_identity,2345));
    md_inode_store_close(view); view=NULL;
    assert(!md_inode_store_reconnect(lifetime,&view));
    md_inode_lifetime_release(lifetime);
    view->identity=&root;
    assert(md_inode_open(view,-1,"/secret",O_RDONLY,0)==-EACCES);
    fd=md_inode_open(view,-1,"/group",O_RDONLY,0); assert(fd>=0); close(fd);
    owned_metadata(s,dirs[1],0,0,0700);
    assert(md_inode_open(view,-1,"/denied",O_CREAT|O_RDWR,0600)==-EACCES);
    assert(md_inode_open(s,-1,"/policy-upper/denied",O_RDONLY,0)==-ENOENT);
    owned_metadata(s,dirs[1],1000,1000,0700);
    assert(md_inode_open(view,-1,"/denied",O_RDONLY,0)==-ENOENT);
    fd=md_inode_open(view,-1,"/allowed",O_CREAT|O_RDWR,0644); assert(fd>=0); close(fd);
    assert(md_inode_unlink(view,-1,"/sticky/victim",0)==-EPERM);
    assert(md_inode_rename(view,-1,"/allowed",-1,"/sticky/victim",0)==-EPERM);
    fd=md_inode_open(view,-1,"/allowed",O_RDONLY,0); assert(fd>=0); close(fd);
    fd=md_inode_open(view,-1,"/sticky/victim",O_RDONLY,0); assert(fd>=0); close(fd);
    fd=md_inode_open(s,-1,"/policy-upper/sticky/victim",O_RDONLY,0); assert(fd>=0); close(fd);
    fd=md_inode_open(view,-1,"/sticky/own",O_CREAT|O_RDWR,0644); assert(fd>=0); close(fd);
    owned_metadata(s,"/policy-upper/sticky/own",1000,1000,0644);
    assert(!md_inode_unlink(view,-1,"/sticky/own",0));
    md_inode_store_close(view);
    close(lower); close(upper); close(work);
    s->identity=NULL;
    md_identity_release(&other); md_identity_release(&mounter); md_identity_release(&root);
    collect(s); assert(views(s)==1);
    puts("PASS overlay credentials: two-sided DAC, captured groups, upper denial, rollback and custody reconnect");
}
static void snapshot_aliases(struct md_inode_store *s, const char *base) {
    char path[PATH_MAX];
    struct md_inode_store *a=NULL,*b=NULL,*c=NULL,*view=NULL;
    snprintf(path,sizeof(path),"%s/shared-source",base);
    assert(!md_inode_store_open(path,1,&a));
    int file=md_inode_open(a,-1,"/file",O_CREAT|O_WRONLY,0600); assert(file>=0);
    assert(write(file,"shared",6)==6); close(file);
    assert(!md_inode_store_seal(a));
    snprintf(path,sizeof(path),"%s/shared-snapshot",base);
    assert(!md_inode_store_open(path,1,&b) && !md_inode_snapshot(a,b));
    assert(!md_inode_store_seal(b));
    snprintf(path,sizeof(path),"%s/shared-metadata",base);
    assert(!md_inode_store_open(path,1,&c) && !md_inode_snapshot(a,c));
    assert(!md_inode_rename(c,-1,"/file",-1,"/different",0));
    file=md_inode_open(c,-1,"/different",O_RDONLY,0); assert(file>=0);
    assert(!mdi_begin(c,1));
    struct mdi_node node;
    assert(!mdi_fd(c,file,&node));
    assert(!mdi_metadata(c,&node,4242,4343,0600));
    assert(!mdi_commit(c,0)); close(file);
    assert(!md_inode_store_seal(c));
    int ar=md_inode_open(a,-1,"/",O_RDONLY|O_DIRECTORY,0);
    int br=md_inode_open(b,-1,"/",O_RDONLY|O_DIRECTORY,0);
    int cr=md_inode_open(c,-1,"/",O_RDONLY|O_DIRECTORY,0);
    assert(ar>=0 && br>=0 && cr>=0);
    assert(!md_inode_view_create(s,MD_FILESYSTEM_OVERLAY,&view));
    assert(!md_inode_overlay_layer(view,a,ar,1));
    assert(!md_inode_overlay_layer(view,b,br,1));
    file=md_inode_open(view,-1,"/file",O_RDONLY,0); assert(file>=0);
    int original=md_inode_open(a,-1,"/file",O_RDONLY,0); assert(original>=0);
    struct stat first,second;
    assert(!fstat(file,&first) && !fstat(original,&second));
    assert(first.st_dev==second.st_dev && first.st_ino==second.st_ino);
    assert(!md_inode_overlay_layer(view,c,cr,1));
    int distinct=md_inode_open(view,-1,"/different",O_RDONLY,0); assert(distinct>=0);
    text(file,"shared"); text(distinct,"shared");
    assert(!fstat(distinct,&second) && (first.st_dev!=second.st_dev || first.st_ino!=second.st_ino));
    assert(!md_inode_fstat(view,file,&first) && !md_inode_fstat(view,distinct,&second));
    assert(first.st_uid!=4242 && second.st_uid==4242 && second.st_gid==4343);
    close(file); close(original); close(distinct); close(ar); close(br); close(cr);
    md_inode_store_close(view); md_inode_store_close(a); md_inode_store_close(b); md_inode_store_close(c);
    collect(s); assert(views(s)==1);
    for (unsigned i=1;i<MDI_SOURCES;++i) assert(s->lifetime->sources[i]<0);
}
static void merge_views(struct md_inode_store *s) {
    assert(!md_inode_mkdir(s,-1,"/lower-dir",0700));
    assert(!md_inode_mkdir(s,-1,"/upper-dir",0700));
    assert(!md_inode_mkdir(s,-1,"/work-dir",0700));
    assert(!md_inode_mkdir(s,-1,"/upper-dir/nested-upper",0700));
    assert(!md_inode_mkdir(s,-1,"/upper-dir/nested-work",0700));
    const char *paths[]={"/lower-dir/kept","/lower-dir/replaced","/upper-dir/replaced"};
    for (unsigned i=0;i<3;++i) {
        int fd=md_inode_open(s,-1,paths[i],O_WRONLY|O_CREAT,0600); assert(fd>=0);
        assert(write(fd,i==2 ? "upper" : "lower",5)==5); close(fd);
    }
    int lower=md_inode_open(s,-1,"/lower-dir",O_RDONLY|O_DIRECTORY,0);
    int upper=md_inode_open(s,-1,"/upper-dir",O_RDONLY|O_DIRECTORY,0);
    int work=md_inode_open(s,-1,"/work-dir",O_RDONLY|O_DIRECTORY,0);
    assert(lower>=0 && upper>=0 && work>=0);
    struct md_inode_store *a=NULL,*b=NULL;
    assert(!md_inode_view_create(s,MD_FILESYSTEM_OVERLAY,&a));
    assert(!md_inode_view_create(s,MD_FILESYSTEM_OVERLAY,&b));
    assert(!md_inode_overlay_layer(a,s,lower,1));
    assert(!md_inode_overlay_prepare_upper(a,s,upper,work,1));
    struct stat work_stat;
    assert(!md_inode_stat(s,work,"work",0,&work_stat));
    assert(S_ISDIR(work_stat.st_mode) && !(work_stat.st_mode&07777));
    assert(!md_inode_overlay_layer(b,s,lower,1));
    int fd=md_inode_open(a,-1,"/replaced",O_RDONLY,0); assert(fd>=0); text(fd,"upper"); close(fd);
    fd=md_inode_open(b,-1,"/replaced",O_RDONLY,0); assert(fd>=0); text(fd,"lower"); close(fd);
    fd=md_inode_open(a,-1,"/kept",O_RDONLY,0); assert(fd>=0); text(fd,"lower"); close(fd);
    fd=md_inode_open(s,-1,"/lower-dir/kept",O_RDONLY,0); assert(fd>=0); text(fd,"lower"); close(fd);
    fd=md_inode_open(b,-1,"/kept",O_RDONLY,0); assert(fd>=0); text(fd,"lower"); close(fd);
    assert(md_inode_overlay_prepare_upper(b,s,upper,work,1)==-EBUSY);
    md_inode_store_close(b); b=NULL;
    struct md_inode_custody_parcel p={0};
    assert(!md_inode_custody_export(a->lifetime,&p));
    md_inode_store_close(a);
    assert(!md_inode_view_create(s,MD_FILESYSTEM_OVERLAY,&b));
    assert(md_inode_overlay_prepare_upper(b,s,upper,work,1)==-EBUSY);
    md_inode_store_close(b); b=NULL;
    md_inode_custody_parcel_close(&p);
    assert(!md_inode_view_create(s,MD_FILESYSTEM_OVERLAY,&b));
    assert(!md_inode_overlay_layer(b,s,lower,1));
    assert(!md_inode_overlay_prepare_upper(b,s,upper,work,1));
    assert(!md_inode_stat(s,work,"work",0,&work_stat) && !(work_stat.st_mode&07777));
    int nested_upper=md_inode_open(b,-1,"/nested-upper",O_RDONLY|O_DIRECTORY,0);
    int nested_work=md_inode_open(b,-1,"/nested-work",O_RDONLY|O_DIRECTORY,0);
    assert(nested_upper>=0 && nested_work>=0);
    a=NULL;
    assert(!md_inode_view_create(b,MD_FILESYSTEM_OVERLAY,&a));
    assert(!md_inode_overlay_prepare_upper(a,b,nested_upper,nested_work,1));
    close(nested_upper); close(nested_work); md_inode_store_close(b);
    collect(s); assert(views(s)==3);
    md_inode_store_close(a);
    close(lower); close(upper); close(work);
    collect(s); assert(views(s)==1);
}
static void writable_view(struct md_inode_store *s) {
    assert(!md_inode_mkdir(s,-1,"/wl",0700) && !md_inode_mkdir(s,-1,"/wu",0700)
        && !md_inode_mkdir(s,-1,"/ww",0700) && !md_inode_mkdir(s,-1,"/wl/d",0700));
    const char *files[]={"/wl/file","/wl/d/entry"};
    for (unsigned i=0;i<2;++i) {
        int fd=md_inode_open(s,-1,files[i],O_CREAT|O_RDWR,0600); assert(fd>=0);
        assert(write(fd,"lower",5)==5); close(fd);
    }
    int lower=md_inode_open(s,-1,"/wl",O_RDONLY|O_DIRECTORY,0);
    int upper=md_inode_open(s,-1,"/wu",O_RDONLY|O_DIRECTORY,0);
    int work=md_inode_open(s,-1,"/ww",O_RDONLY|O_DIRECTORY,0);
    assert(lower>=0 && upper>=0 && work>=0);
    struct md_inode_store *view=NULL;
    assert(!md_inode_view_create(s,MD_FILESYSTEM_OVERLAY,&view));
    assert(!md_inode_overlay_layer(view,s,lower,1));
    assert(!md_inode_overlay_prepare_upper(view,s,upper,work,1));
    assert(!md_inode_overlay_activate(view));
    int root=md_inode_open(view,-1,"/",O_RDONLY|O_DIRECTORY,0); assert(root>=0);
    int watcher=md_inode_watch_create(s,IN_NONBLOCK); assert(watcher>=0);
    assert(md_inode_watch_add(s,watcher,upper,IN_CREATE|IN_DELETE)>0);
    int old=md_inode_open(view,-1,"/file",O_RDONLY,0); assert(old>=0);
    int fd=md_inode_open(view,-1,"/file",O_RDWR,0);
    if (fd<0) fprintf(stderr,"overlay writable open: %d\n",fd);
    assert(fd>=0 && pwrite(fd,"upper",5,0)==5);
    int body=md_inode_open(s,upper,"file",O_RDONLY,0); assert(body>=0); text(body,"upper");
    struct stat a,b;
    assert(!fstat(fd,&a) && !fstat(body,&b) && a.st_ino==b.st_ino && a.st_dev==b.st_dev);
    assert(watched(s,watcher,"file",IN_CREATE)==1);
    text(old,"lower"); close(body); close(fd);
    assert(!md_inode_link(view,-1,"/file",-1,"/alias",0));
    assert(!md_inode_stat(s,upper,"alias",0,&a) && !md_inode_stat(s,upper,"file",0,&b) && a.st_ino==b.st_ino);
    assert(md_inode_rename(view,-1,"/d",-1,"/other",0)==-EXDEV);
    assert(!md_inode_stat(view,-1,"/d/entry",0,&a));
    assert(!md_inode_rename(view,-1,"/file",-1,"/moved",0));
    assert(md_inode_open(view,-1,"/file",O_RDONLY,0)==-ENOENT);
    assert(!md_inode_unlink(view,-1,"/d/entry",0));
    assert(!md_inode_unlink(view,-1,"/d",AT_REMOVEDIR));
    assert(!md_inode_mkdir(view,-1,"/d",0700));
    assert(!md_inode_mkdir(view,-1,"/newdir",0700));
    fd=md_inode_open(view,-1,"/newdir/value",O_CREAT|O_RDWR,0600); assert(fd>=0);
    assert(write(fd,"new",3)==3); close(fd);
    assert(!md_inode_rename(view,-1,"/newdir",-1,"/renamed",0));
    fd=md_inode_open(s,upper,"renamed/value",O_RDONLY,0); assert(fd>=0); text(fd,"new"); close(fd);
    assert(md_inode_open(s,upper,"newdir",O_RDONLY,0)==-ENOENT);
    fd=md_inode_open(view,-1,"/d",O_RDONLY|O_DIRECTORY,0); assert(fd>=0);
    struct md_fs_request q={.operation=MD_FS_XATTR_OBJECT,.directory={fd,-1},
        .path={NULL,"user.fixture"},.mode=MD_FS_XATTR_SET,.value="attr",.capacity=4,.value_size=4};
    struct md_fs_result result={.fd=-1};
    md_inode_xattr(view,&q,&result,NULL); assert(!result.error);
    close(fd); body=md_inode_open(s,upper,"d",O_RDONLY|O_DIRECTORY,0); assert(body>=0);
    char data[16]; assert(fgetxattr(body,"user.fixture",data,sizeof(data))==4 && !memcmp(data,"attr",4)); close(body);
    struct mdi_node upper_node;
    assert(!mdi_begin(view,0) && !mdi_fd(s,upper,&upper_node));
    assert(!mdi_finish(view,0));
    char *sql=sqlite3_mprintf("CREATE TEMP TRIGGER reject_upper BEFORE INSERT ON main.names "
        "WHEN NEW.parent='%q' AND NEW.name=CAST('rollback' AS BLOB) BEGIN SELECT RAISE(ABORT,'fixture'); END",upper_node.id);
    assert(sql && !mdi_sql(view,sql)); sqlite3_free(sql);
    assert(md_inode_open(view,-1,"/rollback",O_CREAT|O_RDWR,0600)==-EIO);
    assert(!mdi_sql(view,"DROP TRIGGER temp.reject_upper"));
    assert(md_inode_open(view,-1,"/rollback",O_RDONLY,0)==-ENOENT);
    assert(md_inode_open(s,upper,"rollback",O_RDONLY,0)==-ENOENT);
    assert(!watched(s,watcher,"rollback",IN_CREATE));
    fd=md_inode_open(view,-1,"/rollback",O_CREAT|O_RDWR,0600); assert(fd>=0); close(fd);
    assert(watched(s,watcher,"rollback",IN_CREATE)==1);
    struct md_inode_lifetime *owner=md_inode_lifetime_retain(view->lifetime);
    md_inode_store_close(view); view=NULL;
    assert(!md_inode_store_reconnect(owner,&view)); md_inode_lifetime_release(owner);
    assert(!md_inode_unlink(view,-1,"/alias",0));
    assert(md_inode_open(s,upper,"alias",O_RDONLY,0)==-ENOENT);
    fd=md_inode_open(view,root,"moved",O_RDONLY,0); assert(fd>=0); text(fd,"upper"); close(fd);
    close(root); close(old); md_inode_store_close(view); view=NULL;
    collect(s);
    assert(!md_inode_view_create(s,MD_FILESYSTEM_OVERLAY,&view));
    assert(!md_inode_overlay_layer(view,s,lower,1));
    assert(!md_inode_overlay_prepare_upper(view,s,upper,work,1));
    assert(!md_inode_overlay_activate(view));
    assert(md_inode_open(view,-1,"/file",O_RDONLY,0)==-ENOENT);
    assert(md_inode_open(view,-1,"/d/entry",O_RDONLY,0)==-ENOENT);
    fd=md_inode_open(view,-1,"/moved",O_RDONLY,0); assert(fd>=0); text(fd,"upper"); close(fd);
    fd=md_inode_open(view,-1,"/renamed/value",O_RDONLY,0); assert(fd>=0); text(fd,"new"); close(fd);
    fd=md_inode_open(s,lower,"file",O_RDONLY,0); assert(fd>=0); text(fd,"lower"); close(fd);
    close(lower); close(upper); close(work); md_inode_store_close(view);
    close(watcher); md_inode_watch_close(s);
    collect(s); assert(views(s)==1);
    puts("PASS writable overlay: copy-up, upper bodies, links, whiteouts, opaque directories, rollback and reconnect");
}
static void socket_message(struct md_inode_store *s,const char *path,int receiver) {
    struct sockaddr_un address={.sun_family=AF_UNIX};
    assert(!md_inode_socket_address(s,-1,path,address.sun_path+1,sizeof(address.sun_path)-1));
    int fd=socket(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0); assert(fd>=0);
    socklen_t size=(socklen_t)(offsetof(struct sockaddr_un,sun_path)+1+strlen(address.sun_path+1));
    assert(sendto(fd,"channel",7,0,(void *)&address,size)==7);
    char data[16]; assert(recv(receiver,data,sizeof(data),MSG_DONTWAIT)==7 && !memcmp(data,"channel",7));
    char name[108]; assert(!md_inode_socket_name(s,address.sun_path+1,name,sizeof(name)));
    close(fd);
}
static void channel_views(struct md_inode_store *s,const char *base) {
    char path[PATH_MAX]; snprintf(path,sizeof(path),"%s/channel-source",base);
    struct md_inode_store *source=NULL,*view=NULL;
    assert(!md_inode_store_open(path,1,&source));
    assert(!md_inode_mkfifo(source,-1,"/fifo",0600));
    int fifo=md_inode_open(source,-1,"/fifo",O_RDWR|O_NONBLOCK,0); assert(fifo>=0);
    int socket_fd=socket(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0); assert(socket_fd>=0);
    assert(!md_inode_socket_bind(source,-1,"/socket","/socket",0600,socket_fd));
    int root=md_inode_open(source,-1,"/",O_RDONLY|O_DIRECTORY,0); assert(root>=0);
    assert(!md_inode_mkdir(s,-1,"/cu",0700) && !md_inode_mkdir(s,-1,"/cw",0700));
    int upper=md_inode_open(s,-1,"/cu",O_RDONLY|O_DIRECTORY,0);
    int work=md_inode_open(s,-1,"/cw",O_RDONLY|O_DIRECTORY,0); assert(upper>=0 && work>=0);
    assert(!md_inode_view_create(s,MD_FILESYSTEM_OVERLAY,&view));
    assert(!md_inode_overlay_layer(view,source,root,1));
    assert(!md_inode_overlay_prepare_upper(view,s,upper,work,1) && !md_inode_overlay_activate(view));
    int other=md_inode_open(view,-1,"/fifo",O_RDWR|O_NONBLOCK,0); assert(other>=0);
    assert(write(fifo,"one",3)==3);
    char data[16]; assert(read(other,data,sizeof(data))==3 && !memcmp(data,"one",3));
    struct stat a,b;
    assert(!md_inode_fstat(view,other,&a) && !md_inode_stat(view,-1,"/fifo",0,&b) && a.st_ino==b.st_ino);
    socket_message(view,"/socket",socket_fd);
    assert(!md_inode_link(view,-1,"/fifo",-1,"/fifo-copy",0));
    int upper_fifo=md_inode_open(s,upper,"fifo-copy",O_RDWR|O_NONBLOCK,0);
    if (upper_fifo<0) fprintf(stderr,"upper FIFO errno=%d\n",-upper_fifo);
    assert(upper_fifo>=0);
    assert(write(upper_fifo,"two",3)==3 && read(fifo,data,sizeof(data))==3 && !memcmp(data,"two",3));
    assert(!md_inode_link(view,-1,"/socket",-1,"/socket-copy",0));
    socket_message(s,"/cu/socket-copy",socket_fd);
    assert(!md_inode_mkfifo(view,-1,"/created",0600));
    int created=md_inode_open(view,-1,"/created",O_RDWR|O_NONBLOCK,0); assert(created>=0);
    int keeper=md_inode_open(s,upper,"created",O_RDWR|O_NONBLOCK,0); assert(keeper>=0);
    int retained=socket(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0); assert(retained>=0);
    assert(!md_inode_socket_bind(view,-1,"/created-socket","/created-socket",0600,retained));
    socket_message(s,"/cu/created-socket",retained);
    close(other); md_inode_store_close(view); view=NULL; collect(s);
    assert(!md_inode_view_create(s,MD_FILESYSTEM_OVERLAY,&view));
    assert(!md_inode_overlay_layer(view,source,root,1));
    int result=md_inode_overlay_prepare_upper(view,s,upper,work,1);
    if (!result) result=md_inode_overlay_activate(view);
    if (result) fprintf(stderr,"channel remount errno=%d\n",-result);
    assert(!result);
    other=md_inode_open(view,-1,"/created",O_RDWR|O_NONBLOCK,0); assert(other>=0);
    /* Retain a registry owner, not just the raw pipe FD, across remount. */
    assert(write(created,"new",3)==3);
    assert(read(other,data,sizeof(data))==3 && !memcmp(data,"new",3));
    socket_message(view,"/created-socket",retained);
    close(other); close(created); close(keeper); close(retained); close(upper_fifo); close(fifo);
    close(socket_fd); close(root); close(upper); close(work);
    md_inode_store_close(view); md_inode_store_close(source); collect(s);
    puts("PASS overlay channels: foreign FIFO and socket identity, upper links, new channels and remount");
}
void test_inode_view(const char *base) {
    char path[PATH_MAX]; snprintf(path,sizeof(path),"%s/view-store",base);
    struct md_inode_store *s=NULL,*view=NULL;
    assert(!md_inode_store_open(path,1,&s));
    control_attributes(s);
    trusted_attributes(s);
    int file=md_inode_open(s,-1,"/file",O_CREAT|O_RDWR,0600); assert(file>=0);
    assert(write(file,"lower",5)==5);
    struct mdi_node lower;
    assert(!mdi_begin(s,0)); assert(!mdi_fd(s,file,&lower)); assert(!mdi_finish(s,0));
    assert(!md_inode_view_create(s,MD_FILESYSTEM_OVERLAY,&view));
    assert(!md_inode_lifetime_same(s->lifetime,view->lifetime));
    assert(views(s)==2 && md_inode_store_seal(s)==-EBUSY);
    assert(!mdi_begin(view,1));
    struct mdi_node projected;
    assert(!mdi_import_shared(view,0,lower.backing,&projected));
    assert(!mdi_add_name(view,mdi_root(view),"file",projected.id));
    assert(!mdi_commit(view,0));
    assert(strcmp(projected.id,lower.id) && !strcmp(projected.scope,view->lifetime->scope));
    assert(md_inode_open_object(view,lower.id,O_RDONLY)==-EXDEV);
    assert(md_inode_open_object(s,projected.id,O_RDONLY)==-EXDEV);
    int old=md_inode_open(view,-1,"/file",O_RDONLY,0); assert(old>=0); text(old,"lower");
    int output=md_inode_open(view,-1,"/file",O_RDWR,0); assert(output>=0);
    assert(pwrite(output,"upper",5,0)==5);
    text(output,"upper"); text(file,"lower"); text(old,"lower");
    struct stat a,b;
    assert(!md_inode_fstat(view,old,&a) && !md_inode_fstat(view,output,&b));
    assert(a.st_ino==b.st_ino && a.st_dev==b.st_dev);
    /* Both roots participate in one SQLite rollback/commit, not two journals. */
    assert(!mdi_begin(view,1));
    assert(!mdi_add_name(view,mdi_root(view),"view-name",projected.id));
    assert(!mdi_add_name(view,MDI_ROOT,"upper-name",lower.id));
    assert(mdi_commit(view,-ECANCELED)==-ECANCELED);
    assert(md_inode_open(view,-1,"/view-name",O_RDONLY,0)==-ENOENT);
    assert(md_inode_open(s,-1,"/upper-name",O_RDONLY,0)==-ENOENT);
    assert(!mdi_begin(view,1));
    assert(!mdi_add_name(view,mdi_root(view),"view-name",projected.id));
    assert(!mdi_add_name(view,MDI_ROOT,"upper-name",lower.id));
    assert(!mdi_commit(view,0));
    int named=md_inode_open(s,-1,"/upper-name",O_RDONLY,0); assert(named>=0); text(named,"lower"); close(named);
    named=md_inode_open(view,-1,"/view-name",O_RDONLY,0); assert(named>=0); text(named,"upper"); close(named);
    struct md_inode_custody_parcel p={0};
    assert(!md_inode_custody_export(view->lifetime,&p) && p.count==3);
    struct md_inode_lifetime *owner=NULL;
    assert(!md_inode_custody_import(&p,s->lifetime->root,&owner));
    assert(md_inode_lifetime_same(owner,view->lifetime));
    md_inode_store_close(view); view=NULL;
    collect(s); assert(views(s)==2);
    assert(!md_inode_store_reconnect(owner,&view));
    assert(!md_inode_fstat(view,old,&a) && !md_inode_fstat(view,output,&b) && a.st_ino==b.st_ino);
    named=md_inode_open(view,-1,"/file",O_RDONLY,0); assert(named>=0); text(named,"upper"); close(named);
    close(old); close(output); close(file);
    md_inode_store_close(view); md_inode_lifetime_release(owner);
    collect(s); assert(views(s)==1);
    merge_views(s);
    writable_view(s);
    snapshot_aliases(s,base);
    channel_views(s,base);
    overlay_credentials(s);
    struct md_inode_audit audit;
    assert(!md_inode_audit(s,&audit));
    assert(audit.untracked>0);
    assert(!md_inode_store_seal(s));
    md_inode_store_close(s);
    assert(!md_inode_store_open_exclusive(path,&s));
    assert(!md_inode_audit(s,&audit) && !audit.untracked);
    md_inode_store_close(s);
    puts("PASS inode views: atomic roots, scoped identities, copy-up, retained custody and collection");
}

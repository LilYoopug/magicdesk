#define _GNU_SOURCE
#include "inode_internal.h"
#include "inode_publication.h"
#include "inode_native.h"
#include "inode_watch.h"
#include "inode_overlay.h"
#include "inode_view.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static int kill_point=-1, deny_catalogue, fail_move, fail_sync, journal_queries, sync_after_intent;
static void checkpoint(enum md_inode_checkpoint point,void *context) {
    (void)context;
    if (point==MD_PUBLICATION_INTENT && sync_after_intent) fail_sync=1;
    if ((int)point==kill_point) { kill(getpid(),SIGKILL); _exit(99); }
}
int __real_renameat2(int,const char *,int,const char *,unsigned);
int __wrap_renameat2(int a,const char *b,int c,const char *d,unsigned flags) {
    if (fail_move) { errno=ENOSPC; return -1; }
    return __real_renameat2(a,b,c,d,flags);
}
int __real_fsync(int);
int __wrap_fsync(int fd) {
    if (fail_sync) { errno=EIO; return -1; }
    return __real_fsync(fd);
}
static int authorize(void *ctx,int action,const char *a,const char *b,const char *db,const char *trigger) {
    (void)ctx; (void)b; (void)db; (void)trigger;
    return deny_catalogue && action==SQLITE_INSERT && a && !strcmp(a,"objects") ? SQLITE_DENY : SQLITE_OK;
}
static int trace(unsigned kind,void *ctx,void *statement,void *detail) {
    (void)ctx; (void)detail;
    if (kind==SQLITE_TRACE_STMT && strstr(sqlite3_sql(statement),"native_publication")) ++journal_queries;
    return 0;
}
static int setup(const char *path,struct md_inode_store **s,int *directory) {
    assert(!md_inode_store_open(path,1,s));
    assert(!md_inode_mkdir(*s,-1,"work",0700));
    *directory=md_inode_open(*s,-1,"work",O_RDONLY|O_DIRECTORY,0); assert(*directory>=0);
    assert(!md_inode_import_metadata(*s,*directory,0,0,0700));
    int fd=openat(*directory,"file",O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600); assert(fd>=0);
    assert(!ftruncate(fd,4096) && pwrite(fd,"contents",8,0)==8);
    assert(!mdi_native_metadata(fd,41,42,0640));
    return fd;
}
static int promote(struct md_inode_store *s,int directory,int file) {
    struct stat st; assert(!fstat(file,&st));
    int r=mdi_begin(s,0); if (r) return r;
    struct mdi_node parent,node;
    r=mdi_fd(s,directory,&parent);
    if (!r) r=mdi_publication_promote(s,&parent,"file",&st,&node);
    return mdi_finish(s,r);
}
static void check(struct md_inode_store *s,int original) {
    struct stat native,logical,opened;
    assert(!fstat(original,&native));
    assert(!md_inode_stat(s,-1,"work/file",0,&logical));
    assert(native.st_dev==logical.st_dev && native.st_ino==logical.st_ino && logical.st_nlink==1);
    assert(logical.st_uid==41 && logical.st_gid==42 && (logical.st_mode&07777)==0640);
    int fd=md_inode_open(s,-1,"work/file",O_RDWR,0); assert(fd>=0);
    assert(!fstat(fd,&opened) && opened.st_dev==native.st_dev && opened.st_ino==native.st_ino);
    assert(!flock(original,LOCK_EX|LOCK_NB));
    assert(flock(fd,LOCK_EX|LOCK_NB)==-1 && errno==EWOULDBLOCK);
    assert(!flock(original,LOCK_UN));
    char bytes[9]={0}; assert(pread(fd,bytes,8,0)==8 && !strcmp(bytes,"contents"));
    close(fd);
    assert(!mdi_publication_pending(s));
    struct md_inode_audit audit; assert(!md_inode_audit(s,&audit) && !audit.untracked);
}
static void success(const char *path) {
    struct md_inode_store *s;
    int directory,fd=setup(path,&s,&directory);
    char *memory=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0); assert(memory!=MAP_FAILED);
    int watch=md_inode_watch_create(s,IN_NONBLOCK); assert(watch>=0);
    assert(md_inode_watch_add(s,watch,directory,IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO)>0);
    assert(!promote(s,directory,fd)); check(s,fd);
    assert(md_inode_watch_bytes(s,watch)==0);
    assert(!md_inode_link(s,-1,"work/file",-1,"work/alias",0));
    int alias=md_inode_open(s,-1,"work/alias",O_RDWR,0); assert(alias>=0);
    assert(pwrite(alias,"updated!",8,0)==8 && !memcmp(memory,"updated!",8));
    assert(!md_inode_unlink(s,-1,"work/file",0));
    assert(!md_inode_unlink(s,-1,"work/alias",0));
    struct stat st; assert(!md_inode_fstat(s,fd,&st) && st.st_nlink==0);
    assert(!memcmp(memory,"updated!",8));
    munmap(memory,4096); close(alias); close(fd); close(directory); close(watch); md_inode_store_close(s);
    puts("PASS in-place promotion retains physical inode, mmap, flock and hardlink/unlinked descriptors; no namespace event for representation change");
}
static void killed(const char *path,int point,int cold) {
    struct md_inode_store *s;
    int directory,fd=setup(path,&s,&directory);
    struct stat unused; assert(!md_inode_stat(s,-1,"work/file",0,&unused));
    assert(!mdi_begin(s,0));
    struct mdi_node parent,node;
    assert(!mdi_fd(s,directory,&parent));
    assert(mdi_catalogue_lookup(s,parent.id,"file",&node)==-ENOENT);
    assert(!mdi_finish(s,0));
    pid_t pid=fork(); assert(pid>=0);
    if (!pid) {
        struct md_inode_store *child=NULL; assert(!md_inode_store_open(path,0,&child));
        kill_point=point; md_inode_observe(child,checkpoint,NULL);
        (void)promote(child,directory,fd); _exit(97);
    }
    int status; assert(waitpid(pid,&status,0)==pid && WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL);
    if (cold) { md_inode_store_close(s); assert(!md_inode_store_open(path,0,&s)); }
    check(s,fd);
    close(fd); close(directory); md_inode_store_close(s);
    printf("PASS SIGKILL at %d, %s owner recovers identity and invalidates negative lookup\n",point,cold ? "cold" : "already-open");
}
static void errors(const char *path,int kind) {
    struct md_inode_store *s;
    int directory,fd=setup(path,&s,&directory);
    assert(sqlite3_set_authorizer(s->db,authorize,NULL)==SQLITE_OK);
    md_inode_observe(s,checkpoint,NULL);
    fail_move=kind==0; deny_catalogue=kind==1; fail_sync=kind==2; sync_after_intent=kind==3;
    int r=promote(s,directory,fd);
    assert(r==(kind==0 ? -ENOSPC : -EIO));
    fail_move=deny_catalogue=fail_sync=sync_after_intent=0;
    if (kind==2) {
        assert(!mdi_publication_pending(s));
        struct stat st; assert(!fstatat(directory,"file",&st,AT_SYMLINK_NOFOLLOW));
        assert(!promote(s,directory,fd));
    }
    check(s,fd);
    close(fd); close(directory); md_inode_store_close(s);
    puts("PASS sync, move and catalogue failure preserve the original body and recover without replaying the guest operation");
}
static void recovery_killed(const char *path) {
    struct md_inode_store *s;
    int directory,fd=setup(path,&s,&directory);
    int ready[2],resume[2]; assert(!pipe(ready) && !pipe(resume));
    pid_t pid=fork(); assert(pid>=0);
    if (!pid) {
        close(ready[0]); close(resume[1]);
        struct md_inode_store *child; assert(!md_inode_store_open(path,0,&child));
        md_inode_observe(child,checkpoint,NULL); kill_point=MD_PUBLICATION_MOVED;
        char byte=1; assert(write(ready[1],&byte,1)==1);
        /* EVENT_WAIT: the parent has left a durable intent. Outer timeout
         * terminates a broken handshake, never substitutes elapsed time. */
        assert(read(resume[0],&byte,1)==1);
        struct stat st; (void)md_inode_stat(child,-1,"work/file",0,&st); _exit(96);
    }
    close(ready[1]); close(resume[0]); char byte;
    /* EVENT_WAIT: second owner is admitted before interruption; bounded by
     * the invocation's outer timeout. */
    assert(read(ready[0],&byte,1)==1);
    fail_move=1; assert(promote(s,directory,fd)==-ENOSPC); fail_move=0;
    struct md_inode_store *inspection=NULL;
    assert(md_inode_store_open_inspect(path,&inspection)==-EBUSY && !inspection);
    assert(write(resume[1],&byte,1)==1); close(resume[1]); close(ready[0]);
    int status; assert(waitpid(pid,&status,0)==pid && WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL);
    check(s,fd); close(fd); close(directory); md_inode_store_close(s);
    puts("PASS a second SIGKILL during recovery is recoverable; inspection never performs the pending mutation");
}
static void conflicts(const char *path) {
    struct md_inode_store *s;
    int directory,fd=setup(path,&s,&directory);
    fail_move=1; assert(promote(s,directory,fd)==-ENOSPC); fail_move=0;
    assert(!renameat(directory,"file",directory,"original"));
    int foreign=openat(directory,"file",O_CREAT|O_EXCL|O_RDWR,0600); assert(foreign>=0);
    assert(write(foreign,"foreign",7)==7);
    struct stat st;
    assert(md_inode_stat(s,-1,"work/file",0,&st)==-ESTALE);
    char bytes[8]={0}; assert(pread(foreign,bytes,7,0)==7 && !strcmp(bytes,"foreign"));
    assert(!unlinkat(directory,"file",0) && !renameat(directory,"original",directory,"file"));
    close(foreign); check(s,fd);
    close(fd); close(directory); md_inode_store_close(s);
    puts("PASS conflicting identity blocks admission without replacing either file");
}
static void hot_path(const char *path) {
    struct md_inode_store *s;
    assert(!md_inode_store_open(path,1,&s));
    int fd=md_inode_create(s,-1,"ordinary",0600); assert(fd>=0); close(fd);
    journal_queries=0; assert(sqlite3_trace_v2(s->db,SQLITE_TRACE_STMT,trace,NULL)==SQLITE_OK);
    for (int i=0;i<100;++i) {
        struct stat st; assert(!md_inode_stat(s,-1,"ordinary",0,&st));
        assert(!md_inode_link(s,-1,"ordinary",-1,"alias",0));
        assert(!md_inode_unlink(s,-1,"alias",0));
    }
    assert(!journal_queries); md_inode_store_close(s);
    puts("PASS steady-state filesystem operations never query the publication journal");
}
static void snapshots(const char *path,const char *left_path,const char *right_path) {
    struct md_inode_store *base,*left,*right;
    int directory,fd=setup(path,&base,&directory);
    assert(!promote(base,directory,fd));
    assert(!md_inode_link(base,-1,"work/file",-1,"work/alias",0));
    assert(!md_inode_store_seal(base));
    assert(!md_inode_store_open(left_path,1,&left) && !md_inode_store_open(right_path,1,&right));
    assert(!md_inode_snapshot(base,left) && !md_inode_snapshot(base,right));
    int reader=md_inode_open(left,-1,"work/file",O_RDONLY,0); assert(reader>=0);
    char *mapped=mmap(NULL,4096,PROT_READ,MAP_SHARED,reader,0); assert(mapped!=MAP_FAILED);
    struct stat before,after,physical;
    assert(!md_inode_fstat(left,reader,&before));
    int writer=md_inode_open(left,-1,"work/alias",O_RDWR,0); assert(writer>=0);
    assert(pwrite(writer,"private!",8,0)==8);
    assert(!md_inode_fstat(left,writer,&after) && before.st_dev==after.st_dev && before.st_ino==after.st_ino);
    assert(!fstat(writer,&physical) && physical.st_ino!=before.st_ino);
    assert(!memcmp(mapped,"contents",8));
    int other=md_inode_open(right,-1,"work/file",O_RDONLY,0); assert(other>=0);
    char bytes[8]; assert(pread(other,bytes,8,0)==8 && !memcmp(bytes,"contents",8));
    assert(pread(fd,bytes,8,0)==8 && !memcmp(bytes,"contents",8));
    int current=md_inode_open(left,-1,"work/file",O_RDONLY,0); assert(current>=0);
    assert(pread(current,bytes,8,0)==8 && !memcmp(bytes,"private!",8));
    struct md_inode_audit audit;
    assert(!md_inode_audit(base,&audit) && !md_inode_audit(left,&audit) && !md_inode_audit(right,&audit));
    close(current); close(other); close(writer); munmap(mapped,4096); close(reader); close(fd); close(directory);
    md_inode_store_close(right); md_inode_store_close(left); md_inode_store_close(base);
    puts("PASS promoted body enters existing shared-source snapshots and COW with stable logical identity and isolated aliases");
}
static void admission(const char *path) {
    struct md_inode_store *s;
    int directory,fd=setup(path,&s,&directory);
    struct stat st; assert(!fstat(fd,&st));
    struct mdi_node parent,node;
    assert(!mdi_begin(s,0) && !mdi_fd(s,directory,&parent));
    assert(!mdi_begin(s,0));
    assert(mdi_publication_promote(s,&parent,"file",&st,&node)==-EDEADLK);
    assert(!mdi_finish(s,0) && !mdi_finish(s,0));
    assert(!mdi_begin(s,1));
    assert(!mdi_sql(s,"INSERT INTO properties VALUES('test-publication',1)"));
    assert(mdi_publication_promote(s,&parent,"file",&st,&node)==-EDEADLK);
    assert(mdi_finish(s,-ECANCELED)==-ECANCELED);
    assert(!mdi_begin(s,0));
    assert(mdi_publication_promote(s,&parent,"../file",&st,&node)==-EINVAL);
    struct stat wrong=st; ++wrong.st_ino;
    assert(mdi_publication_promote(s,&parent,"file",&wrong,&node)==-ESTALE);
    assert(!mdi_finish(s,0));
    assert(!mdi_publication_pending(s));
    assert(!promote(s,directory,fd)); check(s,fd);
    close(fd); close(directory); md_inode_store_close(s);
    puts("PASS nested/dirty transaction, unsafe name and stale inode are rejected before intent publication");
}
static void overlay_killed(const char *path,int point,int upper,int cold) {
    struct md_inode_store *s=NULL,*view=NULL;
    assert(!md_inode_store_open(path,1,&s));
    struct md_identity ids=md_identity_new(0,0); s->identity=&ids;
    const char *names[]={"lower","upper","work"}; int directories[3];
    for (unsigned i=0;i<3;++i) {
        assert(!md_inode_mkdir(s,-1,names[i],0755));
        directories[i]=md_inode_open(s,-1,names[i],O_RDONLY|O_DIRECTORY,0); assert(directories[i]>=0);
    }
    assert(!md_inode_view_create(s,MD_FILESYSTEM_OVERLAY,&view));
    assert(!md_inode_overlay_layer(view,s,directories[0],1));
    assert(!md_inode_overlay_prepare_upper(view,s,directories[1],directories[2],1));
    assert(!md_inode_overlay_activate(view) && !md_inode_overlay_stash(view,&ids)); view->identity=&ids;
    int fd=md_inode_create(view,-1,"file",0644); assert(fd>=0 && write(fd,"overlay",7)==7);
    int original=md_inode_open(s,directories[1],"file",O_RDONLY,0); assert(original>=0);
    char a[33],b[33],after[33];
    assert(!md_inode_object_id(view,fd,a) && !md_inode_object_id(s,original,b) && strcmp(a,b));
    int merged=md_inode_open(view,-1,"/",O_RDONLY|O_DIRECTORY,0); assert(merged>=0);
    int watchers[2]={md_inode_watch_create(s,IN_NONBLOCK),md_inode_watch_create(view,IN_NONBLOCK)};
    assert(watchers[0]>=0 && watchers[1]>=0);
    unsigned mask=IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO;
    assert(md_inode_watch_add(s,watchers[0],directories[1],mask)>0);
    assert(md_inode_watch_add(view,watchers[1],merged,mask)>0);
    pid_t pid=fork(); assert(pid>=0);
    if (!pid) {
        struct md_inode_store *child=NULL;
        assert(!md_inode_store_reconnect(upper ? s->lifetime : view->lifetime,&child)); child->identity=&ids;
        kill_point=point; md_inode_observe(child,checkpoint,NULL);
        (void)md_inode_link(child,upper ? directories[1] : -1,"file",upper ? directories[1] : -1,"alias",0);
        _exit(96);
    }
    int status; assert(waitpid(pid,&status,0)==pid && WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL);
    if (cold) {
        close(watchers[0]); close(watchers[1]); md_inode_store_close(view); view=NULL;
        md_inode_store_close(s); s=NULL; assert(!md_inode_store_open(path,0,&s)); s->identity=&ids;
    }
    struct stat st;
    assert(!md_inode_stat(s,directories[1],"file",0,&st) && st.st_size==7 && st.st_nlink==1);
    assert(!md_inode_object_id(s,original,after) && !strcmp(b,after));
    if (!cold) {
        assert(!md_inode_stat(view,-1,"file",0,&st) && st.st_size==7 && st.st_nlink==1);
        assert(!md_inode_object_id(view,fd,after) && !strcmp(a,after));
        assert(md_inode_watch_bytes(s,watchers[0])==0 && md_inode_watch_bytes(view,watchers[1])==0);
        close(watchers[0]); close(watchers[1]); md_inode_store_close(view);
    }
    close(fd); close(original); close(merged);
    for (unsigned i=0;i<3;++i) close(directories[i]);
    md_inode_store_close(s); md_identity_release(&ids);
    printf("PASS overlay SIGKILL at %d upper=%d cold=%d: both projections, identity and no false namespace events\n",point,upper,cold);
}
int main(int argc,char **argv) {
    assert(argc==2 && argv[1][0]=='/' && !mkdir(argv[1],0700));
    char path[PATH_MAX];
    snprintf(path,sizeof(path),"%s/success",argv[1]); success(path);
    const int points[]={MD_PUBLICATION_INTENT,MD_PUBLICATION_MOVED,MD_PUBLICATION_STAGED,MD_PUBLICATION_CATALOGUED};
    for (unsigned i=0;i<sizeof(points)/sizeof(*points);++i) for (int cold=0;cold<2;++cold) {
        snprintf(path,sizeof(path),"%s/kill-%u-%d",argv[1],i,cold); killed(path,points[i],cold);
    }
    for (unsigned i=0;i<sizeof(points)/sizeof(*points);++i) for (int upper=0;upper<2;++upper) for (int cold=0;cold<2;++cold) {
        snprintf(path,sizeof(path),"%s/overlay-%u-%d-%d",argv[1],i,upper,cold); overlay_killed(path,points[i],upper,cold);
    }
    for (int i=0;i<4;++i) {
        snprintf(path,sizeof(path),"%s/error-%d",argv[1],i); errors(path,i);
    }
    snprintf(path,sizeof(path),"%s/conflict",argv[1]); conflicts(path);
    snprintf(path,sizeof(path),"%s/recovery",argv[1]); recovery_killed(path);
    snprintf(path,sizeof(path),"%s/hot",argv[1]); hot_path(path);
    snprintf(path,sizeof(path),"%s/admission",argv[1]); admission(path);
    char left[PATH_MAX],right[PATH_MAX];
    snprintf(left,sizeof(left),"%s/left",argv[1]); snprintf(right,sizeof(right),"%s/right",argv[1]);
    snprintf(path,sizeof(path),"%s/base",argv[1]); snapshots(path,left,right);
    return 0;
}

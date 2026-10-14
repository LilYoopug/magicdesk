#define _GNU_SOURCE
#include "inode_internal.h"
#include "inode_watch.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <sys/inotify.h>
#include <unistd.h>

static int fail_fd=-1, fail_database, failures;
static struct md_identity identity;
int __real_fsync(int);
int __real_fdatasync(int);
static int fail_sync(int fd) {
    int fail=fd==fail_fd;
    if (fail_database) {
        char name[64], path[PATH_MAX];
        snprintf(name,sizeof(name),"/proc/self/fd/%d",fd);
        ssize_t n=readlink(name,path,sizeof(path)-1);
        if (n>=0) { path[n]=0; fail=!!strstr(path,"namespace.db"); }
    }
    if (fail) { ++failures; errno=EIO; }
    return fail;
}
int __wrap_fsync(int fd) { return fail_sync(fd) ? -1 : __real_fsync(fd); }
int __wrap_fdatasync(int fd) { return fail_sync(fd) ? -1 : __real_fdatasync(fd); }
static int scalar(struct md_inode_store *s,const char *sql) {
    sqlite3_stmt *q=NULL;
    assert(sqlite3_prepare_v2(s->db,sql,-1,&q,NULL)==SQLITE_OK);
    assert(sqlite3_step(q)==SQLITE_ROW);
    int result=sqlite3_column_int(q,0);
    assert(sqlite3_finalize(q)==SQLITE_OK); return result;
}
static void audit(struct md_inode_store *s) {
    struct md_inode_audit a; assert(!md_inode_audit(s,&a));
    assert(!scalar(s,"SELECT count(*) FROM allocation_reserve r JOIN backings b ON r.backing=b.backing WHERE b.source=0"));
}
static void copy(int directory,const char *from,const char *to) {
    int a=openat(directory,from,O_RDONLY|O_CLOEXEC), b=openat(directory,to,O_CREAT|O_TRUNC|O_WRONLY|O_CLOEXEC,0600);
    assert(a>=0 && b>=0);
    char buffer[16384]; ssize_t n;
    while ((n=read(a,buffer,sizeof(buffer)))>0) assert(write(b,buffer,(size_t)n)==n);
    assert(n==0 && !__real_fsync(b)); close(a); close(b);
}
static void barriers(const char *path) {
    struct md_inode_store *s;
    assert(!md_inode_store_open(path,1,&s));
    s->identity=&identity;
    struct md_inode_statistics stats={0}; md_inode_measure(s,&stats);
    int fd=md_inode_create(s,-1,"value",0600); assert(fd>=0);
    assert(write(fd,"durable",7)==7);
    assert(!md_inode_link(s,-1,"value",-1,"alias",0));
    assert(!md_inode_rename(s,-1,"value",-1,"renamed",0));
    assert(!stats.checkpoint.calls);
    assert(!md_inode_sync(s,fd,MD_INODE_SYNC_DATA) && stats.checkpoint.calls==1);
    struct md_inode_store *other;
    assert(!md_inode_store_open(path,0,&other));
    other->identity=&identity;
    assert(!md_inode_unlink(other,-1,"renamed",0));
    int dir=md_inode_open(s,-1,"/",O_RDONLY|O_DIRECTORY,0); assert(dir>=0);
    assert(!md_inode_sync(s,dir,MD_INODE_SYNC_FILE) && stats.checkpoint.calls==2);
    int opath=md_inode_open(s,-1,"alias",O_PATH,0); assert(opath>=0);
    assert(md_inode_sync(s,opath,MD_INODE_SYNC_FILE)==-EBADF);
    close(opath);
    assert(!md_inode_sync(s,fd,MD_INODE_SYNC_FILESYSTEM) && stats.checkpoint.calls==3);
    fail_fd=fd;
    assert(md_inode_sync(s,fd,MD_INODE_SYNC_FILE)==-EIO && failures==1);
    assert(stats.checkpoint.calls==3); fail_fd=-1;
    assert(!md_inode_unlink(other,-1,"alias",0));
    assert(!md_inode_sync(s,fd,MD_INODE_SYNC_FILE));
    char contents[8]={0}; assert(pread(fd,contents,7,0)==7 && !strcmp(contents,"durable"));
    assert(!md_inode_mkfifo(s,-1,"fifo",0600));
    opath=md_inode_open(s,-1,"fifo",O_PATH,0); assert(opath>=0);
    assert(md_inode_sync(s,opath,MD_INODE_SYNC_DATA)==-EBADF); close(opath);
    uint64_t before=stats.checkpoint.calls;
    int synchronous=md_inode_open(s,-1,"sync",O_CREAT|O_RDWR|O_DSYNC,0600);
    assert(synchronous>=0 && stats.checkpoint.calls==before+1); close(synchronous);
    assert(!md_inode_link(s,-1,"sync",-1,"sync-alias",0));
    fail_database=1; int previous=failures;
    assert(md_inode_sync(s,dir,MD_INODE_SYNC_FILE)==-EIO && failures>previous);
    fail_database=0;
    close(dir); close(fd); md_inode_store_close(other); md_inode_store_close(s);
    assert(!md_inode_store_open(path,0,&s)); audit(s); md_inode_store_close(s);
    puts("PASS data/namespace barriers, other writer, hardlink/rename/unlinked FD, O_DSYNC and propagated data/WAL IO failures");
}
static void reserve_failures(const char *path) {
    struct md_inode_store *s;
    assert(!md_inode_store_open(path,1,&s));
    s->identity=&identity;
    fail_fd=s->objects;
    assert(md_inode_create(s,-1,"failed",0600)==-EIO); fail_fd=-1;
    assert(!scalar(s,"SELECT count(*) FROM allocation_reserve"));
    struct md_inode_audit a;
    assert(!md_inode_audit(s,&a) && a.untracked==MDI_RESERVE_BATCH && a.names==0);
    struct md_inode_statistics stats={0}; md_inode_measure(s,&stats);
    for (unsigned i=0;i<MDI_RESERVE_BATCH;++i) {
        char name[32]; snprintf(name,sizeof(name),"file-%u",i);
        int fd=md_inode_create(s,-1,name,0600); assert(fd>=0); close(fd);
    }
    assert(stats.sync_directory.calls==1);
    assert(!scalar(s,"SELECT count(*) FROM allocation_reserve"));
    int reader=md_inode_watch_create(s,IN_NONBLOCK); assert(reader>=0);
    int root=md_inode_open(s,-1,"/",O_PATH|O_DIRECTORY,0); assert(root>=0);
    int wd=md_inode_watch_add(s,reader,root,IN_ALL_EVENTS); assert(wd>0);
    int watched=md_inode_create(s,-1,"watched",0600); assert(watched>=0);
    close(watched);
    assert(stats.sync_directory.calls==2);
    assert(!scalar(s,"SELECT count(*) FROM allocation_reserve"));
    assert(!md_inode_watch_pump(s));
    char events[4096]; ssize_t size=md_inode_watch_read(s,reader,events,sizeof(events),NULL,NULL);
    assert(size>0);
    unsigned created=0,opened=0,closed=0;
    for (ssize_t i=0;i<size;) {
        struct inotify_event *event=(void *)(events+i);
        assert(event->wd==wd && !strcmp(event->name,"watched"));
        assert(!(event->mask&(IN_MODIFY|IN_ATTRIB)));
        created+=!!(event->mask&IN_CREATE); opened+=!!(event->mask&IN_OPEN); closed+=!!(event->mask&IN_CLOSE_WRITE);
        i+=sizeof(*event)+event->len;
    }
    assert(created==1 && opened==1 && closed==1);
    close(root); close(reader); assert(!md_inode_watch_pump(s));
    audit(s); md_inode_store_close(s);
    assert(!md_inode_store_open_exclusive(path,&s));
    assert(!md_inode_audit(s,&a) && a.untracked==0 && a.names==MDI_RESERVE_BATCH+1);
    md_inode_store_close(s);
    puts("PASS reserve failures, batched directory sync, clean directory watch events and exclusive orphan cleanup");
}
static void recovery(const char *path,int durable) {
    struct md_inode_store *s;
    assert(!md_inode_store_open(path,1,&s));
    s->identity=&identity;
    int fd=md_inode_create(s,-1,"base",0600); assert(fd>=0); close(fd);
    assert(!md_inode_sync(s,-1,MD_INODE_SYNC_FILESYSTEM));
    md_inode_store_close(s);
    int directory=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC); assert(directory>=0);
    copy(directory,"namespace.db","frontier");
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        assert(!md_inode_store_open(path,0,&s));
        s->identity=&identity;
        assert(sqlite3_wal_autocheckpoint(s->db,0)==SQLITE_OK);
        fd=md_inode_create(s,-1,"pending",0600); assert(fd>=0);
        assert(write(fd,"old contents",12)==12);
        assert(!fsetxattr(fd,"user.previous","old",3,0));
        assert(!md_inode_link(s,-1,"pending",-1,"alias",0));
        assert(!md_inode_rename(s,-1,"pending",-1,"renamed",0));
        assert(!md_inode_unlink(s,-1,"base",0));
        if (durable) assert(!md_inode_sync(s,fd,MD_INODE_SYNC_DATA));
        /* No SQLite close/checkpoint. This process-death boundary also leaves
         * native bodies for the modeled loss of the uncheckpointed WAL below. */
        kill(getpid(),SIGKILL); _exit(90);
    }
    int status; assert(waitpid(child,&status,0)==child && WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL);
    if (!durable) copy(directory,"frontier","namespace.db");
    assert(!unlinkat(directory,"namespace.db-wal",0));
    assert(!unlinkat(directory,"namespace.db-shm",0));
    close(directory);
    assert(!md_inode_store_open(path,0,&s)); audit(s);
    s->identity=&identity;
    struct stat st;
    if (durable) {
        assert(md_inode_stat(s,-1,"base",0,&st)==-ENOENT);
        assert(!md_inode_stat(s,-1,"renamed",0,&st) && st.st_nlink==2 && st.st_size==12);
        assert(!md_inode_stat(s,-1,"alias",0,&st) && st.st_nlink==2);
    } else {
        assert(!md_inode_stat(s,-1,"base",0,&st));
        assert(md_inode_stat(s,-1,"renamed",0,&st)==-ENOENT);
        fd=md_inode_create(s,-1,"fresh",0640); assert(fd>=0);
        assert(!md_inode_fstat(s,fd,&st) && !st.st_size && (st.st_mode&0777)==0640);
        char value[8]; assert(fgetxattr(fd,"user.previous",value,sizeof(value))<0 && errno==ENODATA);
        close(fd); audit(s);
    }
    md_inode_store_close(s);
}
static void writers(const char *path) {
    struct md_inode_store *s;
    assert(!md_inode_store_open(path,1,&s)); md_inode_store_close(s);
    pid_t children[4];
    for (unsigned i=0;i<4;++i) {
        children[i]=fork(); assert(children[i]>=0);
        if (!children[i]) {
            assert(!md_inode_store_open(path,0,&s)); s->identity=&identity;
            for (unsigned j=0;j<40;++j) {
                char name[32], alias[32];
                snprintf(name,sizeof(name),"writer-%u-%u",i,j);
                snprintf(alias,sizeof(alias),"alias-%u-%u",i,j);
                int fd=md_inode_create(s,-1,name,0600); assert(fd>=0);
                assert(write(fd,name,strlen(name))==(ssize_t)strlen(name));
                assert(!md_inode_link(s,-1,name,-1,alias,0));
                assert(!md_inode_unlink(s,-1,name,0));
                if (!(j%8)) assert(!md_inode_sync(s,fd,MD_INODE_SYNC_DATA));
                close(fd);
            }
            md_inode_store_close(s); _exit(0);
        }
    }
    for (unsigned i=0;i<4;++i) {
        int status; assert(waitpid(children[i],&status,0)==children[i]);
        assert(WIFEXITED(status) && !WEXITSTATUS(status));
    }
    assert(!md_inode_store_open(path,0,&s)); audit(s);
    assert(!md_inode_sync(s,-1,MD_INODE_SYNC_FILESYSTEM));
    assert(scalar(s,"SELECT count(*) FROM names")==160);
    md_inode_store_close(s);
    puts("PASS four concurrent reserve writers, hardlinks and shared metadata barriers");
}
static void snapshot(const char *source,const char *target) {
    struct md_inode_store *a,*b;
    assert(!md_inode_store_open(source,1,&a)); a->identity=&identity;
    int fd=md_inode_create(a,-1,"image",0600); assert(fd>=0);
    assert(write(fd,"image",5)==5); close(fd);
    assert(scalar(a,"SELECT count(*) FROM allocation_reserve")==MDI_RESERVE_BATCH-1);
    assert(!md_inode_store_seal(a));
    assert(!md_inode_store_open(target,1,&b));
    assert(!md_inode_snapshot(a,b));
    assert(!scalar(b,"SELECT count(*) FROM allocation_reserve")); audit(b);
    b->identity=&identity;
    fd=md_inode_create(b,-1,"new",0600); assert(fd>=0); close(fd);
    assert(!md_inode_sync(b,-1,MD_INODE_SYNC_FILESYSTEM)); audit(a); audit(b);
    md_inode_store_close(b); md_inode_store_close(a);
    puts("PASS sealed image durability and snapshot-local allocation reserve");
}
int main(int argc,char **argv) {
    assert(argc==2 && argv[1][0]=='/' && !mkdir(argv[1],0700));
    identity=md_identity_new(0,0);
    char path[PATH_MAX];
    snprintf(path,sizeof(path),"%s/barriers",argv[1]); barriers(path);
    snprintf(path,sizeof(path),"%s/reserve",argv[1]); reserve_failures(path);
    snprintf(path,sizeof(path),"%s/lost",argv[1]); recovery(path,0);
    snprintf(path,sizeof(path),"%s/durable",argv[1]); recovery(path,1);
    puts("PASS modeled WAL loss: reserved-body reset and durable hardlink/rename/unlink frontier (not a physical power-cut test)");
    snprintf(path,sizeof(path),"%s/writers",argv[1]); writers(path);
    char target[PATH_MAX];
    snprintf(path,sizeof(path),"%s/image",argv[1]);
    snprintf(target,sizeof(target),"%s/instance",argv[1]); snapshot(path,target);
    md_identity_release(&identity);
}

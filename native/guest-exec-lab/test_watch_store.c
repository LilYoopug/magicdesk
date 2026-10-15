#define _GNU_SOURCE
#include "inode_internal.h"
#include "inode_watch.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"store watch line=%d %s errno=%d\n",__LINE__,#x,errno); exit(1); } } while (0)
static int64_t count(struct md_inode_store *s) {
    sqlite3_stmt *q = NULL;
    CHECK(!mdi_begin(s, 0));
    CHECK(!mdi_prepare(s, "SELECT count(*) FROM events", &q));
    CHECK(mdi_step(s, q) == SQLITE_ROW);
    int64_t result = sqlite3_column_int64(q, 0);
    sqlite3_finalize(q); CHECK(!mdi_finish(s, 0));
    return result;
}
static void crash(enum md_inode_checkpoint stage, void *context) {
    (void)context;
    if (stage == MD_NAMESPACE_STAGED) kill(getpid(), SIGKILL);
}
static void expect_record(int reader, struct md_inode_store *s, int wd, unsigned mask, const char *name) {
    union { struct inotify_event align; char bytes[1024]; } bytes;
    ssize_t n=md_inode_watch_read(s,reader,bytes.bytes,sizeof(bytes.bytes),NULL,NULL);
    CHECK(n==(ssize_t)(sizeof(bytes.align)+bytes.align.len));
    CHECK(bytes.align.wd==wd && bytes.align.mask==mask);
    CHECK(name ? bytes.align.len && !strcmp(bytes.align.name,name) : !bytes.align.len);
}
static void physical_create(int parent,const char *name) {
    int fd=openat(parent,name,O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600); CHECK(fd>=0); close(fd);
}
static void logical_create(struct md_inode_store *s,const char *path) {
    int fd=md_inode_create(s,-1,path,0600); CHECK(fd>=0); close(fd);
}
static void native_transitions(const char *base) {
    char path[PATH_MAX];
    snprintf(path,sizeof(path),"%s/mixed",base);
    struct md_inode_store *s,*writer;
    CHECK(!md_inode_store_open(path,1,&s) && !md_inode_store_open(path,0,&writer));
    snprintf(path,sizeof(path),"%s/native",base); CHECK(!mkdir(path,0700));
    int native=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC); CHECK(native>=0);
    int root=md_inode_open(s,-1,"/",O_PATH|O_DIRECTORY,0); CHECK(root>=0);
    int reader=md_inode_watch_create(s,IN_NONBLOCK|IN_CLOEXEC); CHECK(reader>=0);
    int native_wd=md_inode_watch_add(s,reader,native,IN_CREATE); CHECK(native_wd>0);
    struct md_inode_statistics stats={0}; md_inode_measure(s,&stats);
    physical_create(native,"before"); expect_record(reader,s,native_wd,IN_CREATE,"before");
    CHECK(!stats.step.calls && !stats.transaction.calls);
    logical_create(writer,"/unsubscribed");
    CHECK(!mdi_begin(writer,1));
    CHECK(!mdi_sql(writer,"UPDATE events SET sequence=sequence+70000"));
    CHECK(!mdi_finish(writer,0));
    CHECK(md_inode_watch_read(s,reader,path,sizeof(path),NULL,NULL)==-EAGAIN);
    int logical_wd=md_inode_watch_add(s,reader,root,IN_CREATE); CHECK(logical_wd>0);
    CHECK(md_inode_watch_read(s,reader,path,sizeof(path),NULL,NULL)==-EAGAIN);
    logical_create(writer,"/mixed"); expect_record(reader,s,logical_wd,IN_CREATE,"mixed");
    physical_create(native,"mixed"); expect_record(reader,s,native_wd,IN_CREATE,"mixed");
    int second=md_inode_watch_create(s,IN_NONBLOCK|IN_CLOEXEC); CHECK(second>=0);
    int second_wd=md_inode_watch_add(s,second,root,IN_CREATE); CHECK(second_wd>0);
    CHECK(!md_inode_watch_remove(s,reader,logical_wd));
    expect_record(reader,s,logical_wd,IN_IGNORED,NULL);
    logical_create(writer,"/second"); expect_record(second,s,second_wd,IN_CREATE,"second");
    CHECK(md_inode_watch_read(s,reader,path,sizeof(path),NULL,NULL)==-EAGAIN);
    close(second); CHECK(!md_inode_watch_pump(s));
    physical_create(native,"after-close"); expect_record(reader,s,native_wd,IN_CREATE,"after-close");
    logical_create(writer,"/before-oneshot");
    logical_wd=md_inode_watch_add(s,reader,root,IN_CREATE|IN_ONESHOT); CHECK(logical_wd>0);
    logical_create(writer,"/oneshot");
    union { struct inotify_event align; char bytes[1024]; } bytes;
    ssize_t n=md_inode_watch_read(s,reader,bytes.bytes,sizeof(bytes.bytes),NULL,NULL); CHECK(n==48);
    CHECK(bytes.align.wd==logical_wd && bytes.align.mask==IN_CREATE && !strcmp(bytes.align.name,"oneshot"));
    struct inotify_event *ignored=(void *)(bytes.bytes+32);
    CHECK(ignored->wd==logical_wd && ignored->mask==IN_IGNORED);
    uint64_t steps=stats.step.calls, transactions=stats.transaction.calls;
    physical_create(native,"after-oneshot"); expect_record(reader,s,native_wd,IN_CREATE,"after-oneshot");
    CHECK(stats.step.calls==steps && stats.transaction.calls==transactions);
    logical_create(writer,"/between");
    logical_wd=md_inode_watch_add(s,reader,root,IN_CREATE); CHECK(logical_wd>0);
    CHECK(md_inode_watch_read(s,reader,path,sizeof(path),NULL,NULL)==-EAGAIN);
    CHECK(!md_inode_link(writer,-1,"/between",-1,"/alias",0));
    struct pollfd ready={.fd=md_inode_watch_pollfd(s),.events=POLLIN};
    /* EVENT_WAIT: independent writer's WAL notification; timeout fails. */
    CHECK(poll(&ready,1,5000)==1 && (ready.revents&POLLIN));
    expect_record(reader,s,logical_wd,IN_CREATE,"alias");
    close(reader); CHECK(!md_inode_watch_pump(s) && md_inode_watch_pollfd(s)==-1);
    close(root); close(native); md_inode_store_close(writer); md_inode_store_close(s);
    puts("PASS native/logical transitions, mixed observers, remove/close/oneshot, late cursor, independent hardlink wakeup");
}
int main(int argc, char **argv) {
    CHECK(argc == 2);
    sigset_t mask; sigemptyset(&mask); sigaddset(&mask, SIGPIPE); CHECK(!sigprocmask(SIG_BLOCK, &mask, NULL));
    struct md_inode_store *s, *writer;
    CHECK(!md_inode_store_open(argv[1], 1, &s));
    CHECK(!md_inode_store_open(argv[1], 0, &writer));
    int file = md_inode_create(writer, -1, "/unobserved", 0600); CHECK(file >= 0); close(file);
    CHECK(!count(s));
    int root = md_inode_open(s, -1, "/", O_PATH | O_DIRECTORY, 0); CHECK(root >= 0);
    int reader = md_inode_watch_create(s, IN_NONBLOCK | IN_CLOEXEC); CHECK(reader >= 0);
    int wd = md_inode_watch_add(s, reader, root, IN_CREATE); CHECK(wd > 0);
    file = md_inode_create(writer, -1, "/observed", 0600); CHECK(file >= 0); close(file);
    CHECK(!md_inode_watch_pump(s)); CHECK(count(s) == 1);
    char bytes[1024];
    CHECK(md_inode_watch_read(s, reader, bytes, sizeof(bytes), NULL, NULL) == 32);
    struct inotify_event *e = (void *)bytes;
    CHECK(e->wd == wd && e->mask == IN_CREATE);
    CHECK(!md_inode_watch_pump(s));
    struct pollfd ready={.fd=md_inode_watch_pollfd(s),.events=POLLIN};
    CHECK(!poll(&ready,1,0));
    /* A logical hardlink changes only the namespace journal, not the backing
     * directory. The worker must wake on its WAL write before a checkpoint. */
    CHECK(!md_inode_link(writer,-1,"/observed",-1,"/alias",0));
    /* EVENT_WAIT: committed WAL event; the timeout fails missing wakeup. */
    CHECK(poll(&ready,1,5000)==1 && (ready.revents&POLLIN));
    CHECK(md_inode_watch_read(s,reader,bytes,sizeof(bytes),NULL,NULL)==32);
    e=(void *)bytes;
    CHECK(e->wd==wd && e->mask==IN_CREATE && !strcmp(e->name,"alias"));
    pid_t pid = fork(); CHECK(pid >= 0);
    if (!pid) {
        struct md_inode_store *other;
        CHECK(!md_inode_store_open(argv[1], 0, &other));
        md_inode_observe(other, crash, NULL);
        md_inode_create(other, -1, "/rolled-back", 0600);
        _exit(2);
    }
    int status; CHECK(waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    CHECK(!md_inode_watch_pump(s));
    CHECK(md_inode_watch_bytes(s, reader) == 0 && count(s) == 3);
    struct stat st; CHECK(md_inode_stat(s, -1, "/rolled-back", 0, &st) == -ENOENT);
    puts("PASS watcher sees committed namespace only after writer SIGKILL rollback");
    int alias = dup(reader); CHECK(alias >= 0); close(reader);
    CHECK(!md_inode_watch_pump(s)); CHECK(md_inode_watch_pollfd(s) >= 0);
    close(alias); CHECK(!md_inode_watch_pump(s)); CHECK(md_inode_watch_pollfd(s) == -1);
    file = md_inode_create(writer, -1, "/after-close", 0600); CHECK(file >= 0); close(file);
    CHECK(count(s) == 3);
    puts("PASS kernel last-reader lifetime releases subscriptions and disables journal production");
    reader = md_inode_watch_create(s, IN_NONBLOCK); CHECK(reader >= 0);
    CHECK(md_inode_watch_add(s, reader, root, IN_CREATE) > 0);
    CHECK(!mdi_begin(writer, 1));
    CHECK(!mdi_sql(writer, "INSERT INTO events(sequence,parent,object,name,mask,cookie) "
        "SELECT sequence+70000,parent,object,name,mask,cookie FROM events ORDER BY sequence LIMIT 1"));
    CHECK(!mdi_finish(writer, 0));
    CHECK(!md_inode_watch_pump(s));
    CHECK(md_inode_watch_read(s, reader, bytes, sizeof(bytes), NULL, NULL) == 48);
    e = (void *)bytes;
    CHECK(e->wd == -1 && e->mask == IN_Q_OVERFLOW);
    puts("PASS a missing journal range publishes IN_Q_OVERFLOW");
    close(reader); close(root);
    md_inode_store_close(writer); md_inode_store_close(s);
    native_transitions(argv[1]);
    return 0;
}

#define _GNU_SOURCE
#include "mount_graph.h"
#include "fs_mount_internal.h"
#include "fs_wire.h"
#include "event_wait.h"
#include "mount_topology.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static int fail_allocation=-1;
void test_mount_allocation_failure_after(int count) { fail_allocation=count; }
void test_mount_policy_map_failure_after(int count);
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t n, size_t size) {
    if (fail_allocation==0) { errno=ENOMEM; return NULL; }
    if (fail_allocation>0) --fail_allocation;
    return __real_calloc(n,size);
}
static unsigned descriptors(void) {
    DIR *dir=opendir("/proc/self/fd"); assert(dir);
    unsigned n=0; struct dirent *entry;
    while ((entry=readdir(dir))) if (entry->d_name[0]!='.') ++n;
    assert(!closedir(dir)); return n;
}
static void ready(int fd) {
    /* EVENT_WAIT: exact fixture packet; timeout fails the test. */
    assert(!md_event_wait_fd(fd,POLLIN,md_event_now()+5000000000LL));
}
static void send_byte(int fd, char byte) {
    assert(md_fs_send(fd,&byte,1,&(struct md_fs_rights){0})==1);
}
static char receive_byte(int fd) {
    ready(fd); char byte; struct md_fs_rights rights={0};
    assert(md_fs_receive(fd,&byte,1,&rights)==1 && !rights.count); return byte;
}
static void send_graph(int fd, struct md_mount_graph_parcel *p) {
    assert(md_fs_send(fd,&p->count,sizeof(p->count),&(struct md_fs_rights){0})==sizeof(p->count));
    for (unsigned i=0;i<p->count;) {
        struct md_fs_rights rights={0};
        while (rights.count<MD_FS_MAX_FDS && i<p->count) rights.fd[rights.count++]=p->fd[i++];
        assert(md_fs_send(fd,"g",1,&rights)==1);
    }
    md_mount_graph_parcel_close(p);
}
static struct md_mount_graph_parcel receive_graph(int fd) {
    ready(fd); unsigned count; struct md_fs_rights rights={0};
    assert(md_fs_receive(fd,&count,sizeof(count),&rights)==sizeof(count) && !rights.count);
    assert(count && count<=MD_MOUNT_GRAPH_FDS);
    struct md_mount_graph_parcel p={.fd=calloc(count,sizeof(int))}; assert(p.fd);
    while (p.count<count) {
        ready(fd); char byte;
        assert(md_fs_receive(fd,&byte,1,&rights)==1 && byte=='g' && rights.count
            && rights.count<=count-p.count);
        for (unsigned i=0;i<rights.count;++i) p.fd[p.count++]=rights.fd[i];
    }
    return p;
}
static void channel(int fds[2]) {
    assert(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0,fds));
}
static pid_t start(const char *mode, int fd, const char *base) {
    pid_t parent=getpid(), child=fork(); assert(child>=0);
    if (!child) {
        assert(!prctl(PR_SET_PDEATHSIG,SIGKILL) && getppid()==parent);
        assert(!fcntl(fd,F_SETFD,0)); char number[16]; snprintf(number,sizeof(number),"%d",fd);
        execl("/proc/self/exe","mount-graph",mode,number,base,(char *)NULL); _exit(90);
    }
    return child;
}
static void reap(pid_t child) {
    /* EVENT_WAIT: exact fixture process; outer alarm bounds a stuck child. */
    int status; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
}
static void path(char *out, const char *base, const char *suffix) {
    assert(snprintf(out,PATH_MAX,"%s/%s",base,suffix)<PATH_MAX);
}
static void file(const char *path, const char *text) {
    int fd=open(path,O_CREAT|O_WRONLY|O_CLOEXEC,0600); assert(fd>=0);
    assert(write(fd,text,strlen(text))==(ssize_t)strlen(text)); close(fd);
}
static struct md_filesystem filesystem(const char *base, int create) {
    char store[PATH_MAX]; path(store,base,"store");
    struct md_filesystem fs={0}; assert(!md_inode_store_open(store,create,&fs.store));
    if (!create) return fs;
    char host[3][PATH_MAX], name[PATH_MAX];
    for (unsigned i=0;i<3;++i) {
        char leaf[16]; snprintf(leaf,sizeof(leaf),"host%u",i); path(host[i],base,leaf);
        assert(!mkdir(host[i],0700));
    }
    path(name,host[0],"nested"); assert(!mkdir(name,0700));
    path(name,host[0],"parent"); file(name,"native");
    path(name,host[1],"value"); file(name,"value");
    path(name,host[1],"absolute"); assert(!symlink("/parent",name));
    assert(!md_inode_mkdir(fs.store,-1,"/outer",0700));
    assert(!md_inode_mkdir(fs.store,-1,"/alias",0700));
    int fd=md_inode_open(fs.store,-1,"/parent",O_CREAT|O_WRONLY,0600); assert(fd>=0);
    assert(write(fd,"guest",5)==5); close(fd);
    struct md_fs_attachment entries[]={{host[0],"/outer",0},{host[1],"/outer/nested",1},{host[2],"/alias",0}};
    assert(!md_fs_mounts_open(&fs,entries,3));
    /* The engine supports aliases; launch admission stays restricted until
     * application FD provenance is connected. Build one before publication. */
    struct md_view_mount *a=&fs.mounts->tree->mounts[1], *b=&fs.mounts->tree->mounts[2];
    close(b->source); b->source=fcntl(a->source,F_DUPFD_CLOEXEC,3); assert(b->source>=0);
    b->native=a->native; return fs;
}
static void close_filesystem(struct md_filesystem *fs) {
    md_fs_mounts_close(fs); md_inode_store_close(fs->store); fs->store=NULL;
}
static struct md_fs_result open_file(struct md_filesystem *fs, const char *name, unsigned flags,
        struct md_fs_anchor *origin, struct md_fs_anchor **capture) {
    struct md_fs_request q={.operation=MD_FS_OPEN,.directory={origin ? md_fs_anchor_fd(origin) : -1,-1},
        .origin={origin,NULL},.path={name,NULL},.flags=flags};
    struct md_fs_result out;
    md_fs_execute(fs,&q,&out,&(struct md_fs_output){.origin=capture}); return out;
}
static void contents(struct md_filesystem *fs, const char *name, struct md_fs_anchor *origin, const char *expected) {
    struct md_fs_result r=open_file(fs,name,O_RDONLY,origin,NULL);
    if (r.error) fprintf(stderr,"graph open %s: %d\n",name,r.error);
    assert(!r.error); char bytes[32]={0};
    assert(read(r.fd,bytes,sizeof(bytes)-1)==(ssize_t)strlen(expected) && !strcmp(bytes,expected)); close(r.fd);
}
static void checks(struct md_filesystem *fs, unsigned readonly) {
    assert(fs->mounts->tree->count==3);
    struct md_view_mount *m=fs->mounts->tree->mounts;
    assert(!m[0].parent && m[1].parent==m && !m[2].parent);
    assert(m[0].id!=m[1].id && m[1].id!=m[2].id && m[0].id!=m[2].id);
    contents(fs,"/outer/nested/value",NULL,"value");
    contents(fs,"/alias/value",NULL,"value");
    contents(fs,"/outer/nested/../parent",NULL,"native");
    contents(fs,"/alias/../parent",NULL,"guest");
    contents(fs,"/outer/nested/absolute",NULL,"guest");
    struct md_fs_result r=open_file(fs,"/outer/nested/value",O_RDWR,NULL,NULL);
    if (readonly) assert(r.error==-EROFS && r.fd<0);
    else { assert(!r.error); close(r.fd); }
    r=open_file(fs,"/alias/value",O_RDWR,NULL,NULL); assert(!r.error); close(r.fd);
}
static void duplicate_manifest(struct md_mount_graph_parcel *p, unsigned word, uint32_t value,
        int seals, int length_adjustment) {
    uint32_t words[256]; ssize_t n=pread(p->fd[0],words,sizeof(words),0); assert(n>=16);
    words[word]=value;
    int fd=memfd_create("graph-invalid",MFD_CLOEXEC|MFD_ALLOW_SEALING); assert(fd>=0);
    assert(write(fd,words,(size_t)n)==n);
    if (length_adjustment) assert(!ftruncate(fd,n+length_adjustment));
    assert(!fcntl(fd,F_ADD_SEALS,seals)); close(p->fd[0]); p->fd[0]=fd;
}
static void failures(struct md_filesystem *source) {
    puts("CHECK mount graph malformed parcels");
    struct md_mount_graph_parcel p={0};
    assert(!md_mount_graph_export(source->mounts,&p)); md_mount_graph_parcel_close(&p);
    unsigned before=descriptors();
    for (unsigned i=0;i<14;++i) {
        assert(!md_mount_graph_export(source->mounts,&p));
        int seals=F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL;
        switch (i) {
        case 0: duplicate_manifest(&p,0,0,seals,0); break;
        case 1: duplicate_manifest(&p,1,UINT32_MAX,seals,0); break;
        case 2: duplicate_manifest(&p,2,MD_FS_MOUNTS_MAX+1,seals,0); break;
        case 3: duplicate_manifest(&p,3,1,seals,0); break;
        case 4: duplicate_manifest(&p,8,1,seals,0); break;
        case 5: duplicate_manifest(&p,9,UINT32_MAX,seals,0); break;
        case 6: duplicate_manifest(&p,1,3,seals,1); break;
        case 7: duplicate_manifest(&p,1,3,seals&~F_SEAL_WRITE,0); break;
        case 8: { int fd=p.fd[2]; p.fd[2]=p.fd[3]; p.fd[3]=fd; break; }
        case 9: { int fd=p.fd[4]; p.fd[4]=p.fd[7]; p.fd[7]=fd; break; }
        case 10: close(p.fd[--p.count]); break;
        case 11: assert(!fcntl(p.fd[1],F_SETFD,0)); break;
        case 12: close(p.fd[2]); p.fd[2]=p.fd[1]; break;
        case 13: duplicate_manifest(&p,8,2,seals,0); break;
        }
        struct md_mount_namespace *view=NULL;
        assert(md_mount_graph_import(&p,&view)<0 && !view && !p.count);
        assert(descriptors()==before);
    }
    for (int i=0;i<3;++i) {
        printf("CHECK mount graph allocation failure %d\n",i);
        assert(!md_mount_graph_export(source->mounts,&p));
        struct md_mount_namespace *view=NULL; fail_allocation=i;
        int result=md_mount_graph_import(&p,&view);
        fail_allocation=-1;
        assert(result==-ENOMEM && !view && !p.count && descriptors()==before);
    }
    for (int i=0;i<3;++i) {
        printf("CHECK mount graph mapping failure %d\n",i);
        assert(!md_mount_graph_export(source->mounts,&p));
        struct md_mount_namespace *view=NULL; test_mount_policy_map_failure_after(i);
        int result=md_mount_graph_import(&p,&view);
        test_mount_policy_map_failure_after(-1);
        assert(result==-ENOMEM && !view && !p.count && descriptors()==before);
    }
    puts("CHECK mount graph descriptor exhaustion");
    int guard=fcntl(source->mounts->tree->mounts[0].source,F_DUPFD_CLOEXEC,3); assert(guard>=3);
    assert(fcntl(3,F_GETFD)>=0);
    struct rlimit old, limited; assert(!getrlimit(RLIMIT_NOFILE,&old)); limited=old; limited.rlim_cur=4;
    assert(!setrlimit(RLIMIT_NOFILE,&limited));
    int result=md_mount_graph_export(source->mounts,&p);
    assert(!setrlimit(RLIMIT_NOFILE,&old));
    assert(result==-EMFILE && !p.count); close(guard); assert(descriptors()==before);
    /* Leave exactly one admissible slot: manifest duplication succeeds, source
     * duplication fails, and rollback must release the partial parcel. */
    limited.rlim_cur=128; if (limited.rlim_cur>old.rlim_cur) limited.rlim_cur=old.rlim_cur;
    assert(!setrlimit(RLIMIT_NOFILE,&limited));
    int fill[128]; unsigned filled=0;
    while ((guard=fcntl(source->mounts->tree->mounts[0].source,F_DUPFD_CLOEXEC,3))>=0) {
        assert(filled<128); fill[filled++]=guard;
    }
    assert(errno==EMFILE && filled); close(fill[--filled]);
    result=md_mount_graph_export(source->mounts,&p);
    assert(!setrlimit(RLIMIT_NOFILE,&old));
    assert(result==-EMFILE && !p.count);
    while (filled) close(fill[--filled]);
    assert(descriptors()==before);
    struct md_view_mount *alias=&source->mounts->tree->mounts[2];
    alias->parent=&source->mounts->tree->mounts[0];
    assert(md_mount_graph_export(source->mounts,&p)==-ESTALE && !p.count);
    alias->parent=NULL; assert(descriptors()==before);
    puts("PASS mount graph rollback: malformed graph/rights, allocation and FD exhaustion, frozen topology identity");
}
static void unordered(const char *base) {
    char directory[PATH_MAX]; path(directory,base,"unordered"); assert(!mkdir(directory,0700));
    unsigned before=descriptors(); struct md_filesystem fs=filesystem(directory,1);
    struct md_view_mount *m=fs.mounts->tree->mounts, saved=m[0];
    m[0]=m[1]; m[1]=saved; m[0].parent=&m[1];
    unsigned order[MD_FS_MOUNTS_MAX];
    assert(!md_view_topology_order(fs.mounts->tree,order));
    assert(order[0]==1 && order[1]==2 && order[2]==0);
    contents(&fs,"/outer/nested/value",NULL,"value");
    struct md_mount_graph_parcel p={0}; assert(!md_mount_graph_export(fs.mounts,&p));
    struct md_filesystem imported={.store=fs.store};
    assert(!md_mount_graph_import(&p,&imported.mounts));
    assert(imported.mounts->tree->mounts[0].parent==&imported.mounts->tree->mounts[1]);
    contents(&imported,"/outer/nested/../parent",NULL,"native");
    struct md_mount_namespace *copy=NULL; struct md_fs_location root;
    assert(!md_fs_mounts_copy(&fs,&(struct md_fs_location){0},&copy,&root));
    assert(copy->tree->mounts[0].parent==&copy->tree->mounts[1]);
    copy->tree->mounts[1].parent=&copy->tree->mounts[0];
    assert(md_mount_graph_export(copy,&p)==-ELOOP && !p.count);
    md_mount_namespace_release(copy); md_fs_mounts_close(&imported); close_filesystem(&fs);
    assert(descriptors()==before);
    puts("PASS mount topology: child-before-parent placement, portable graph/copy and cycle rejection");
}
static void sizes(const char *base) {
    unsigned before=descriptors();
    struct md_mount_namespace *empty=md_mount_namespace_new(), *received=NULL; assert(empty);
    struct md_mount_graph_parcel p={0}; assert(!md_mount_graph_export(empty,&p) && p.count==2);
    assert(!md_mount_graph_import(&p,&received) && !received->tree);
    md_mount_namespace_release(empty); md_mount_namespace_release(received);
    char store[PATH_MAX], host[MD_FS_MOUNTS_MAX][PATH_MAX], target[MD_FS_MOUNTS_MAX][32];
    path(store,base,"max-store"); struct md_filesystem fs={0};
    assert(!md_inode_store_open(store,1,&fs.store));
    struct md_fs_attachment entries[MD_FS_MOUNTS_MAX];
    for (unsigned i=0;i<MD_FS_MOUNTS_MAX;++i) {
        char leaf[32]; snprintf(leaf,sizeof(leaf),"max-host-%u",i); path(host[i],base,leaf);
        snprintf(target[i],sizeof(target[i]),"/volume-%u",i);
        assert(!mkdir(host[i],0700) && !md_inode_mkdir(fs.store,-1,target[i],0700));
        entries[i]=(struct md_fs_attachment){host[i],target[i],i&1};
    }
    assert(!md_fs_mounts_open(&fs,entries,MD_FS_MOUNTS_MAX));
    assert(!md_mount_graph_export(fs.mounts,&p) && p.count==MD_MOUNT_GRAPH_PLACEMENT_FDS);
    received=NULL; assert(!md_mount_graph_import(&p,&received));
    assert(received->tree->count==MD_FS_MOUNTS_MAX);
    for (unsigned i=0;i<MD_FS_MOUNTS_MAX;++i) {
        assert(md_view_readonly(&received->tree->mounts[i])==(int)(i&1));
        assert(md_view_same(&received->tree->mounts[i].native,&fs.mounts->tree->mounts[i].native));
    }
    md_mount_namespace_release(received); close_filesystem(&fs); assert(descriptors()==before);
    puts("PASS mount graph bounds: empty and maximum topology, exact rights count and cleanup");
}
static void models(const char *base) {
    puts("CHECK mount graph source setup");
    unsigned before=descriptors(); struct md_filesystem source=filesystem(base,1);
    assert(!source.mounts->graph);
    struct md_mount_graph_parcel p={0};
    puts("CHECK mount graph lazy publication failure");
    fail_allocation=0;
    int result=md_mount_graph_export(source.mounts,&p);
    fail_allocation=-1;
    assert(result==-ENOMEM && !p.count && !source.mounts->graph);
    checks(&source,1); failures(&source);
    assert(!md_mount_graph_export(source.mounts,&p));
    struct md_filesystem imported={.store=source.store};
    assert(!md_mount_graph_import(&p,&imported.mounts) && !p.count);
    checks(&imported,1); struct md_mount_namespace *saved=imported.mounts;
    unsigned id=saved->tree->mounts[1].id, objects=saved->tree->objects, current=descriptors();
    assert(id!=source.mounts->tree->mounts[1].id);
    for (unsigned i=0;i<10;++i) {
        assert(!md_mount_graph_export(source.mounts,&p));
        assert(!md_mount_graph_import(&p,&imported.mounts));
        assert(imported.mounts==saved && saved->tree->mounts[1].id==id
            && saved->tree->objects==objects && descriptors()==current);
    }
    assert(!md_mount_graph_export(source.mounts,&p));
    saved->tree->mounts[2].parent=&saved->tree->mounts[0];
    assert(md_mount_graph_import(&p,&imported.mounts)==-ESTALE && imported.mounts==saved);
    saved->tree->mounts[2].parent=NULL; assert(descriptors()==current);
    /* Forwarding keeps the sealed identity; it does not publish a new graph. */
    assert(!md_mount_graph_export(imported.mounts,&p));
    assert(!md_mount_graph_import(&p,&source.mounts));
    struct md_mount_namespace *copy=NULL; struct md_fs_location root;
    assert(!md_fs_mounts_copy(&source,&(struct md_fs_location){0},&copy,&root) && !copy->graph);
    assert(!md_mount_graph_export(copy,&p));
    assert(md_mount_graph_import(&p,&imported.mounts)==-ESTALE && imported.mounts==saved);
    md_mount_namespace_release(copy);
    assert(!md_mount_policy_set(&source.mounts->tree->mounts[1].policy,0)); checks(&imported,0);
    assert(md_mount_policy_set(&imported.mounts->tree->mounts[1].policy,1)==-EPERM);
    struct md_fs_anchor *origin=NULL;
    struct md_fs_result r=open_file(&imported,"/outer/nested",O_PATH|O_DIRECTORY,NULL,&origin);
    assert(!r.error && origin); close(r.fd);
    md_fs_mounts_close(&imported); md_fs_mounts_close(&source);
    assert(!md_fs_mounts_open(&imported,NULL,0));
    contents(&imported,"../parent",origin,"native");
    md_fs_anchor_release(origin); md_fs_mounts_close(&imported); md_inode_store_close(source.store);
    assert(descriptors()==before);
    puts("PASS mount graph engine: nested parents, aliases, local IDs, repeated/forwarded import, live policy and retained dirfd");
}
int test_mount_graph_child(int argc, char **argv) {
    if (argc!=4 || (strcmp(argv[1],"--graph-reader") && strcmp(argv[1],"--graph-writer"))) return -1;
    alarm(30); int fd=atoi(argv[2]); assert(!fcntl(fd,F_SETFD,FD_CLOEXEC));
    unsigned before=descriptors();
    if (!strcmp(argv[1],"--graph-writer")) {
        struct md_filesystem fs=filesystem(argv[3],1); struct md_mount_graph_parcel p={0};
        assert(!md_mount_graph_export(fs.mounts,&p)); send_graph(fd,&p); close_filesystem(&fs);
    } else {
        struct md_filesystem fs=filesystem(argv[3],0);
        struct md_mount_graph_parcel p=receive_graph(fd);
        assert(!md_mount_graph_import(&p,&fs.mounts)); checks(&fs,1); send_byte(fd,'r');
        assert(receive_byte(fd)=='u'); checks(&fs,0); send_byte(fd,'r');
        assert(receive_byte(fd)=='x'); checks(&fs,0); close_filesystem(&fs);
    }
    assert(descriptors()==before); close(fd); return 0;
}
static void processes(const char *base) {
    unsigned before=descriptors(); char path1[PATH_MAX], path2[PATH_MAX];
    path(path1,base,"live"); path(path2,base,"exited");
    assert(!mkdir(path1,0700) && !mkdir(path2,0700));
    struct md_filesystem fs=filesystem(path1,1); int pair[2]; channel(pair);
    pid_t child=start("--graph-reader",pair[1],path1); close(pair[1]);
    struct md_mount_graph_parcel p={0}; assert(!md_mount_graph_export(fs.mounts,&p));
    /* Replace the old path before import. Neither source nor covered dentries
     * may be rediscovered by a pathname in the receiving process. */
    char old[PATH_MAX], moved[PATH_MAX], wrong[PATH_MAX];
    path(old,path1,"host0"); path(moved,path1,"moved");
    assert(!rename(old,moved) && !mkdir(old,0700)); path(wrong,old,"parent"); file(wrong,"wrong");
    send_graph(pair[0],&p); assert(receive_byte(pair[0])=='r');
    assert(!md_mount_policy_set(&fs.mounts->tree->mounts[1].policy,0));
    send_byte(pair[0],'u'); assert(receive_byte(pair[0])=='r');
    close_filesystem(&fs); send_byte(pair[0],'x'); reap(child); close(pair[0]);
    channel(pair); child=start("--graph-writer",pair[1],path2); close(pair[1]);
    reap(child); p=receive_graph(pair[0]); close(pair[0]);
    fs=filesystem(path2,0); assert(!md_mount_graph_import(&p,&fs.mounts));
    checks(&fs,1); close_filesystem(&fs); assert(descriptors()==before);
    puts("PASS mount graph exec peers: real rights, replaced source path, live policy, publisher teardown/exit and exact FD balance");
}
void test_mount_graph(const char *base) {
    alarm(60); char model[PATH_MAX], peers[PATH_MAX];
    path(model,base,"graph-model"); path(peers,base,"graph-peers");
    assert(!mkdir(model,0700) && !mkdir(peers,0700));
    models(model); sizes(base); unordered(base); processes(peers); alarm(0);
}

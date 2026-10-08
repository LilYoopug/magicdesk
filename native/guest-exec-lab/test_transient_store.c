#define _GNU_SOURCE
#include "inode_internal.h"
#include "inode_custody.h"
#include "temporary_directory.h"
#include "fs_wire.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

void test_mount_allocation_failure_after(int count);
static unsigned descriptors(void) {
    DIR *d=opendir("/proc/self/fd"); assert(d); unsigned count=0;
    struct dirent *entry;
    while ((entry=readdir(d))) if (entry->d_name[0]!='.') ++count;
    assert(!closedir(d)); return count;
}
static unsigned entries(int parent) {
    int fd=openat(parent,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC); assert(fd>=0);
    DIR *d=fdopendir(fd); assert(d); unsigned count=0; struct dirent *entry;
    while ((entry=readdir(d)))
        if (strcmp(entry->d_name,".") && strcmp(entry->d_name,"..")) ++count;
    assert(!closedir(d)); return count;
}
static void content(struct md_inode_store *store) {
    int fd=md_inode_open(store,-1,"/file",O_RDONLY,0); assert(fd>=0);
    char text[16]; assert(read(fd,text,sizeof(text))==5 && !memcmp(text,"hello",5));
    assert(!close(fd));
    assert(!md_inode_link(store,-1,"/file",-1,"/linked",0));
    fd=md_inode_open(store,-1,"/linked",O_RDWR,0); assert(fd>=0);
    assert(pwrite(fd,"!",1,4)==1 && !close(fd));
}
int test_transient_store_child(int argc, char **argv) {
    if (argc!=4 || strcmp(argv[1],"--transient-receiver")) return -1;
    alarm(30);
    int socket=atoi(argv[2]), gate=atoi(argv[3]); char byte;
    /* EVENT_WAIT: parent has released its store before receipt begins. */
    assert(read(gate,&byte,1)==1 && byte=='g'); close(gate);
    struct md_inode_custody_parcel parcel={0};
    assert(md_fs_receive_fds(socket,&byte,1,parcel.fd,3,&parcel.count)==1);
    assert(parcel.count==3);
    struct md_inode_lifetime *owner=NULL;
    assert(!md_inode_custody_import(&parcel,parcel.fd[1],&owner) && owner->temporary);
    assert(owner->owner && md_user_namespace_into(owner->owner,0,0)==1000);
    assert(md_user_namespace_into(owner->owner,1,0)==2000);
    assert(md_user_namespace_from(owner->owner,0,0)==UINT32_MAX);
    struct md_inode_store *store=NULL;
    assert(!md_inode_store_reconnect(owner,&store));
    content(store);
    md_inode_store_close(store);
    md_inode_lifetime_release(owner);
    assert(write(socket,"d",1)==1); close(socket); return 0;
}
static void transferred(int parent) {
    struct md_user_namespace *namespace=md_user_namespace_new(NULL,1000,2000,0); assert(namespace);
    struct md_user_authority authority={.uid=1000,.gid=2000,.caps=UINT64_MAX};
    struct md_id_extent map={0,1000,1};
    assert(!md_user_namespace_map(namespace,0,&authority,&authority,&map,1));
    map.outside=2000;
    assert(!md_user_namespace_map(namespace,1,&authority,&authority,&map,1));
    struct md_inode_store *store=NULL; assert(!md_inode_store_transient(parent,namespace,&store));
    md_user_namespace_release(namespace);
    int file=md_inode_open(store,-1,"/file",O_CREAT|O_WRONLY,0600); assert(file>=0);
    assert(write(file,"hello",5)==5 && !close(file));
    struct md_inode_custody_parcel parcel={0};
    assert(!md_inode_custody_export(store->lifetime,&parcel));
    int pair[2], gate[2]; assert(!socketpair(AF_UNIX,SOCK_SEQPACKET,0,pair) && !pipe(gate));
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        close(pair[0]); close(gate[1]);
        char number[32], barrier[32]; snprintf(number,sizeof(number),"%d",pair[1]);
        snprintf(barrier,sizeof(barrier),"%d",gate[0]);
        execl("/proc/self/exe","test","--transient-receiver",number,barrier,NULL); _exit(120);
    }
    close(pair[1]); close(gate[0]);
    /* The command packet is separate from queued rights. Child cannot receive
     * its object before the parent has dropped all local ownership. */
    assert(md_fs_send_fds(pair[0],"p",1,parcel.fd,parcel.count)==1);
    md_inode_custody_parcel_close(&parcel); md_inode_store_close(store);
    assert(!md_temporary_directory_collect(parent) && entries(parent)==1);
    assert(write(gate[1],"g",1)==1); close(gate[1]);
    char byte;
    /* EVENT_WAIT: receiver completed IO and released its final owner. */
    assert(read(pair[0],&byte,1)==1 && byte=='d'); close(pair[0]);
    int status;
    assert(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    assert(!entries(parent));
}
void test_transient_store(const char *base) {
    char path[PATH_MAX]; snprintf(path,sizeof(path),"%s/transient",base);
    assert(!mkdir(path,0700));
    int parent=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC); assert(parent>=0);
    unsigned before=descriptors();
    for (unsigned i=0;i<32;++i) {
        struct md_inode_store *s=NULL; assert(!md_inode_store_transient(parent,NULL,&s));
        assert(s->lifetime->temporary && !md_temporary_directory_check(s->lifetime->root));
        int fd=md_inode_open(s,-1,"/file",O_CREAT|O_WRONLY,0600); assert(fd>=0);
        assert(write(fd,"hello",5)==5 && !close(fd));
        struct md_inode_lifetime *owner=md_inode_lifetime_retain(s->lifetime);
        md_inode_store_close(s);
        assert(entries(parent)==1 && !md_temporary_directory_collect(parent));
        assert(!md_inode_store_reconnect(owner,&s)); content(s);
        md_inode_store_close(s); md_inode_lifetime_release(owner);
        assert(entries(parent)==0 && descriptors()==before);
    }
    puts("PASS transient stores: retained connection reopen, shared data and exact final retirement");
    for (unsigned drop=0;drop<2;++drop) {
        struct md_inode_store *s=NULL; assert(!md_inode_store_transient(parent,NULL,&s));
        struct md_inode_custody_parcel p={0}; assert(!md_inode_custody_export(s->lifetime,&p));
        md_inode_store_close(s);
        assert(entries(parent)==1 && !md_temporary_directory_collect(parent));
        if (drop) {
            md_inode_custody_parcel_close(&p);
            assert(entries(parent)==1 && !md_temporary_directory_collect(parent));
        } else {
            struct md_inode_lifetime *owner=NULL;
            assert(!md_inode_custody_import(&p,p.fd[1],&owner) && owner->temporary);
            md_inode_lifetime_release(owner);
        }
        assert(!entries(parent) && descriptors()==before);
    }
    puts("PASS transient custody: import, unpublished parcel discard and admission recovery");
    transferred(parent);
    assert(descriptors()==before);
    puts("PASS transient store: queued rights outlive publisher, fresh exec importer owns final cleanup");
    for (int i=0;i<4;++i) {
        struct md_inode_store *s=NULL;
        test_mount_allocation_failure_after(i);
        int r=md_inode_store_transient(parent,NULL,&s);
        test_mount_allocation_failure_after(-1);
        if (!r) md_inode_store_close(s);
        else assert(r==-ENOMEM && !s);
        assert(!md_temporary_directory_collect(parent) && !entries(parent) && descriptors()==before);
    }
    assert(!close(parent));
}

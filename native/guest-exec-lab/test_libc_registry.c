#define _GNU_SOURCE
#include "libc_registry.h"
#include "cooperative_entry.h"
#include "fs_mount_internal.h"
#include "inode_internal.h"
#include "image_identity.h"
#include "elf.h"
#include "raw.h"
#include "fs_storage.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static unsigned descriptors(void) {
    DIR *d=opendir("/proc/self/fd"); assert(d);
    unsigned n=0; struct dirent *e;
    while ((e=readdir(d))) if (e->d_name[0]!='.') ++n;
    closedir(d); return n;
}
static void elf_file(int fd,unsigned char marker) {
    unsigned char data[4096]={0};
    Elf64_Ehdr *h=(void *)data;
    *h=(Elf64_Ehdr){.e_type=ET_DYN,.e_machine=EM_AARCH64,.e_version=EV_CURRENT,
        .e_entry=256,.e_phoff=sizeof(*h),.e_ehsize=sizeof(*h),
        .e_phentsize=sizeof(Elf64_Phdr),.e_phnum=1};
    memcpy(h->e_ident,ELFMAG,SELFMAG);
    h->e_ident[EI_CLASS]=ELFCLASS64; h->e_ident[EI_DATA]=ELFDATA2LSB; h->e_ident[EI_VERSION]=EV_CURRENT;
    Elf64_Phdr *p=(void *)(data+sizeof(*h));
    *p=(Elf64_Phdr){.p_type=PT_LOAD,.p_flags=PF_R|PF_X,.p_filesz=sizeof(data),.p_memsz=sizeof(data)};
    data[256]=marker;
    assert(pwrite(fd,data,sizeof(data),0)==sizeof(data));
    assert(!md_elf_validate(fd,1));
}
static void manifest(int dir,const char *hash,unsigned abi) {
    int fd=openat(dir,"manifest",O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600); assert(fd>=0);
    assert(dprintf(fd,"shroot-libc-1\n%u\nmusl\n1.2.5\n%064d\n/lib/ld-musl-aarch64.so.1\n/lib/ld-musl-aarch64.so.1\n%s\n%s\nlib/libc.so\n",
        abi,0,hash,hash)>0);
    close(fd);
}
static struct md_fs_result call(struct md_filesystem *fs,unsigned op,const char *path,unsigned mode) {
    struct md_fs_request q={.operation=op,.directory={-1,-1},.path={path,NULL},.mode=mode};
    struct md_fs_result out;
    md_fs_execute(fs,&q,&out,NULL); return out;
}
static void selected(struct md_filesystem *fs,int interpreter,unsigned char marker) {
    struct md_image_identity identity;
    struct md_fs_anchor *origin=NULL;
    struct md_fs_request q={.operation=MD_FS_OPEN_IMAGE,.directory={-1,-1},
        .path={"/lib/ld-musl-aarch64.so.1",NULL},.mode=interpreter ? MD_FS_IMAGE_INTERPRETER : 0};
    struct md_fs_output output={.data=&identity,.capacity=sizeof(identity),.origin=&origin};
    struct md_fs_result out;
    md_fs_execute(fs,&q,&out,&output);
    if (out.error) fprintf(stderr,"libc selection: %d\n",out.error);
    assert(!out.error && out.fd>=0);
    unsigned char byte=0; assert(pread(out.fd,&byte,1,256)==1);
    if (byte!=marker) fprintf(stderr,"libc marker expected=%c actual=%c\n",marker,byte);
    assert(byte==marker);
    close(out.fd); md_fs_anchor_release(origin);
}
void test_libc_registry(const char *base) {
    md_page_size=(size_t)sysconf(_SC_PAGESIZE);
    unsigned baseline=descriptors();
    char root[PATH_MAX],candidate[PATH_MAX],path[PATH_MAX],store_path[PATH_MAX];
    snprintf(root,sizeof(root),"%s/registry",base); assert(!mkdir(root,0700));
    snprintf(candidate,sizeof(candidate),"%s/candidate",base); assert(!mkdir(candidate,0700));
    int dir=open(candidate,O_RDONLY|O_DIRECTORY|O_CLOEXEC); assert(dir>=0);
    assert(!mkdirat(dir,"lib",0700));
    int replacement=openat(dir,"lib/libc.so",O_CREAT|O_RDWR|O_CLOEXEC,0700); assert(replacement>=0);
    elf_file(replacement,'B');
    snprintf(store_path,sizeof(store_path),"%s/store",base);
    struct md_inode_store *store=NULL; assert(!md_inode_store_open(store_path,1,&store));
    struct md_identity identity=md_identity_new(0,0); store->identity=&identity;
    struct md_fs_storage_cache cache={0};
    struct md_filesystem fs={.store=store,.storage=&cache}; assert(!md_fs_mounts_open(&fs,NULL,0));
    assert(!call(&fs,MD_FS_CHMOD,"/",0755).error);
    assert(!call(&fs,MD_FS_MKDIR,"/lib",0755).error);
    struct md_fs_result opened=call(&fs,MD_FS_CREATE,"/lib/ld-musl-aarch64.so.1",0755);
    assert(!opened.error && opened.fd>=0); elf_file(opened.fd,'A');
    char hash[65]; assert(!md_libc_registry_hash(NULL,opened.fd,hash));
    manifest(dir,hash,MD_ENTRY_VERSION);
    struct md_libc_manifest m; assert(!md_libc_manifest_read(dir,&m));
    assert(!md_libc_registry_open(root,&fs.libc_registry));
    assert(md_libc_registry_count(fs.libc_registry)==0);
    selected(&fs,1,'A');
    assert(!md_libc_registry_publish(root,candidate));
    assert(md_libc_registry_publish(root,candidate)==-EEXIST);
    snprintf(path,sizeof(path),"%s/%064d",root,1);
    assert(!symlink(candidate,path)); /* A broken entry cannot mask valid builds. */
    assert(!md_libc_registry_refresh(fs.libc_registry));
    assert(!unlink(path));
    selected(&fs,0,'A');
    struct md_identity user=md_identity_new(1000,1000);
    store->identity=&user; selected(&fs,1,'A'); /* Cannot create a privileged attachment point. */
    store->identity=&identity; selected(&fs,1,'B');
    store->identity=&user; selected(&fs,1,'B'); /* Prepared readonly mount is usable without root. */
    store->identity=&identity; md_identity_release(&user);
    assert(md_libc_registry_count(fs.libc_registry)==1);
    elf_file(replacement,'C'); selected(&fs,1,'B'); /* Published copy, not builder inode. */
    assert(!md_libc_registry_prune(root)); selected(&fs,1,'B'); /* Active lease. */
    snprintf(path,sizeof(path),"%s/%s/lib/libc.so",MD_LIBC_PREFIX,m.key);
    struct md_fs_request writable={.operation=MD_FS_OPEN,.directory={-1,-1},.path={path,NULL},.flags=O_WRONLY};
    struct md_fs_result denied; md_fs_execute(&fs,&writable,&denied,NULL); assert(denied.error==-EROFS);
    assert(!call(&fs,MD_FS_MKDIR,"/etc",0755).error);
    assert(!call(&fs,MD_FS_MKDIR,"/etc/shroot",0755).error);
    struct md_fs_result flag=call(&fs,MD_FS_CREATE,"/etc/shroot/libc-base",0644); assert(!flag.error); close(flag.fd);
    selected(&fs,1,'A'); assert(!call(&fs,MD_FS_UNLINK,"/etc/shroot/libc-base",0).error);
    elf_file(opened.fd,'D'); selected(&fs,1,'D'); /* Package update invalidates match/cache. */
    elf_file(opened.fd,'A'); selected(&fs,1,'B');
    md_fs_mounts_close(&fs); md_libc_registry_close(fs.libc_registry); fs.libc_registry=NULL;
    assert(!md_fs_mounts_open(&fs,NULL,0));
    assert(!md_libc_registry_open(root,&fs.libc_registry));
    selected(&fs,1,'B'); /* Empty persisted mountpoint is reusable. */
    md_libc_registry_close(fs.libc_registry); fs.libc_registry=NULL;
    assert(!md_libc_registry_prune(root)); /* The mounted duplicate owns the same lease. */
    snprintf(path,sizeof(path),"%s/%s",root,m.key); assert(!access(path,F_OK));
    md_fs_mounts_close(&fs);
    assert(!md_libc_registry_prune(root));
    assert(!md_libc_registry_open(root,&fs.libc_registry));
    assert(!md_libc_registry_count(fs.libc_registry));
    md_libc_registry_close(fs.libc_registry); fs.libc_registry=NULL;
    /* Reject unsafe exports before publication. */
    assert(!symlinkat("/etc/passwd",dir,"escape"));
    assert(md_libc_registry_publish(root,candidate)==-EINVAL); assert(!unlinkat(dir,"escape",0));
    manifest(dir,hash,MD_ENTRY_VERSION+1);
    assert(md_libc_registry_publish(root,candidate)==-EPROTONOSUPPORT);
    manifest(dir,hash,MD_ENTRY_VERSION);
    int corrupt=openat(dir,"manifest",O_WRONLY|O_APPEND|O_CLOEXEC); assert(corrupt>=0);
    assert(write(corrupt,"\0",1)==1); close(corrupt);
    assert(md_libc_registry_publish(root,candidate)==-EBADMSG);
    manifest(dir,hash,MD_ENTRY_VERSION);
    assert(pwrite(replacement,"bad",3,0)==3);
    assert(md_libc_registry_publish(root,candidate)==-ENOEXEC);
    close(opened.fd); close(replacement); close(dir);
    md_fs_storage_close(&cache);
    store->identity=NULL; md_identity_release(&identity); md_inode_store_close(store);
    assert(descriptors()==baseline);
    puts("PASS libc registry: immutable publication, refresh, exact matching, Base, readonly, leases, prune and FD cleanup");
}

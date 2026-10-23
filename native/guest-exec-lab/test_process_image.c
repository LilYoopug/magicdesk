#define _GNU_SOURCE
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct image_open_how { uint64_t flags, mode, resolve; };
enum { NO_XDEV = 1, NO_MAGICLINKS = 2, NO_SYMLINKS = 4, BENEATH = 8, IN_ROOT = 16, CACHED = 32 };
static int extended(int fd, const char *path, uint64_t flags, uint64_t resolve) {
    struct image_open_how how = {flags, 0, resolve};
    return (int)syscall(SYS_openat2, fd, path, &how, sizeof(how));
}
static void image(int base, const char *name, int argc, char **argv) {
    char buffer[8192];
    int fd = openat(base, name, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { fprintf(stderr, "open image %s base=%d: %s\n", name, base, strerror(errno)); }
    assert(fd >= 0);
    ssize_t n = read(fd, buffer, sizeof(buffer)); assert(n > 0);
    size_t offset = 0;
    for (int i = 0; i < argc; ++i) {
        size_t bytes = strlen(argv[i]) + 1;
        assert(offset + bytes <= (size_t)n && !memcmp(buffer + offset, argv[i], bytes));
        offset += bytes;
    }
    assert(offset == (size_t)n && read(fd, buffer, 1) == 0);
    assert(lseek(fd, 0, SEEK_SET) == 0);
    close(fd);
}
static void protected_image(int argc,char **argv,int other_user) {
    int ready[2],finish[2]; assert(!pipe(ready) && !pipe(finish));
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        assert(!prctl(PR_SET_DUMPABLE,0,0,0,0));
        char executable[4096];
        assert(readlink("/proc/self/exe",executable,sizeof(executable))>0);
        int fd=open("/proc/self/exe",O_RDONLY|O_CLOEXEC); assert(fd>=0);
        unsigned char elf[4];
        assert(read(fd,elf,sizeof(elf))==sizeof(elf) && !memcmp(elf,"\177ELF",sizeof(elf)));
        assert(!close(fd));
        argv[0][0]='X';
        assert(write(ready[1],"!",1)==1);
        char byte; assert(read(finish[0],&byte,1)==1);
        _exit(0);
    }
    char byte; assert(read(ready[0],&byte,1)==1);
    if (other_user) assert(!seteuid(1000));
    char path[128]; snprintf(path,sizeof(path),"/proc/%d/cmdline",child);
    char first=argv[0][0]; argv[0][0]='X';
    image(AT_FDCWD,path,argc,argv); argv[0][0]=first;
    snprintf(path,sizeof(path),"/proc/%d/auxv",child);
    int fd=open(path,O_RDONLY); assert(fd==-1 && errno==EACCES);
    snprintf(path,sizeof(path),"/proc/%d/exe",child);
    fd=open(path,O_RDONLY); assert(fd==-1 && errno==EACCES);
    char executable[4096];
    assert(readlink(path,executable,sizeof(executable))==-1 && errno==EACCES);
    if (other_user) assert(!seteuid(0));
    assert(write(finish[1],"!",1)==1);
    int status; assert(waitpid(child,&status,0)==child && status==0);
    close(ready[0]); close(ready[1]); close(finish[0]); close(finish[1]);
    puts("PASS protected process image: self exe and live cmdline readable; foreign auxv/exe stay denied");
}
static void title_snapshot(const char *path,const char *expected,size_t size) {
    int fd=open(path,O_RDONLY|O_CLOEXEC); assert(fd>=0);
    size_t offset=0;
    char bytes[127];
    while (offset<size) {
        ssize_t n=read(fd,bytes,sizeof(bytes));
        assert(n>0 && (size_t)n<=size-offset && !memcmp(bytes,expected+offset,(size_t)n));
        offset+=(size_t)n;
    }
    assert(read(fd,bytes,1)==0);
    assert(pread(fd,bytes,1,(off_t)size)==0);
    if (size>1) assert(pread(fd,bytes,1,1)==1 && bytes[0]==expected[1]);
    close(fd);
}
static void process_title(int argc,char **argv) {
    extern char **environ;
    char *start=argv[0], *end=argv[argc-1]+strlen(argv[argc-1])+1;
    assert(environ[0]==end);
    size_t arguments=(size_t)(end-start);
    for (unsigned i=0;environ[i];++i) end=environ[i]+strlen(environ[i])+1;
    size_t total=(size_t)(end-start), page=(size_t)sysconf(_SC_PAGESIZE);
    assert(total>page && total>arguments+64);
    char *backup=malloc(total); assert(backup); memcpy(backup,start,total);
    for (unsigned mode=0;mode<4;++mode) {
        memset(start,'T',total);
        size_t size;
        if (mode==0) { size=arguments+64; start[size-1]=0; if (size>page) size=page; }
        else if (mode==1) { memcpy(start,"new title",10); size=10; }
        else if (mode==2) size=page;
        else { start[arguments-1]=0; start[1]=0; size=arguments; }
        title_snapshot("/proc/self/cmdline",start,size);
        int ready[2],finish[2]; assert(!pipe(ready) && !pipe(finish));
        pid_t child=fork(); assert(child>=0);
        if (!child) {
            assert(!prctl(PR_SET_DUMPABLE,0,0,0,0));
            title_snapshot("/proc/self/cmdline",start,size);
            assert(write(ready[1],"!",1)==1);
            char byte; assert(read(finish[0],&byte,1)==1);
            _exit(0);
        }
        char byte; assert(read(ready[0],&byte,1)==1);
        char path[64]; snprintf(path,sizeof(path),"/proc/%d/cmdline",child);
        title_snapshot(path,start,size);
        assert(write(finish[1],"!",1)==1);
        int status; assert(waitpid(child,&status,0)==child && !status);
        close(ready[0]); close(ready[1]); close(finish[0]); close(finish[1]);
    }
    memcpy(start,backup,total); free(backup);
    puts("PASS process title: extended argv/environment, first NUL, page bound and protected foreign views");
}
int main(int argc, char **argv) {
    if (argc==2 && !strcmp(argv[1],"title")) { process_title(argc,argv); return 0; }
    if (argc==2 && (!strcmp(argv[1],"protected") || !strcmp(argv[1],"protected-other-user"))) {
        protected_image(argc,argv,!strcmp(argv[1],"protected-other-user")); return 0;
    }
    image(AT_FDCWD, "/proc/self/cmdline", argc, argv);
    char *original[16]; assert(argc > 0 && argc < 16);
    memcpy(original, argv, (size_t)argc * sizeof(*argv));
    argv[0] = (char *)1;
    image(AT_FDCWD, "/proc/self/cmdline", argc, original);
    argv[0] = original[0];
    char first = argv[0][0]; argv[0][0] = 'X';
    image(AT_FDCWD, "/proc/self/cmdline", argc, original);
    argv[0][0] = first;
    image(AT_FDCWD, "/proc/thread-self/cmdline", argc, argv);
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", getpid());
    image(AT_FDCWD, path, argc, argv);
    int proc = open("/proc/self", O_PATH | O_DIRECTORY); assert(proc >= 0);
    image(proc, "cmdline", argc, argv);
    int fd = openat(proc, "auxv", O_RDONLY); assert(fd >= 0);
    Elf64_auxv_t aux[128];
    ssize_t n = read(fd, aux, sizeof(aux));
    assert(n > 0 && n % sizeof(*aux) == 0);
    int headers = 0, entry = 0;
    for (size_t i = 0; i < (size_t)n / sizeof(*aux); ++i) {
        assert(aux[i].a_un.a_val == getauxval(aux[i].a_type));
        headers |= aux[i].a_type == AT_PHDR; entry |= aux[i].a_type == AT_ENTRY;
    }
    assert(headers && entry); close(fd);
    fd = extended(proc, "cmdline", O_RDONLY, NO_MAGICLINKS | BENEATH);
    assert(fd >= 0); close(fd);
    fd = extended(proc, "cmdline", O_RDONLY, NO_XDEV | NO_SYMLINKS | BENEATH);
    assert(fd >= 0); close(fd); close(proc);
    int root = open("/etc", O_PATH | O_DIRECTORY); assert(root >= 0);
    fd = extended(root, "os-release", O_RDONLY, BENEATH | NO_MAGICLINKS);
    /* Distribution os-release may be an absolute symlink: use passwd instead. */
    if (fd >= 0) close(fd); else assert(errno == EXDEV);
    fd = extended(root, "passwd", O_RDONLY | O_CLOEXEC, BENEATH | NO_XDEV | NO_SYMLINKS);
    assert(fd >= 0 && (fcntl(fd, F_GETFD) & FD_CLOEXEC)); close(fd);
    assert(extended(root, "../bin/sh", O_RDONLY, BENEATH) == -1 && errno == EXDEV);
    assert(extended(root, "/passwd", O_RDONLY, BENEATH) == -1 && errno == EXDEV);
    fd = extended(root, "/passwd", O_RDONLY, IN_ROOT); assert(fd >= 0); close(fd);
    assert(extended(root, "passwd", O_RDONLY, CACHED) == -1 && errno == EAGAIN);
    assert(extended(root, "passwd", O_RDONLY, BENEATH | IN_ROOT) == -1 && errno == EINVAL);
    struct { struct image_open_how how; unsigned char tail[73]; } larger = {{O_RDONLY, 0, BENEATH}, {0}};
    fd = syscall(SYS_openat2, root, "passwd", &larger, sizeof(larger));
    assert(fd >= 0); close(fd);
    larger.tail[72] = 1;
    assert(syscall(SYS_openat2, root, "passwd", &larger, sizeof(larger)) == -1 && errno == E2BIG);
    assert(syscall(SYS_openat2, root, "passwd", &larger, sizeof(larger.how) - 1) == -1 && errno == EINVAL);
    assert(syscall(SYS_openat2, root, "passwd", &larger, getauxval(AT_PAGESZ) + 1) == -1 && errno == E2BIG);
    close(root);
    puts("PASS process image: guest argv/auxv aliases and native seek; openat2 scoped resolution");
    protected_image(argc,argv,0);
    return 0;
}

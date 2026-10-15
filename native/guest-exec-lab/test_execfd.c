#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
static void wait_child(pid_t child, int expected) {
    int status;
    /* EVENT_WAIT: exact child exit; the outer test deadline fails a hung exec. */
    assert(waitpid(child, &status, 0) == child);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != expected)
        fprintf(stderr, "execfd child=%d status=%#x expected=%d\n", child, status, expected);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == expected);
}
static void execute(int fd, const char *path, int flags, int expected) {
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        char invocation[4096];
        if (!*path || (*path != '/' && fd != AT_FDCWD))
            snprintf(invocation, sizeof(invocation), "/dev/fd/%d%s%s", fd, *path ? "/" : "", path);
        else snprintf(invocation, sizeof(invocation), "%s", path);
        char *args[] = {"md-execfd-fixture", "child", invocation, NULL};
        syscall(SYS_execveat, fd, path, args, environ, flags);
        perror("execveat"); _exit(90);
    }
    wait_child(child, expected);
}
static void native_image(int detached) {
    const char *path="/tmp/md-native-exec";
    int source=open("/usr/bin/md-execfd-fixture",O_RDONLY|O_CLOEXEC);
    int output=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0700);
    assert(source>=0 && output>=0);
    char bytes[65536]; ssize_t n;
    while ((n=read(source,bytes,sizeof(bytes)))>0) assert(write(output,bytes,(size_t)n)==n);
    assert(n==0); close(source); close(output);
    int fd=open(path,O_PATH|O_CLOEXEC); assert(fd>=0);
    if (detached) assert(unlink(path)==0);
    int metadata;
    char proc[64]; snprintf(proc,sizeof(proc),"/proc/self/fd/%d",fd);
    metadata=open(proc,O_RDONLY|O_CLOEXEC); assert(metadata>=0);
    assert(fchmod(metadata,0600)==0);
    char *denied[]={"md-execfd-fixture",NULL};
    assert(syscall(SYS_execveat,fd,"",denied,environ,AT_EMPTY_PATH)==-1 && errno==EACCES);
    if (!getuid()) assert(fchown(metadata,42,43)==0);
    assert(fchmod(metadata,0755)==0); close(metadata);
    struct stat st; assert(fstat(fd,&st)==0);
    char device[32],inode[32],links[32];
    snprintf(device,sizeof(device),"%llu",(unsigned long long)st.st_dev);
    snprintf(inode,sizeof(inode),"%llu",(unsigned long long)st.st_ino);
    snprintf(links,sizeof(links),"%llu",(unsigned long long)st.st_nlink);
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        char *args[]={"md-execfd-fixture","native-child",device,inode,links,NULL};
        syscall(SYS_execveat,fd,"",args,environ,AT_EMPTY_PATH);
        perror("native execveat"); _exit(90);
    }
    wait_child(child,41); close(fd);
    if (!detached) assert(unlink(path)==0);
}
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc==5 && (!strcmp(argv[1],"native-child") || !strcmp(argv[1],"native-again"))) {
        assert(syscall(SYS_close_range,3U,~0U,0)==0);
        int fd=open("/proc/self/exe",O_RDONLY|O_CLOEXEC); assert(fd>=0);
        struct stat st; assert(fstat(fd,&st)==0);
        assert(st.st_dev==(dev_t)strtoull(argv[2],NULL,10));
        assert(st.st_ino==(ino_t)strtoull(argv[3],NULL,10));
        assert(st.st_nlink==(nlink_t)strtoull(argv[4],NULL,10));
        assert((st.st_mode&07777)==0755);
        if (!getuid()) assert(st.st_uid==42 && st.st_gid==43);
        char magic[4]; assert(read(fd,magic,4)==4 && !memcmp(magic,"\177ELF",4));
        close(fd);
        assert(stat("/proc/self/exe",&st)==0 && st.st_ino==(ino_t)strtoull(argv[3],NULL,10));
        assert(open("/proc/self/exe",O_WRONLY)<0 && errno==ETXTBSY);
        pid_t observer=fork(); assert(observer>=0);
        if (!observer) {
            char path[64]; snprintf(path,sizeof(path),"/proc/%d/exe",getppid());
            int image=open(path,O_RDONLY|O_CLOEXEC); assert(image>=0);
            assert(fstat(image,&st)==0 && st.st_ino==(ino_t)strtoull(argv[3],NULL,10));
            assert(read(image,magic,4)==4 && !memcmp(magic,"\177ELF",4));
            close(image); _exit(0);
        }
        wait_child(observer,0);
        if (!strcmp(argv[1],"native-child")) {
            argv[1]="native-again";
            execve("/proc/self/exe",argv,environ);
            perror("native proc execve"); return 90;
        }
        return 41;
    }
    for (int i = 1; i + 1 < argc; ++i) if (!strcmp(argv[i], "child")) {
        assert(!strcmp((const char *)getauxval(AT_EXECFN), argv[i + 1]));
        assert(syscall(SYS_close_range, 3U, ~0U, 0) == 0);
        int image = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
        assert(image >= 0);
        unsigned char header[4];
        assert(read(image, header, sizeof(header)) == sizeof(header));
        assert(!memcmp(header, "\177ELF", 4));
        struct stat expected, actual;
        assert(stat("/usr/bin/md-execfd-fixture", &expected) == 0 && fstat(image, &actual) == 0);
        assert(actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino);
        close(image);
        assert(stat("/proc/self/exe", &actual) == 0 && actual.st_ino == expected.st_ino);
        assert(open("/proc/self/exe", O_WRONLY) < 0 && errno == ETXTBSY);
        return 41;
    }
    int fd = open("/usr/bin/md-execfd-fixture", O_PATH | O_CLOEXEC);
    assert(fd >= 0);
    execute(fd, "", AT_EMPTY_PATH, 41);
    close(fd);
    int dir = open("/usr/bin", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(dir >= 0);
    execute(dir, "md-execfd-fixture", 0, 41);
    close(dir);
    execute(-1, "/usr/bin/md-execfd-fixture", AT_SYMLINK_NOFOLLOW, 41);
    assert(chdir("/usr/bin") == 0);
    execute(AT_FDCWD, "./md-execfd-fixture", 0, 41);
    assert(chdir("/") == 0);
    puts("PASS descriptor ELF exec: O_PATH, CLOEXEC, relative dirfd, absolute path");

    assert(link("/usr/bin/md-execfd-fixture", "/tmp/md-unlinked-exec") == 0);
    fd = open("/tmp/md-unlinked-exec", O_RDONLY | O_CLOEXEC); assert(fd >= 0);
    assert(unlink("/tmp/md-unlinked-exec") == 0);
    execute(fd, "", AT_EMPTY_PATH, 41);
    close(fd);
    puts("PASS open-unlinked ELF and /proc/self/exe survive exec and close_range");

    native_image(0); native_image(1);
    puts("PASS copied and open-unlinked native ELF retain proc identity across close_range and re-exec");

    assert(link("/usr/bin/md-execfd-fixture", "/tmp/md-replaced-exec") == 0);
    fd = open("/tmp/md-replaced-exec", O_PATH | O_CLOEXEC); assert(fd >= 0);
    assert(unlink("/tmp/md-replaced-exec") == 0);
    int replacement = open("/tmp/md-replaced-exec", O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(replacement >= 0 && write(replacement, "not the executable", 18) == 18);
    close(replacement);
    execute(fd, "", AT_EMPTY_PATH, 41);
    close(fd); assert(unlink("/tmp/md-replaced-exec") == 0);
    puts("PASS descriptor exec and proc image retain their inode after name reuse");

    fd = open("/tmp/md-exec-script", O_WRONLY | O_CREAT | O_EXCL, 0700); assert(fd >= 0);
    const char script[] = "#!/bin/sh\nexit 42\n";
    assert(write(fd, script, sizeof(script) - 1) == sizeof(script) - 1);
    close(fd);
    fd = open("/tmp/md-exec-script", O_PATH); assert(fd >= 0);
    execute(fd, "", AT_EMPTY_PATH, 42);
    assert(fcntl(fd, F_SETFD, FD_CLOEXEC) == 0);
    char *args[] = {"script", NULL};
    assert(syscall(SYS_execveat, fd, "", args, environ, AT_EMPTY_PATH) == -1 && errno == ENOENT);
    close(fd);
    assert(unlink("/tmp/md-exec-script") == 0);
    fd = open("/tmp/md-exec-script", O_WRONLY | O_CREAT | O_EXCL, 0700); assert(fd >= 0);
    const char interpreter[] = "#!/usr/bin/md-execfd-fixture\n";
    assert(write(fd, interpreter, sizeof(interpreter) - 1) == sizeof(interpreter) - 1);
    close(fd);
    execute(AT_FDCWD, "/tmp/./md-exec-script", 0, 41);
    assert(unlink("/tmp/md-exec-script") == 0);
    assert(symlink("/usr/bin/md-execfd-fixture", "/tmp/md-exec-link") == 0);
    assert(syscall(SYS_execveat, AT_FDCWD, "/tmp/md-exec-link", args, environ, AT_SYMLINK_NOFOLLOW) == -1 && errno == ELOOP);
    assert(syscall(SYS_execveat, -1, "", args, environ, AT_EMPTY_PATH) == -1 && errno == EBADF);
    assert(syscall(SYS_execveat, -1, "", args, environ, 0) == -1 && errno == ENOENT);
    assert(syscall(SYS_execveat, fd, "", args, environ, 1) == -1 && errno == EINVAL);
    assert(unlink("/tmp/md-exec-link") == 0);
    assert(symlink("/missing-executable", "/tmp/md-exec-link") == 0);
    assert(syscall(SYS_execveat, AT_FDCWD, "/tmp/md-exec-link", args, environ, AT_SYMLINK_NOFOLLOW) == -1 && errno == ELOOP);
    assert(unlink("/tmp/md-exec-link") == 0);
    puts("PASS descriptor scripts, CLOEXEC failure, nofollow, invalid arguments and original AT_EXECFN");
    const char *headers[] = {
        "#!/usr/bin/md-execfd-fixture",
        "#!usr/bin/md-execfd-fixture\n",
        "#! \t/usr/bin/md-execfd-fixture  one option with spaces \t\n",
    };
    for (unsigned i = 0; i < sizeof(headers) / sizeof(*headers); ++i) {
        fd = open("/tmp/md-exec-script", O_WRONLY | O_CREAT | O_EXCL, 0700); assert(fd >= 0);
        size_t size = strlen(headers[i]);
        assert(write(fd, headers[i], size) == (ssize_t)size); close(fd);
        execute(AT_FDCWD, "/tmp/md-exec-script", 0, 41);
        assert(unlink("/tmp/md-exec-script") == 0);
    }
    char truncated[257]; memset(truncated, 'x', sizeof(truncated));
    truncated[0] = '#'; truncated[1] = '!'; truncated[256] = '\n';
    fd = open("/tmp/md-exec-script", O_WRONLY | O_CREAT | O_EXCL, 0700); assert(fd >= 0);
    assert(write(fd, truncated, sizeof(truncated)) == sizeof(truncated)); close(fd);
    assert(syscall(SYS_execveat, AT_FDCWD, "/tmp/md-exec-script", args, environ, 0) == -1 && errno == ENOEXEC);
    assert(unlink("/tmp/md-exec-script") == 0);
    puts("PASS bounded shebang parsing: no newline, relative interpreter, whitespace and truncation");
    return 0;
}

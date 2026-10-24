#define _GNU_SOURCE
#include "inode_internal.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Component workload, not guest interception: independent store per run,
 * ordinary root/user leaves, unchanged publication barriers and live IO. */
static unsigned long gets,syncs;
ssize_t __real_fgetxattr(int,const char *,void *,size_t);
ssize_t __wrap_fgetxattr(int fd,const char *name,void *value,size_t size) {
    ++gets; return __real_fgetxattr(fd,name,value,size);
}
ssize_t __real_getxattr(const char *,const char *,void *,size_t);
ssize_t __wrap_getxattr(const char *path,const char *name,void *value,size_t size) {
    ++gets; return __real_getxattr(path,name,value,size);
}
int __real_fsync(int);
int __wrap_fsync(int fd) { ++syncs; return __real_fsync(fd); }
static double now(clockid_t clock) {
    struct timespec time; assert(!clock_gettime(clock,&time));
    return time.tv_sec+time.tv_nsec/1e9;
}
struct frequency { int cpu; unsigned khz; };
static struct frequency frequency(void) {
    struct frequency sample={.cpu=sched_getcpu()};
    char path[128];
    snprintf(path,sizeof(path),"/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq",sample.cpu);
    FILE *file=fopen(path,"r");
    if (file) { if (fscanf(file,"%u",&sample.khz)!=1) sample.khz=0; fclose(file); }
    return sample;
}
int main(int argc,char **argv) {
    assert(argc==4 || argc==5);
    unsigned count=(unsigned)strtoul(argv[3],NULL,10);
    assert(count && count<=8192);
    int native=!strcmp(argv[2],"native");
    assert(native || !strcmp(argv[2],"root") || !strcmp(argv[2],"user"));
    int measured=argc==5 && !strcmp(argv[4],"--statistics");
    assert(argc==4 || measured);
    assert(!mkdir(argv[1],0700));
    int directory=open(argv[1],O_RDONLY|O_DIRECTORY|O_CLOEXEC); assert(directory>=0);
    struct md_inode_store *store=NULL;
    struct md_identity identity=md_identity_new(!strcmp(argv[2],"user") ? 1000 : 0,
        !strcmp(argv[2],"user") ? 1000 : 0);
    if (!native) {
        char path[4096]; assert(snprintf(path,sizeof(path),"%s/store",argv[1])<(int)sizeof(path));
        assert(!md_inode_store_open(path,1,&store));
        int root=md_inode_open(store,-1,"/",O_RDONLY|O_DIRECTORY,0); assert(root>=0);
        assert(!md_inode_import_metadata(store,root,identity.uid.fs,identity.gid.fs,0700)); close(root);
        store->identity=&identity;
    }
    const char *dirs[]={"home","home/user","home/user/library","home/user/library/staging","home/user/library/installed"};
    for (unsigned i=0;i<sizeof(dirs)/sizeof(*dirs);++i)
        assert(!(native ? mkdirat(directory,dirs[i],0700) : md_inode_mkdir(store,-1,dirs[i],0700)));
    const char *phases[]={"create","open-stat-close","rename","unlink"};
    for (unsigned phase=0;phase<4;++phase) {
        struct md_inode_statistics statistics={0};
        if (store && measured) md_inode_measure(store,&statistics);
        gets=syncs=0;
        struct frequency first=frequency();
        double wall=now(CLOCK_MONOTONIC),cpu=now(CLOCK_PROCESS_CPUTIME_ID);
        for (unsigned i=0;i<count;++i) {
            char source[128],target[128];
            snprintf(source,sizeof(source),"home/user/library/staging/file-%u",i);
            snprintf(target,sizeof(target),"home/user/library/installed/file-%u",i);
            if (phase<2) {
                int flags=phase ? O_RDONLY : O_CREAT|O_EXCL|O_RDWR;
                int fd=native ? openat(directory,source,flags|O_CLOEXEC,0644)
                    : md_inode_open(store,-1,source,flags,0644);
                assert(fd>=0);
                if (!phase) assert(write(fd,"data",4)==4);
                else {
                    char bytes[4]; struct stat st;
                    assert(!(native ? fstat(fd,&st) : md_inode_fstat(store,fd,&st)));
                    assert(st.st_size==4 && st.st_uid==(native ? getuid() : identity.uid.fs));
                    assert(read(fd,bytes,sizeof(bytes))==4 && !memcmp(bytes,"data",4));
                }
                assert(!close(fd));
            } else if (phase==2) assert(!(native ? renameat(directory,source,directory,target)
                : md_inode_rename(store,-1,source,-1,target,0)));
            else assert(!(native ? unlinkat(directory,target,0) : md_inode_unlink(store,-1,target,0)));
        }
        cpu=now(CLOCK_PROCESS_CPUTIME_ID)-cpu; wall=now(CLOCK_MONOTONIC)-wall;
        struct frequency last=frequency();
        printf("FILE_BATCH mode=%s phase=%s count=%u wall_ms=%.3f cpu_ms=%.3f xattr_calls=%lu fsync_calls=%lu prefix_hits=%llu sql_steps=%llu cpu_start=%d khz_start=%u cpu_end=%d khz_end=%u\n",
            argv[2],phases[phase],count,wall*1000,cpu*1000,gets,syncs,
            (unsigned long long)statistics.path_prefix_hits,(unsigned long long)statistics.step.calls,
            first.cpu,first.khz,last.cpu,last.khz);
        if (store) md_inode_measure(store,NULL);
    }
    if (store) { store->identity=NULL; md_inode_store_close(store); }
    md_identity_release(&identity); close(directory);
}

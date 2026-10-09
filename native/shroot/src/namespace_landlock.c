#include "namespace_internal.h"
#include "landlock_policy.h"
#include "raw.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>

long md_namespace_landlock(const struct md_fs *fs,long nr,const unsigned long *a) {
    uint64_t access=0;
    struct md_fs_request q={.operation=MD_FS_LANDLOCK,.directory={-1,-1},
        .value=&access,.value_size=sizeof(access)};
    if (nr==SYS_landlock_create_ruleset) {
        if (a[2]) return a[2]==1 && !a[0] && !a[1] ? MD_LANDLOCK_ABI : -EINVAL;
        if (!a[0]) return -EFAULT;
        if (a[1]<sizeof(access)) return -EINVAL;
        long r=md_read_struct(&access,sizeof(access),(const void *)a[0],a[1]);
        if (r<0) return r;
        q.mode=MD_LL_CREATE; q.flags=O_RDWR|O_CLOEXEC;
    } else if (nr==SYS_landlock_add_rule) {
        if (a[3] || a[1]!=1) return -EINVAL;
        struct __attribute__((packed)) { uint64_t allowed; int32_t parent; } rule;
        long r=md_read_memory(&rule,(const void *)a[2],sizeof(rule));
        if (r<0) return r;
        if ((int)a[0]<0 || rule.parent<0) return -EBADF;
        q.mode=MD_LL_ADD; q.directory[0]=(int)a[0]; q.directory[1]=rule.parent;
        access=rule.allowed;
    } else {
        if (a[1]) return -EINVAL;
        if ((int)a[0]<0) return -EBADF;
        q.mode=MD_LL_RESTRICT; q.directory[0]=(int)a[0];
    }
    struct md_fs_response out;
    long r=md_fs_call_deliver(fs->endpoint,5000,&q,&out,NULL,NULL);
    if (r>=0) r=out.result.error;
    if (r<0) return r;
    return q.mode==MD_LL_CREATE ? md_namespace_open_result(&out.result,q.flags) : 0;
}

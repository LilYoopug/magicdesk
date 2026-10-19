#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <sys/auxv.h>
#include <sys/fsuid.h>
#include <unistd.h>

int setid_library_value(void);
int main(void) {
    uid_t r, e, s;
    gid_t gr, ge, gs;
    if (getresuid(&r,&e,&s) || getresgid(&gr,&ge,&gs)) return 1;
    struct __user_cap_header_struct header={.version=_LINUX_CAPABILITY_VERSION_3};
    struct __user_cap_data_struct caps[2];
    if (syscall(SYS_capget,&header,caps)) return 2;
    printf("{\"uid\":[%u,%u,%u,%u],\"gid\":[%u,%u,%u,%u],"
        "\"aux\":[%lu,%lu,%lu,%lu],\"secure\":%lu,\"env\":%d,\"library\":%d,"
        "\"caps\":[%llu,%llu]}\n",
        r,e,s,setfsuid((uid_t)-1),gr,ge,gs,setfsgid((gid_t)-1),
        getauxval(AT_UID),getauxval(AT_EUID),getauxval(AT_GID),getauxval(AT_EGID),
        getauxval(AT_SECURE),secure_getenv("LD_LIBRARY_PATH")!=NULL,setid_library_value(),
        (unsigned long long)caps[0].permitted|((unsigned long long)caps[1].permitted<<32),
        (unsigned long long)caps[0].effective|((unsigned long long)caps[1].effective<<32));
    return 0;
}

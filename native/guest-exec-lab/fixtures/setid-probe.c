#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <sys/fsuid.h>
#include <unistd.h>

int setid_library_value(void);
int main(void) {
    uid_t r, e, s;
    gid_t gr, ge, gs;
    if (getresuid(&r,&e,&s) || getresgid(&gr,&ge,&gs)) return 1;
    printf("{\"uid\":[%u,%u,%u,%u],\"gid\":[%u,%u,%u,%u],"
        "\"aux\":[%lu,%lu,%lu,%lu],\"secure\":%lu,\"env\":%d,\"library\":%d}\n",
        r,e,s,setfsuid((uid_t)-1),gr,ge,gs,setfsgid((gid_t)-1),
        getauxval(AT_UID),getauxval(AT_EUID),getauxval(AT_GID),getauxval(AT_EGID),
        getauxval(AT_SECURE),secure_getenv("LD_LIBRARY_PATH")!=NULL,setid_library_value());
    return 0;
}

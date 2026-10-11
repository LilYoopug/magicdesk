#include "pid_namespace.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>

int main(void) {
    struct md_pid_identity *a=NULL,*b=NULL,*c=NULL;
    assert(!md_pid_identity_prepare(NULL,&a) && !a);
    struct md_pid_namespace *outer=md_pid_namespace_new(NULL,NULL); assert(outer);
    assert(md_pid_namespace_depth(outer)==1 && md_pid_namespace_contains(NULL,outer));
    assert(!md_pid_identity_prepare(outer,&a) && md_pid_identity_number(a,outer)==1);
    assert(!md_pid_namespace_lookup(outer,1));
    md_pid_identity_release(a);
    assert(!md_pid_identity_prepare(outer,&a) && md_pid_identity_number(a,outer)==1);
    assert(!md_pid_identity_publish(a,20001,20001) && md_pid_identity_publish(a,20002,20002)==-EINVAL);
    assert(md_pid_identity_number(a,NULL)==20001 && md_pid_identity_live(a));
    struct md_pid_namespace *inner=md_pid_namespace_new(outer,NULL); assert(inner);
    assert(!md_pid_identity_prepare(inner,&b) && !md_pid_identity_publish(b,20002,20002));
    assert(md_pid_identity_number(b,inner)==1 && md_pid_identity_number(b,outer)==2);
    assert(!md_pid_identity_number(a,inner) && md_pid_namespace_contains(outer,inner));
    assert(!md_pid_namespace_contains(inner,outer));
    assert(!md_pid_identity_prepare(inner,&c) && !md_pid_identity_publish(c,20003,20003));
    assert(md_pid_identity_number(c,inner)==2 && md_pid_identity_number(c,outer)==3);
    struct md_pid_identity *found=md_pid_namespace_lookup(outer,3); assert(found==c); md_pid_identity_release(found);
    found=md_pid_namespace_find(inner,20003); assert(found==c); md_pid_identity_release(found);
    assert(!md_pid_namespace_find(inner,20001));
    assert(md_pid_identity_exit(b)==1 && md_pid_namespace_dead(inner));
    assert(!md_pid_identity_exit(b) && !md_pid_identity_live(b));
    struct md_pid_identity *rejected=NULL;
    assert(md_pid_identity_prepare(inner,&rejected)==-ENOMEM && !rejected);
    assert(!md_pid_namespace_dead(outer));
    found=md_pid_namespace_lookup(inner,1); assert(found==b && !md_pid_identity_live(found));
    md_pid_identity_release(found);
    assert(!md_pid_identity_exit(c));
    md_pid_identity_reap(c);
    assert(!md_pid_namespace_lookup(outer,3) && !md_pid_namespace_find(outer,20003));
    assert(md_pid_identity_number(c,outer)==3);
    md_pid_identity_release(c);
    md_pid_identity_release(b); md_pid_namespace_release(inner);
    assert(!md_pid_namespace_lookup(outer,2));
    assert(md_pid_identity_exit(a)); md_pid_identity_release(a); md_pid_namespace_release(outer);
    outer=md_pid_namespace_new(NULL,NULL); assert(outer);
    assert(!md_pid_identity_prepare(outer,&a) && !md_pid_identity_publish(a,20001,20001));
    assert(!md_pid_identity_prepare(outer,&b) && !md_pid_identity_publish(b,20002,20001));
    assert(!md_pid_identity_exit(a) && !md_pid_namespace_dead(outer));
    md_pid_identity_exec(b,a);
    assert(md_pid_identity_live(a) && !md_pid_identity_live(b) && !md_pid_namespace_dead(outer));
    md_pid_identity_release(b);
    assert(!md_pid_identity_prepare(outer,&c) && !md_pid_identity_publish(c,20003,20001));
    assert(!md_pid_identity_exit(a) && !md_pid_namespace_dead(outer));
    assert(md_pid_identity_exit(c) && md_pid_namespace_dead(outer));
    md_pid_identity_release(a); md_pid_identity_release(c); md_pid_namespace_release(outer);
    outer=md_pid_namespace_new(NULL,NULL); assert(outer);
    for (unsigned i=1;i<32;++i) {
        inner=md_pid_namespace_new(outer,NULL); assert(inner);
        md_pid_namespace_release(outer); outer=inner;
    }
    assert(!md_pid_namespace_new(outer,NULL) && errno==ENOSPC);
    md_pid_namespace_release(outer);
    puts("PASS PID namespace model: nested identities, unpublished rollback, ancestor visibility, retained exit and closed init");
    return 0;
}

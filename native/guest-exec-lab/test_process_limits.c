#define _GNU_SOURCE
#include "process_limits.h"
#include <assert.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>

int main(void) {
    struct md_identity root=md_identity_new(0,0), user=md_identity_new(1000,1000), other=md_identity_new(1001,1001);
    struct rlimit limit={3,3}, old;
    struct md_process_member *p=md_process_member_new(&user,&limit), *a=NULL,*b=NULL,*c=NULL;
    assert(p);
    assert(!md_process_member_fork(p,&user,CLONE_THREAD,&a));
    assert(!md_process_member_fork(p,&user,0,&b));
    assert(md_process_member_fork(p,&user,0,&c)==-EAGAIN && !c);
    /* Registry custody, not live-thread custody, bounds a zombie's charge. */
    md_process_member_retain(b); md_process_member_release(b);
    assert(md_process_member_fork(p,&user,0,&c)==-EAGAIN);
    md_process_member_release(b);
    assert(!md_process_member_fork(p,&user,0,&b));
    md_process_member_release(b);
    limit=(struct rlimit){2,3};
    assert(!md_process_nproc(a,&user,&user,1,&limit,&old) && old.rlim_cur==3);
    assert(md_process_nproc_value(p).rlim_cur==2);
    assert(md_process_member_fork(p,&user,0,&c)==-EAGAIN);
    assert(!md_process_member_identity(a,&other));
    assert(!md_process_member_fork(p,&user,0,&c));
    limit=(struct rlimit){1,3};
    assert(!md_process_nproc(c,&user,&user,1,&limit,NULL));
    assert(md_process_nproc_value(p).rlim_cur==2);
    limit=(struct rlimit){4,3};
    assert(md_process_nproc(p,&root,&user,0,&limit,NULL)==-EINVAL);
    limit=(struct rlimit){4,4};
    assert(md_process_nproc(p,&user,&user,1,&limit,NULL)==-EPERM);
    assert(md_process_nproc(p,&other,&user,0,NULL,NULL)==-EPERM);
    assert(!md_process_nproc(p,&root,&user,0,&limit,NULL));
    /* A UID change may exceed the destination quota; the next exec refuses. */
    assert(!md_process_member_identity(c,&other));
    assert(md_process_member_exec(c)==-EAGAIN);
    md_process_member_release(a);
    assert(!md_process_member_exec(c));
    md_process_member_release(c);
    md_process_member_release(p);
    p=md_process_member_new(&root,&(struct rlimit){0,0}); assert(p);
    assert(!md_process_member_fork(p,&root,0,&a));
    md_process_member_release(a); md_process_member_release(p);
    /* A child namespace's creation ceiling bounds its creator's aggregate,
     * including tasks outside that child. Child capabilities cannot bypass it. */
    limit=(struct rlimit){3,10};
    p=md_process_member_new(&user,&limit); assert(p);
    assert(!md_process_member_fork(p,&user,0,&a));
    struct md_identity nested=md_identity_copy(&user);
    nested.user_namespace=md_user_namespace_new(NULL,1000,1000,0); assert(nested.user_namespace);
    nested.caps.effective=MD_CAP_VALID;
    assert(!md_process_member_identity(a,&nested));
    limit=(struct rlimit){10,10};
    assert(!md_process_nproc(a,&nested,&nested,1,&limit,NULL));
    assert(!md_process_member_fork(a,&nested,0,&b));
    assert(md_process_member_fork(a,&nested,0,&c)==-EAGAIN);
    md_process_member_release(p);
    assert(!md_process_member_fork(a,&nested,0,&c));
    md_process_member_release(a); md_process_member_release(b); md_process_member_release(c);
    md_identity_release(&nested);
    md_identity_release(&root); md_identity_release(&user); md_identity_release(&other);
    puts("PASS process limits: reservation, zombie custody, thread sharing, fork copy, credentials and exec");
}

#define _GNU_SOURCE
#include "svc_patch.h"
#include "svc_registry.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <unistd.h>

static struct md_svc_payload_state payload;
static int reads,writes,fail_write=-1,fail_read;
ssize_t __wrap_process_vm_readv(pid_t pid,const struct iovec *local,unsigned long ln,
        const struct iovec *remote,unsigned long rn,unsigned long flags) {
    assert((pid==111 || pid==222) && ln==1 && rn==1 && !flags);
    ++reads;
    if (fail_read) { errno=ESRCH; return -1; }
    assert(remote->iov_base==&payload && remote->iov_len==sizeof(payload));
    memcpy(local->iov_base,&payload,sizeof(payload)); return sizeof(payload);
}
long __wrap_ptrace(int request,pid_t pid,void *address,void *value) {
    assert(pid==111 || pid==222);
    if (request==PTRACE_PEEKTEXT) { assert(fail_read); errno=ESRCH; return -1; }
    assert(request==PTRACE_POKETEXT);
    if (writes++==fail_write) { errno=ESRCH; return -1; }
    assert((char *)address>=(char *)&payload && (char *)address+8<=(char *)(&payload+1));
    if (address==&payload.clients[0].tid) {
        struct md_entry_client zero={0};
        assert(!memcmp(&payload.clients[0].client,&zero,sizeof(zero)));
    }
    uint64_t word=(uintptr_t)value; memcpy(address,&word,8); return 0;
}
static int alive(pid_t pid,void *context) {
    assert(context==&payload); return pid==222;
}
static void client_retirement(void) {
    struct md_svc_registry r={.frames=(uintptr_t)&payload-MD_SVC_POOL_SIZE};
    assert(!md_svc_registry_collect_clients(&r,111,-1,alive,&payload) && !reads && !writes);
    /* Lose the stop before each opaque word, the final owner, and statistics. */
    for (int failure=0;failure<5;++failure) {
        payload=(struct md_svc_payload_state){.clients={
            {.tid=111,.client.opaque={11,12,13}}, {.tid=222,.client.opaque={21,22,23}}}};
        r.clients_dirty=1; writes=0; fail_write=failure;
        assert(md_svc_registry_collect_clients(&r,111,-1,alive,&payload)==-ESRCH && r.clients_dirty);
        fail_write=-1;
        assert(!md_svc_registry_collect_clients(&r,222,-1,alive,&payload) && !r.clients_dirty);
        assert(!payload.clients[0].tid && payload.clients[1].tid==222);
        assert(payload.clients[1].client.opaque[0]==21 && payload.clients[1].client.opaque[2]==23);
        int previous=reads+writes;
        assert(!md_svc_registry_collect_clients(&r,222,-1,alive,&payload) && previous==reads+writes);
    }
    r.clients_dirty=1; fail_read=1;
    assert(md_svc_registry_collect_clients(&r,111,-1,alive,&payload)==-ESRCH && r.clients_dirty);
    fail_read=0;
    assert(!md_svc_registry_collect_clients(&r,222,-1,alive,&payload));
    int fd=open("/proc/self/mem",O_RDWR|O_CLOEXEC); assert(fd>=0);
    payload.clients[0].tid=111; payload.clients[0].client.opaque[0]=123;
    r.clients_dirty=1; fail_read=1; fail_write=writes;
    assert(!md_svc_registry_collect_clients(&r,111,fd,alive,&payload) && !r.clients_dirty);
    assert(!payload.clients[0].tid && !payload.clients[0].client.opaque[0]);
    assert(payload.clients[1].tid==222 && payload.clients[1].client.opaque[0]==21);
    close(fd); fail_read=0; fail_write=-1;
    struct md_svc_registry *copy=md_svc_registry_copy(&r);
    assert(copy && copy->clients_dirty && !r.clients_dirty); free(copy);
    r.disabled=1; r.clients_dirty=1; fail_read=1; fail_write=writes;
    int previous=reads+writes;
    assert(!md_svc_registry_collect_clients(&r,111,-1,alive,&payload));
    assert(previous==reads+writes && r.clients_dirty);
    fail_read=0; fail_write=-1;
    puts("PASS SVC client retirement: lost stop, live peer, owner-last publication and idle fast path");
}

int main(void) {
    client_retirement();
    struct md_svc_registry empty={.count=2,.disabled=1};
    assert(!md_svc_registry_resident(NULL) && !md_svc_registry_resident(&empty));
    struct md_svc_registry registry={.pool_count=1,.count=2,
        .pools={{.address=0x40000,.used=0x1000}},
        .sites={{.direct={.svc=0x10000,.gate=0x40000},.kernel_alias=0x40100},
                {.state=MD_SVC_RETIRED,.direct={.svc=0x20000,.gate=0x40200},
                 .kernel_alias=0x40300}}};
    assert(md_svc_registry_resident(&registry));
    empty.sites[1].direct.gate=0x40000;
    empty.sites[1].state=MD_SVC_RETIRED;
    assert(md_svc_registry_resident(&empty));
    assert(md_svc_registry_call_origin(NULL,0x40104)==0x40104);
    assert(md_svc_registry_call_origin(&registry,0x10004)==0x10004);
    assert(md_svc_registry_call_origin(&registry,0x40100)==0x40100);
    assert(md_svc_registry_call_origin(&registry,0x40104)==0x10004);
    assert(md_svc_registry_call_origin(&registry,0x40108)==0x40108);
    assert(md_svc_registry_call_origin(&registry,0x40304)==0x20004);
    assert(md_svc_registry_call_origin(&registry,0x50004)==0x50004);
    registry.sites[0].original=0xd4000001;
    registry.sites[0].replacement=0x1400c000;
    assert(md_svc_registry_instruction(NULL,0x10000,0x1400c000)==0x1400c000);
    assert(md_svc_registry_instruction(&registry,0x10000,0x1400c000)==0xd4000001);
    assert(md_svc_registry_instruction(&registry,0x10004,0x1400c000)==0x1400c000);
    assert(md_svc_registry_instruction(&registry,0x10000,0xd503201f)==0xd503201f);
    registry.sites[0].state=MD_SVC_RETIRED;
    assert(md_svc_registry_instruction(&registry,0x10000,0x1400c000)==0x1400c000);
    registry.sites[0].state=MD_SVC_PUBLISHED;
    registry.disabled=1;
    assert(md_svc_registry_call_origin(&registry,0x40304)==0x20004);
    uint32_t word=0;
    assert(!md_svc_branch(0x10000000,0x17fffffc,&word) && word==0x15ffffff);
    assert(!md_svc_branch(0x10000000,0x08000000,&word) && word==0x16000000);
    assert(md_svc_branch(0x10000000,0x18000000,&word)==-ERANGE);
    assert(md_svc_branch(0x10000000,0x07fffffc,&word)==-ERANGE);
    assert(md_svc_branch(0x10000001,0x10000000,&word)==-EINVAL);
    assert(md_svc_branch(0x10000000,0x10000002,&word)==-EINVAL);
    assert(md_svc_branch(0,0,NULL)==-EINVAL);
    puts("PASS SVC planner: branch limits, explicit rejection and syscall origin");
}

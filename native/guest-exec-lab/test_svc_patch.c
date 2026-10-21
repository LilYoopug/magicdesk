#include "svc_patch.h"
#include "svc_registry.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>

int main(void) {
    struct md_svc_registry registry={.pool_count=1,.count=2,
        .pools={{.address=0x40000,.used=0x1000}},
        .sites={{.direct={.svc=0x10000,.gate=0x40000},.kernel_alias=0x40100},
                {.state=MD_SVC_RETIRED,.direct={.svc=0x20000,.gate=0x40200},
                 .kernel_alias=0x40300}}};
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

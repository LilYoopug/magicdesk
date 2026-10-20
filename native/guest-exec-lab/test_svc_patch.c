#include "svc_patch.h"
#include "svc_edge.h"
#include "svc_borrowed.h"
#include "svc_registry.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>

int main(void) {
    struct md_svc_registry registry={.pool_count=1,.count=2,
        .pools={{.address=0x40000,.used=0x1000}},
        .sites={{.direct={.svc=0x10000,.gate=0x40000},.window={.kernel_alias=0x40100}},
                {.state=MD_SVC_RETIRED,.direct={.svc=0x20000,.gate=0x40200},
                 .window={.kernel_alias=0x40300}}}};
    assert(md_svc_registry_call_origin(NULL,0x40104)==0x40104);
    assert(md_svc_registry_call_origin(&registry,0x10004)==0x10004);
    assert(md_svc_registry_call_origin(&registry,0x40100)==0x40100);
    assert(md_svc_registry_call_origin(&registry,0x40104)==0x10004);
    assert(md_svc_registry_call_origin(&registry,0x40108)==0x40108);
    assert(md_svc_registry_call_origin(&registry,0x40304)==0x20004);
    assert(md_svc_registry_call_origin(&registry,0x50004)==0x50004);
    registry.disabled=1;
    assert(md_svc_registry_call_origin(&registry,0x40304)==0x20004);
    uint32_t word=0;
    assert(!md_svc_branch(0x10000000,0x17fffffc,&word) && word==0x15ffffff);
    assert(!md_svc_branch(0x10000000,0x08000000,&word) && word==0x16000000);
    assert(md_svc_branch(0x10000000,0x18000000,&word)==-ERANGE);
    assert(md_svc_branch(0x10000000,0x07fffffc,&word)==-ERANGE);
    assert(md_svc_branch(0x10000001,0x10000000,&word)==-EINVAL);
    assert(md_svc_branch(0x10000000,0x10000002,&word)==-EINVAL);
    for (unsigned nr=0;nr<65536;++nr) {
        assert(md_svc_prefix(0xd2800008|(nr<<5))==MD_SVC_MOV_IMMEDIATE);
        assert(md_svc_prefix(0x52800008|(nr<<5))==MD_SVC_MOV_IMMEDIATE);
    }
    for (unsigned reg=0;reg<32;++reg) for (unsigned dest=0;dest<32;++dest) {
        assert(md_svc_prefix(0xaa0003e0|(reg<<16)|dest)==MD_SVC_MOV_REGISTER);
        assert(md_svc_prefix(0x2a0003e0|(reg<<16)|dest)==MD_SVC_MOV_REGISTER);
        assert(md_svc_prefix(0xd28009e0|dest)==MD_SVC_MOV_IMMEDIATE);
    }
    for (unsigned shift=0;shift<4;++shift) {
        assert(md_svc_prefix(0xd2800008|(shift<<21))==MD_SVC_MOV_IMMEDIATE);
        assert(md_svc_prefix(0x92800008|(shift<<21))==MD_SVC_MOV_IMMEDIATE);
        assert(md_svc_decode(0xf2800008|(shift<<21)).reads==(1u<<8));
        assert(md_svc_prefix(0x52800008|(shift<<21))==(shift<2 ? MD_SVC_MOV_IMMEDIATE : MD_SVC_UNSUPPORTED));
    }
    const uint32_t window[]={0xd28009e8,0xaa0103e0,0xaa0303e2,0xd4000001};
    struct md_svc_window w=md_svc_window(window,4);
    assert(w.understood==3 && w.number_distance==3);
    assert(!md_svc_window(window,3).understood);
    assert(md_svc_decode(0xaa0003e5).reads==1 && md_svc_decode(0xaa0003e5).writes==(1u<<5));
    assert(md_svc_prefix(0xb27d0be8)==MD_SVC_MOV_IMMEDIATE);
    assert(md_svc_prefix(0xb24017e8)==MD_SVC_MOV_IMMEDIATE);
    assert(md_svc_decode(0xf9401fe5).kind==MD_SVC_LOAD && md_svc_decode(0xf9401fe5).reads==(1u<<31));
    assert(md_svc_decode(0xb9400008).kind==MD_SVC_LOAD);
    const uint32_t unsafe[]={0x72c00008,0xb2800008,0xaa0007e8,0xb240ffe8,
        0xf9400008^0x00400000,0x10000008,0x58000008,0xd503245f,0xd503233f,0x14000000,0xd4000001};
    for (unsigned i=0;i<sizeof(unsafe)/sizeof(*unsafe);++i) assert(!md_svc_prefix(unsafe[i]));
    uint32_t pair[]={0xd28009e8,0xd4000001},stub[2];
    assert(!md_svc_forward(0x1004,0x2000,pair,&word,stub));
    assert(word==0x14000400 && stub[0]==pair[0] && stub[1]==0x17fffc00);
    pair[1]=0xd4000021;
    assert(md_svc_forward(0x1004,0x2000,pair,&word,stub)==-EINVAL);
    assert(md_svc_original_pc(0x1004,0x2000,0x2000,0)==0x1000);
    assert(md_svc_original_pc(0x1004,0x2000,0x2004,0)==0x1004);
    assert(md_svc_original_pc(0x1004,0x2000,0x2008,0)==0x2008);
    assert(md_svc_original_pc(0x1004,0x2000,0x2008,1)==0x1004);
    unsigned char edge_code[2048];
    struct md_svc_edge edge;
    /* A load-only wrapper needs no dead destination: BL already defines LR.
     * The recognizer is independent of ABI/symbol names and rejects branches,
     * PC-relative accesses, LR writes and false call targets. */
    const uint32_t loads[]={0xf94007e8,0xf9400be0,0xf9400fe1,0xf94013e2,
        0xf94017e3,0xf9401be4,0xf9401fe5,0xd4000001};
    uint32_t call;
    assert(!md_svc_branch(0x1000,0x2000,&call)); call|=0x80000000;
    assert(!md_svc_edge_plan(0x1000,call,0x2000,loads,8,0x3000,0x4000,MD_SVC_POOL_BASE,
        edge_code,sizeof(edge_code),&word,&edge));
    assert(edge.call==0x1000 && edge.svc==0x201c && edge.prefix_count==7);
    assert(edge.size==md_svc_edge_size() && word==0x14000800);
    assert(md_svc_edge_plan(0x1000,call^0x80000000,0x2000,loads,8,0x3000,0x4000,MD_SVC_POOL_BASE,
        edge_code,sizeof(edge_code),&word,&edge)==-EINVAL);
    assert(md_svc_edge_plan(0x1000,call,0x2004,loads,8,0x3000,0x4000,MD_SVC_POOL_BASE,
        edge_code,sizeof(edge_code),&word,&edge)==-EINVAL);
    assert(md_svc_edge_plan(0x1000,call,0x2000,loads,8,0x3000,0x4000,MD_SVC_POOL_BASE,
        edge_code,1,&word,&edge)==-ENOSPC);
    const uint32_t lr_write[]={0xf94007fe,0xd4000001};
    assert(md_svc_edge_plan(0x1000,call,0x2000,lr_write,2,0x3000,0x4000,MD_SVC_POOL_BASE,
        edge_code,sizeof(edge_code),&word,&edge)==-ENOTSUP);
    assert(!md_svc_single_plan(0x1004,0xd28009e8,0x3000,0x4000,MD_SVC_POOL_BASE,edge_code,sizeof(edge_code),&word,&edge));
    assert(edge.call==0x1000 && edge.svc==0x1004 && edge.size==md_svc_single_size());
    assert(!md_svc_single_plan(0x1004,0xaa0603e8,0x3000,0x4000,MD_SVC_POOL_BASE,edge_code,sizeof(edge_code),&word,&edge));
    for (unsigned reg=1;reg<=29;++reg)
        assert(!md_svc_single_plan(0x1004,0xd28009e0|reg,0x3000,0x4000,MD_SVC_POOL_BASE,edge_code,sizeof(edge_code),&word,&edge));
    assert(!md_svc_single_plan(0x1004,0xaa0703e5,0x3000,0x4000,MD_SVC_POOL_BASE,edge_code,sizeof(edge_code),&word,&edge));
    const uint32_t not_replayable[]={0xaa0003e8,0xaa0803e8,0xf28009e8,0xf9400008,0xd28009fe,0xd28009ff,0xd28009e0};
    for (unsigned i=0;i<sizeof(not_replayable)/sizeof(*not_replayable);++i)
        assert(md_svc_single_plan(0x1004,not_replayable[i],0x3000,0x4000,MD_SVC_POOL_BASE,edge_code,sizeof(edge_code),&word,&edge)==-ENOTSUP);
    puts("PASS SVC planner: exact opcode masks, branch limits and explicit rejection");
}

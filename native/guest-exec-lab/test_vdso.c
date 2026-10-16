#define _GNU_SOURCE
#include "vdso.h"
#include <assert.h>
#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

struct fixture {
    Elf64_Ehdr header;
    Elf64_Phdr ph[2];
    Elf64_Dyn dyn[9];
    Elf64_Sym symbols[2];
    uint32_t hash[2];
    Elf64_Half versions[2];
    Elf64_Verdef definition;
    Elf64_Verdaux auxiliary;
    char strings[64];
    uint32_t code;
};
#define OFFSET(member) offsetof(struct fixture,member)
static struct fixture make_fixture(void) {
    struct fixture f={0};
    memcpy(f.header.e_ident,ELFMAG,SELFMAG);
    f.header.e_ident[EI_CLASS]=ELFCLASS64;
    f.header.e_ident[EI_DATA]=ELFDATA2LSB;
    f.header.e_ident[EI_VERSION]=EV_CURRENT;
    f.header.e_version=EV_CURRENT;
    f.header.e_machine=EM_AARCH64; f.header.e_type=ET_DYN;
    f.header.e_phoff=OFFSET(ph); f.header.e_phnum=2; f.header.e_phentsize=sizeof(Elf64_Phdr);
    f.ph[0]=(Elf64_Phdr){.p_type=PT_LOAD,.p_flags=PF_R|PF_X,.p_filesz=sizeof(f),.p_memsz=sizeof(f)};
    f.ph[1]=(Elf64_Phdr){.p_type=PT_DYNAMIC,.p_vaddr=OFFSET(dyn),.p_filesz=sizeof(f.dyn)};
    f.dyn[0]=(Elf64_Dyn){.d_tag=DT_SYMTAB,.d_un.d_val=OFFSET(symbols)};
    f.dyn[1]=(Elf64_Dyn){.d_tag=DT_STRTAB,.d_un.d_val=OFFSET(strings)};
    f.dyn[2]=(Elf64_Dyn){.d_tag=DT_STRSZ,.d_un.d_val=sizeof(f.strings)};
    f.dyn[3]=(Elf64_Dyn){.d_tag=DT_HASH,.d_un.d_val=OFFSET(hash)};
    f.dyn[4]=(Elf64_Dyn){.d_tag=DT_VERSYM,.d_un.d_val=OFFSET(versions)};
    f.dyn[5]=(Elf64_Dyn){.d_tag=DT_VERDEF,.d_un.d_val=OFFSET(definition)};
    f.dyn[6]=(Elf64_Dyn){.d_tag=DT_VERDEFNUM,.d_un.d_val=1};
    f.dyn[7]=(Elf64_Dyn){.d_tag=DT_SYMENT,.d_un.d_val=sizeof(Elf64_Sym)};
    f.hash[1]=2;
    f.symbols[1]=(Elf64_Sym){.st_info=ELF64_ST_INFO(STB_GLOBAL,STT_FUNC),
        .st_shndx=1,.st_value=OFFSET(code),.st_size=4};
    f.versions[1]=2;
    f.definition=(Elf64_Verdef){.vd_version=VER_DEF_CURRENT,.vd_ndx=2,.vd_cnt=1,
        .vd_aux=OFFSET(auxiliary)-OFFSET(definition)};
    f.auxiliary.vda_name=sizeof("__kernel_clock_gettime");
    memcpy(f.strings,"__kernel_clock_gettime\0LINUX_2.6.39",sizeof("__kernel_clock_gettime\0LINUX_2.6.39"));
    return f;
}
int main(void) {
    struct fixture good=make_fixture(), f=good;
    assert(md_vdso_clock(&f,sizeof(f))==(md_vdso_clock_fn)&f.code);
    assert(!md_vdso_clock(NULL,4096));
    assert(!md_vdso_clock(&f,sizeof(Elf64_Ehdr)-1));
    assert(!md_vdso_clock(&f,OFFSET(ph)+sizeof(Elf64_Phdr)));
    f.header.e_machine=EM_X86_64; assert(!md_vdso_clock(&f,sizeof(f))); f=good;
    f.header.e_phoff=UINT64_MAX; assert(!md_vdso_clock(&f,sizeof(f))); f=good;
    f.ph[0].p_vaddr=4096; assert(!md_vdso_clock(&f,sizeof(f))); f=good;
    f.ph[0].p_flags=PF_R; assert(!md_vdso_clock(&f,sizeof(f))); f=good;
    f.ph[1].p_vaddr=sizeof(f); assert(!md_vdso_clock(&f,sizeof(f))); f=good;
    for (unsigned i=0;i<9;++i) f.dyn[i].d_tag=DT_DEBUG;
    assert(!md_vdso_clock(&f,sizeof(f))); f=good;
    f.dyn[2].d_un.d_val=UINT64_MAX; assert(!md_vdso_clock(&f,sizeof(f))); f=good;
    f.dyn[3].d_tag=DT_DEBUG; assert(!md_vdso_clock(&f,sizeof(f))); f=good;
    f.dyn[7].d_tag=DT_DEBUG; assert(!md_vdso_clock(&f,sizeof(f))); f=good;
    f.hash[1]=UINT32_MAX; assert(!md_vdso_clock(&f,sizeof(f))); f=good;
    f.symbols[1].st_value=sizeof(f); assert(!md_vdso_clock(&f,sizeof(f))); f=good;
    f.symbols[1].st_name=sizeof(f.strings); assert(!md_vdso_clock(&f,sizeof(f))); f=good;
    f.symbols[1].st_info=ELF64_ST_INFO(STB_LOCAL,STT_FUNC); assert(!md_vdso_clock(&f,sizeof(f))); f=good;
    f.versions[1]|=0x8000; assert(!md_vdso_clock(&f,sizeof(f))); f=good;
    f.definition.vd_aux=UINT32_MAX; assert(!md_vdso_clock(&f,sizeof(f))); f=good;
    f.definition.vd_ndx=3; f.definition.vd_next=UINT32_MAX; assert(!md_vdso_clock(&f,sizeof(f))); f=good;
    f.strings[f.auxiliary.vda_name]='X'; assert(!md_vdso_clock(&f,sizeof(f)));
    puts("PASS vDSO: exact arm64 symbol/version, bounded tables and unsupported-layout fallback");
    void *vdso=(void *)getauxval(AT_SYSINFO_EHDR);
    md_vdso_clock_fn clock=md_vdso_clock(vdso,(size_t)sysconf(_SC_PAGESIZE));
    if (clock) {
        struct timespec a,b,c;
        assert(!clock_gettime(CLOCK_MONOTONIC,&a));
        assert(!clock(CLOCK_MONOTONIC,&b));
        assert(!clock_gettime(CLOCK_MONOTONIC,&c));
        assert(a.tv_sec<b.tv_sec || (a.tv_sec==b.tv_sec && a.tv_nsec<=b.tv_nsec));
        assert(b.tv_sec<c.tv_sec || (b.tv_sec==c.tv_sec && b.tv_nsec<=c.tv_nsec));
        puts("PASS vDSO: live kernel monotonic clock");
    } else puts("SKIP vDSO: kernel clock export unavailable; syscall fallback required");
    return 0;
}

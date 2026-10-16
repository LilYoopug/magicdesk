#include "vdso.h"
#include <elf.h>
#include <stdint.h>

static const void *span(const char *image,size_t size,uint64_t offset,size_t bytes,size_t alignment) {
    if (offset>size || bytes>size-offset || offset%alignment) return NULL;
    return image+offset;
}
static int name_is(const char *strings,size_t size,uint32_t offset,const char *name) {
    while (offset<size) {
        char c=strings[offset++];
        if (c!=*name++) return 0;
        if (!c) return 1;
    }
    return 0;
}
md_vdso_clock_fn md_vdso_clock(const void *mapping,size_t first_page) {
    const char *image=mapping;
    if (!image || first_page<sizeof(Elf64_Ehdr)) return NULL;
    const Elf64_Ehdr *eh=mapping;
    if (eh->e_ident[EI_MAG0]!=ELFMAG0 || eh->e_ident[EI_MAG1]!=ELFMAG1
            || eh->e_ident[EI_MAG2]!=ELFMAG2 || eh->e_ident[EI_MAG3]!=ELFMAG3
            || eh->e_ident[EI_CLASS]!=ELFCLASS64 || eh->e_ident[EI_DATA]!=ELFDATA2LSB
            || eh->e_ident[EI_VERSION]!=EV_CURRENT || eh->e_version!=EV_CURRENT || eh->e_machine!=EM_AARCH64
            || eh->e_type!=ET_DYN || eh->e_phentsize!=sizeof(Elf64_Phdr)) return NULL;
    const Elf64_Phdr *ph=span(image,first_page,eh->e_phoff,
        (size_t)eh->e_phnum*sizeof(*ph),_Alignof(Elf64_Phdr));
    if (!ph) return NULL;
    size_t size=0;
    const Elf64_Phdr *dynamic=NULL;
    for (unsigned i=0;i<eh->e_phnum;++i) {
        if (ph[i].p_type==PT_LOAD) {
            /* Linux arm64's vDSO is one zero-based RX segment. Do not infer
             * readability across gaps or invent a load bias for another ABI. */
            if (size || ph[i].p_offset || ph[i].p_vaddr || ph[i].p_filesz>ph[i].p_memsz
                    || (ph[i].p_flags&(PF_R|PF_X))!=(PF_R|PF_X)) return NULL;
            size=ph[i].p_filesz;
        } else if (ph[i].p_type==PT_DYNAMIC) dynamic=&ph[i];
    }
    if (!size || !dynamic || !span(image,size,eh->e_phoff,
            (size_t)eh->e_phnum*sizeof(*ph),_Alignof(Elf64_Phdr))) return NULL;
    const Elf64_Dyn *dyn=span(image,size,dynamic->p_vaddr,dynamic->p_filesz,_Alignof(Elf64_Dyn));
    if (!dyn) return NULL;
    uint64_t symbols=0,strings=0,string_size=0,hash=0,versions=0,definitions=0,definition_count=0;
    int ended=0, symbol_size=0;
    for (size_t i=0;i<dynamic->p_filesz/sizeof(*dyn);++i) {
        uint64_t value=dyn[i].d_un.d_val;
        if (dyn[i].d_tag==DT_NULL) { ended=1; break; }
        switch (dyn[i].d_tag) {
        case DT_SYMTAB: symbols=value; break;
        case DT_SYMENT: if (value!=sizeof(Elf64_Sym)) return NULL; symbol_size=1; break;
        case DT_STRTAB: strings=value; break;
        case DT_STRSZ: string_size=value; break;
        case DT_HASH: hash=value; break;
        case DT_VERSYM: versions=value; break;
        case DT_VERDEF: definitions=value; break;
        case DT_VERDEFNUM: definition_count=value; break;
        }
    }
    if (!ended || !symbol_size || !symbols || !strings || !hash || !versions || !definitions
            || !definition_count || definition_count>size/sizeof(Elf64_Verdef)) return NULL;
    const uint32_t *table=span(image,size,hash,2*sizeof(*table),_Alignof(uint32_t));
    const char *names=span(image,size,strings,string_size,1);
    if (!table || !names || table[1]>size/sizeof(Elf64_Sym)) return NULL;
    const Elf64_Sym *syms=span(image,size,symbols,(size_t)table[1]*sizeof(*syms),_Alignof(Elf64_Sym));
    const Elf64_Half *vers=span(image,size,versions,(size_t)table[1]*sizeof(*vers),_Alignof(Elf64_Half));
    if (!syms || !vers) return NULL;
    for (uint32_t i=0;i<table[1];++i) {
        const Elf64_Sym *s=&syms[i];
        unsigned binding=ELF64_ST_BIND(s->st_info);
        if (ELF64_ST_TYPE(s->st_info)!=STT_FUNC || (binding!=STB_GLOBAL && binding!=STB_WEAK)
                || s->st_shndx==SHN_UNDEF || (vers[i]&0x8000)
                || !name_is(names,string_size,s->st_name,"__kernel_clock_gettime")) continue;
        uint64_t at=definitions;
        for (uint64_t n=0;n<definition_count;++n) {
            const Elf64_Verdef *v=span(image,size,at,sizeof(*v),_Alignof(Elf64_Verdef));
            if (!v || v->vd_version!=VER_DEF_CURRENT) return NULL;
            if (!(v->vd_flags&VER_FLG_BASE) && (v->vd_ndx&0x7fff)==vers[i]) {
                if (!v->vd_cnt || v->vd_aux>size-at) return NULL;
                const Elf64_Verdaux *a=span(image,size,at+v->vd_aux,sizeof(*a),_Alignof(Elf64_Verdaux));
                if (!a || !name_is(names,string_size,a->vda_name,"LINUX_2.6.39")) return NULL;
                return (md_vdso_clock_fn)span(image,size,s->st_value,s->st_size ? s->st_size : 4,4);
            }
            if (!v->vd_next || v->vd_next>size-at) break;
            at+=v->vd_next;
        }
    }
    return NULL;
}

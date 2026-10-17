#!/usr/bin/env python3
"""Integrate the common entry ABI into an isolated glibc 2.41 AArch64 tree."""
import argparse
import shutil
from pathlib import Path
from integrate_musl import replace_once


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    source = parser.parse_args().source.resolve()
    lab = Path(__file__).resolve().parent
    arch = source / 'sysdeps/unix/sysv/linux/aarch64'
    shutil.copyfile(lab.parent / 'shroot/src/cooperative_entry.h', source / 'include/cooperative_entry.h')
    shutil.copyfile(lab / 'glibc_entry.c', arch / 'shroot-entry.c')
    shutil.copyfile(lab / 'glibc_entry_asm.S', arch / 'shroot-entry-asm.S')
    replace_once(arch / 'Makefile', 'ifeq ($(subdir),misc)',
                 'ifeq ($(subdir),misc)\nsysdep_routines += shroot-entry shroot-entry-asm\n'
                 'CFLAGS-shroot-entry.c += -fexceptions -fasynchronous-unwind-tables')
    # Symbol discovery links libc objects first, then rebuilds selected objects
    # for rtld. These references disappear in the IS_IN(rtld) rebuild.
    replace_once(source / 'elf/Makefile', '  __syscall_cancel \\\n',
                 '  __syscall_cancel \\\n'
                 '  __shroot_entry \\\n'
                 '  __shroot_syscall \\\n'
                 '  __shroot_syscall_asm \\\n')
    descr = source / 'nptl/descr.h'
    replace_once(descr, '#include <list_t.h>', '#include <list_t.h>\n#include <cooperative_entry.h>')
    replace_once(descr, '  list_t list;', '  list_t list;\n  struct md_entry_client shroot_client;')
    replace_once(source / 'nptl/allocatestack.c', '  pd->lock = LLL_LOCK_INITIALIZER;',
                 '  pd->lock = LLL_LOCK_INITIALIZER;\n'
                 '  pd->shroot_client = (struct md_entry_client){0};')
    replace_once(source / 'sysdeps/nptl/_Fork.c', '      struct pthread *self = THREAD_SELF;',
                 '      struct pthread *self = THREAD_SELF;\n'
                 '      self->shroot_client = (struct md_entry_client){0};')
    replace_once(source / 'csu/libc-start.c', '  /* Call the initializer of the program, if any.  */',
                 '  extern void __shroot_init (char **) attribute_hidden;\n'
                 '  __shroot_init (&argv[argc + 1]);\n\n'
                 '  /* Call the initializer of the program, if any.  */')
    header = arch / 'sysdep.h'
    asm = r'''
# if IS_IN (libc)
#  define SHROOT_DO_SYSCALL \
    adrp x9, __shroot_entry; \
    ldr x9, [x9, :lo12:__shroot_entry]; \
    cbz x9, 991f; \
    ldr w10, [x9, #24]; \
    cmp x8, x10; \
    b.hs 991f; \
    ldr x9, [x9, #16]; \
    ldrb w10, [x9, x8]; \
    tbz w10, #0, 991f; \
    stp x29, x30, [sp, #-16]!; \
    cfi_adjust_cfa_offset (16); \
    cfi_rel_offset (x29, 0); \
    cfi_rel_offset (x30, 8); \
    bl __shroot_syscall_asm; \
    ldp x29, x30, [sp], #16; \
    cfi_restore (x29); \
    cfi_restore (x30); \
    cfi_adjust_cfa_offset (-16); \
    b 992f; \
991: svc 0; \
992:
# else
#  define SHROOT_DO_SYSCALL svc 0
# endif
'''
    replace_once(header, '# undef\tDO_CALL', asm + '\n# undef\tDO_CALL')
    replace_once(header, '    svc 0\n', '    SHROOT_DO_SYSCALL\n')
    replace_once(arch / 'syscall.S', '\tsvc\t0x0', '\tSHROOT_DO_SYSCALL')
    replace_once(header, '# define INTERNAL_SYSCALL_RAW(name, nr, args...)',
                 '# define SHROOT_KERNEL_SYSCALL_RAW(name, nr, args...)')
    c = '''
# if IS_IN (libc) && !defined SHROOT_RAW_SYSCALLS
#  include <cooperative_entry.h>
extern const struct md_entry_api *__shroot_entry attribute_hidden;
extern long __shroot_syscall (long, const uint64_t *) attribute_hidden;
extern int __shroot_cp_try (long, const uint64_t *, long *) attribute_hidden;
'''
    for n in range(7):
        names = [f'a{i}' for i in range(n)]
        args = ', '.join(f'(uint64_t) ({a})' for a in names) or '0'
        c += f'#  define SHROOT_ARGS_{n}({", ".join(names)}) {{{args}}}\n'
    c += r'''
#  define INTERNAL_SYSCALL_RAW(name, nr, args...) \
  ({ long _shroot_nr = (name), _shroot_result; \
     if (md_entry_offered (__shroot_entry, _shroot_nr, MD_ENTRY_ORDINARY)) \
       { const uint64_t _shroot_args[6] = SHROOT_ARGS_##nr(args); \
         _shroot_result = __shroot_syscall (_shroot_nr, _shroot_args); } \
     else _shroot_result = SHROOT_KERNEL_SYSCALL_RAW (_shroot_nr, nr, args); \
     _shroot_result; })
# else
#  define INTERNAL_SYSCALL_RAW(name, nr, args...) SHROOT_KERNEL_SYSCALL_RAW(name, nr, args)
# endif
'''
    replace_once(header, '# undef INTERNAL_SYSCALL\n', c + '\n# undef INTERNAL_SYSCALL\n')
    cancel = source / 'nptl/cancellation.c'
    replace_once(cancel, '  /* If cancellation is not enabled,',
                 '  const uint64_t shroot_args[6] = {a1, a2, a3, a4, a5, a6};\n'
                 '  if (__shroot_cp_try (nr, shroot_args, &result)) goto shroot_completed;\n\n'
                 '  /* If cancellation is not enabled,')
    replace_once(cancel, '  /* If the cancellable syscall was interrupted',
                 'shroot_completed:\n  /* If the cancellable syscall was interrupted')


if __name__ == '__main__':
    main()

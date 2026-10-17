#!/usr/bin/env python3
"""Apply the bounded AArch64 source integration to an unpacked musl 1.2.5 tree."""
import argparse
import shutil
from pathlib import Path


def replace_once(path, before, after):
    content = path.read_text()
    if content.count(before) != 1:
        raise RuntimeError(f'{path}: expected exactly one integration boundary')
    path.write_text(content.replace(before, after, 1))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    replace_once(source / 'Makefile', 'src/internal/stdio_impl.h src/internal/pthread_impl.h',
                 'src/internal/cooperative_entry.h '
                 'src/internal/stdio_impl.h src/internal/pthread_impl.h')
    runtime = Path(__file__).resolve().parent.parent / 'shroot/src'
    shutil.copyfile(runtime / 'cooperative_entry.h', source / 'src/internal/cooperative_entry.h')
    arch = source / 'arch/aarch64/syscall_arch.h'
    replace_once(arch, '#define __SYSCALL_LL_E(x)', '''#include "cooperative_entry.h"
hidden extern const struct md_entry_api *__shroot_entry;
hidden int __shroot_try(long, long, long, long, long, long, long, long *);

#define __SYSCALL_LL_E(x)''')
    for count in range(7):
        arguments = list('abcdef')[:count] + ['0'] * (6-count)
        signature = f'static inline long __syscall{count}(long n'
        signature += ''.join(f', long {arg}' for arg in 'abcdef'[:count]) + ')\n{'
        replace_once(arch, signature, signature + '\n\tlong result;\n'
                     '\tif (md_entry_offered(__shroot_entry, n, MD_ENTRY_ORDINARY) && __shroot_try(n, '
                     + ', '.join(arguments) + ', &result)) return result;')
    pthread = source / 'src/internal/pthread_impl.h'
    replace_once(pthread, '#include <pthread.h>', '#include <pthread.h>\n#include "cooperative_entry.h"')
    replace_once(pthread, '\tvoid *stdio_locks;', '\tvoid *stdio_locks;\n\tstruct md_entry_client shroot_client;')
    start = source / 'src/env/__libc_start_main.c'
    replace_once(start, '#define AUX_CNT 38', 'hidden void __shroot_init(size_t *);\n\n#define AUX_CNT 38')
    replace_once(start, '\t__init_ssp((void *)aux[AT_RANDOM]);',
                 '\t__init_ssp((void *)aux[AT_RANDOM]);\n\t__shroot_init(auxv);')
    fork = source / 'src/process/_Fork.c'
    replace_once(fork, '\t\tpthread_t self = __pthread_self();',
                 '\t\tpthread_t self = __pthread_self();\n'
                 '\t\tself->shroot_client = (struct md_entry_client){0};')
    cancel = source / 'src/thread/pthread_cancel.c'
    replace_once(cancel, 'hidden long __cancel(), __syscall_cp_asm(), __syscall_cp_c();',
                 'hidden int __shroot_cp_try(long,long,long,long,long,long,long,long *);\n'
                 'hidden long __cancel(), __syscall_cp_asm(), __syscall_cp_c();')
    replace_once(cancel, '\tr = __syscall_cp_asm(&self->cancel, nr, u, v, w, x, y, z);',
                 '\tif (!__shroot_cp_try(nr,u,v,w,x,y,z,&r))\n'
                 '\t\tr = __syscall_cp_asm(&self->cancel, nr, u, v, w, x, y, z);')
    # The isolated AArch64 fixture targets Shroot's Linux >= 5.15 baseline.
    # O_CLOEXEC is atomic there; preserve it on open, remove only the legacy
    # post-open repair (also in native/entry-disabled controls).
    replace_once(source / 'src/fcntl/open.c',
                 '\tif (fd>=0 && (flags & O_CLOEXEC))\n'
                 '\t\t__syscall(SYS_fcntl, fd, F_SETFD, FD_CLOEXEC);\n', '')
    shutil.copyfile(Path(__file__).with_name('musl_entry.c'),
                    source / 'src/thread/aarch64/shroot.c')


if __name__ == '__main__':
    main()

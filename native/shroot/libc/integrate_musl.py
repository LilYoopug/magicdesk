#!/usr/bin/env python3
"""Integrate AArch64 musl syscall wrappers and checked lifecycle hooks."""
import argparse
from pathlib import Path
import re
from source_integration import IntegrationError, SourceIntegration

ARCH = 'arch/aarch64/syscall_arch.h'
FILES = (ARCH, 'Makefile', 'src/internal/pthread_impl.h',
         'src/env/__libc_start_main.c', 'src/process/_Fork.c',
         'src/thread/pthread_cancel.c', 'src/fcntl/open.c')


def redirect_syscalls(tree):
    tree.regex(ARCH, r'^#define[ \t]+__SYSCALL_LL_E\(x\)[^\n]*',
               lambda match: '#include "cooperative_entry.h"\n'
               'hidden extern const struct md_entry_api *__shroot_entry;\n'
               'hidden int __shroot_try(long, long, long, long, long, long, long, long *);\n\n'
               + match[0])
    seen = set()

    def wrapper(match):
        arity = int(match[1])
        parameters = match[2].split(',')
        names = [re.fullmatch(r'\s*long\s+([A-Za-z_]\w*)\s*', p) for p in parameters]
        if arity in seen or len(names) != arity + 1 or not all(names):
            raise IntegrationError(f'{ARCH}: unexpected __syscall{arity} signature')
        seen.add(arity)
        names = [p[1] for p in names]
        if len(set(names)) != len(names) or '_shroot_result' in names:
            raise IntegrationError(f'{ARCH}: conflicting syscall parameters')
        nr = names[0]
        arguments = ', '.join(names[1:] + ['0'] * (6 - arity))
        return (match[0] + '\n\tlong _shroot_result;\n'
                f'\tif (md_entry_offered(__shroot_entry, {nr}, MD_ENTRY_ORDINARY) && '
                f'__shroot_try({nr}, {arguments}, &_shroot_result)) return _shroot_result;')

    tree.regex(ARCH, r'^static\s+inline\s+long\s+__syscall([0-6])\s*\(([^)]*)\)\s*\{',
               wrapper, count=7)
    if seen != set(range(7)):
        raise IntegrationError(f'{ARCH}: incomplete syscall wrapper family')


def integrate(source):
    tree = SourceIntegration(source, FILES)
    redirect_syscalls(tree)
    here = Path(__file__).resolve().parent
    tree.add('src/internal/cooperative_entry.h', (here.parent / 'src/cooperative_entry.h').read_text())
    tree.add('src/thread/aarch64/shroot.c', (here / 'musl_entry.c').read_text())
    tree.finish(here / 'musl.patch')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    integrate(args.source)


if __name__ == '__main__':
    main()

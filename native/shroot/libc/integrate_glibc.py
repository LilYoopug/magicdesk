#!/usr/bin/env python3
"""Integrate AArch64 glibc syscall wrappers and checked lifecycle hooks."""
import argparse
from pathlib import Path
import re
from source_integration import IntegrationError, SourceIntegration

ARCH = 'sysdeps/unix/sysv/linux/aarch64/'
FILES = (ARCH + 'sysdep.h', ARCH + 'syscall.S', ARCH + 'Makefile',
         'elf/Makefile', 'elf/Versions', 'nptl/descr.h', 'nptl/allocatestack.c',
         'sysdeps/nptl/_Fork.c', 'csu/libc-start.c')


def build_hooks(tree):
    tree.regex('elf/Makefile', r'^rtld-stubbed-symbols = \\\n',
               lambda match: match[0] + '  __shroot_entry \\\n  __shroot_syscall \\\n  __shroot_syscall_asm \\\n')
    tree.regex(ARCH + 'Makefile', r'^ifeq \(\$\(subdir\),misc\)\n',
               lambda match: match[0] + 'sysdep_routines += shroot-entry shroot-entry-asm\n'
               'CFLAGS-shroot-entry.c += -fexceptions -fasynchronous-unwind-tables\n')


def legacy_cancellation(tree):
    # Older glibc enables asynchronous cancellation around its original syscall.
    # Retain that mechanism; the hook declines while CANCELTYPE_BITMASK is set.
    # Verify both wrappers instead of inferring this contract from a version.
    for name in ('SYSCALL_CANCEL', 'INTERNAL_SYSCALL_CANCEL'):
        pattern = r'^#define ' + name + r'\(\.\.\.\)[^\n]*\n(?:[^\n]*\\\n)*[^\n]*'
        def check(match):
            if match[0].count('LIBC_CANCEL_ASYNC ()') != 1 or match[0].count('LIBC_CANCEL_RESET (sc_cancel_oldtype)') != 1:
                raise IntegrationError('unknown legacy cancellation boundary')
            return match[0]
        tree.regex('sysdeps/unix/sysdep.h', pattern, check)


def redirect_syscalls(tree):
    header = ARCH + 'sysdep.h'

    def assembly_wrapper(match):
        body, count = re.subn(r'(?m)^([ \t]*)svc[ \t]+(?:0|0x0)[ \t]*$',
                             r'\1SHROOT_DO_SYSCALL', match[0])
        if count != 1:
            raise IntegrationError(f'{header}: expected one svc in DO_CALL')
        return '# include <shroot-syscall.h>\n' + body

    tree.regex(header, r'^#[ \t]*define[ \t]+DO_CALL\([^\n]*\n(?:[^\n]*\\\n)*[^\n]*',
               assembly_wrapper)
    # Redirect only syscall(2)'s own assembly body, not clone or cancellation.
    def syscall_wrapper(match):
        body, count = re.subn(r'(?m)^([ \t]*)svc[ \t]+(?:0|0x0)[ \t]*$',
                             r'\1SHROOT_DO_SYSCALL', match[0])
        if count != 1:
            raise IntegrationError('syscall.S: expected one svc in syscall entry')
        return body

    tree.regex(ARCH + 'syscall.S', r'^ENTRY\s*\(syscall\)[\s\S]*?^PSEUDO_END\s*\(syscall\)',
               syscall_wrapper)
    tree.regex(header, r'^(#[ \t]*define[ \t]+)INTERNAL_SYSCALL_RAW(?=\()',
               r'\1SHROOT_KERNEL_SYSCALL_RAW')
    tree.regex(header, r'^#[ \t]*undef[ \t]+INTERNAL_SYSCALL[ \t]*$',
               lambda match: '# include <shroot-syscall.h>\n' + match[0])


def integrate(source, library_path=None):
    if library_path is not None and not re.fullmatch(r'/opt/shroot/libc/[A-Za-z0-9_.-]+/lib', library_path):
        raise IntegrationError('invalid private library directory')
    paths = (*FILES, 'nptl/cancellation.c') + (('elf/dl-load.c',) if library_path else ())
    tree = SourceIntegration(source, paths)
    modern = bool(re.search(r'^__internal_syscall_cancel\s*\(', tree.files['nptl/cancellation.c'], re.M))
    if not modern:
        tree = SourceIntegration(source, (*paths, 'sysdeps/unix/sysdep.h'))
    redirect_syscalls(tree)
    build_hooks(tree)
    here = Path(__file__).resolve().parent
    patches = [here / 'glibc.patch']
    if modern:
        patches.append(here / 'glibc-cancellation.patch')
    else:
        legacy_cancellation(tree)
    tree.add('include/shroot-cancellation.h', f'#define SHROOT_MODERN_CANCEL {int(modern)}\n')
    if library_path:
        tree.add('include/shroot-library-path.h', f'#define SHROOT_LIBC_PATH "{library_path}"\n')
        patches.append(here / 'glibc-private.patch')
    tree.add('include/cooperative_entry.h', (here.parent / 'src/cooperative_entry.h').read_text())
    for original, target in (('glibc_entry.c', 'shroot-entry.c'),
                             ('glibc_entry_asm.S', 'shroot-entry-asm.S'),
                             ('glibc_syscall.h', 'shroot-syscall.h')):
        tree.add(ARCH + target, (here / original).read_text())
    tree.finish(*patches)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--library-path', help='Private deployment library directory')
    args = parser.parse_args()
    integrate(args.source, args.library_path)


if __name__ == '__main__':
    main()

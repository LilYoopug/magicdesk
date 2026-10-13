#!/usr/bin/env python3
"""Proc bind/remount policy without reading or writing host control files."""
import argparse
import ctypes
import errno
import os
from pathlib import Path
import sys
import tempfile


def guest():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                           ctypes.c_ulong, ctypes.c_void_p]

    def mount(source, target, kind, flags):
        args = [os.fsencode(value) if value is not None else None
                for value in (source, target, kind)]
        if libc.mount(*args, flags, None):
            raise OSError(ctypes.get_errno(), repr((source, target, kind, flags)))

    with tempfile.TemporaryDirectory(prefix='md-proc-policy-') as directory:
        mount('proc', directory, 'proc', 2 | 4 | 8)
        try:
            entries = os.listdir(directory)
            for name in ('sysrq-trigger', 'kcore', 'kmsg', 'keys', 'asound', 'kallsyms'):
                assert name not in entries, name
                for lookup in (os.stat, lambda p: os.open(p, os.O_PATH)):
                    try:
                        lookup(directory + '/' + name)
                    except OSError as error:
                        assert error.errno == errno.ENOENT, error
                    else:
                        raise AssertionError('host kernel control was exposed: ' + name)
            print('PASS mounted proc omits unsupported host-kernel controls', flush=True)
            for name in ('irq', 'bus', 'fs', 'version'):
                target = directory + '/' + name
                print('LOOKUP', target, flush=True)
                before = os.stat(target)
                fd = os.open(target, os.O_PATH | os.O_CLOEXEC)
                try:
                    assert os.fstat(fd).st_ino == before.st_ino
                finally:
                    os.close(fd)
                print('O_PATH', name, 'ok', flush=True)
                mount(target, target, None, 4096 | 16384)
                print('BIND', name, 'ok', flush=True)
                mount(None, target, None, 4096 | 32 | 1 | 2 | 4 | 8)
                print('REMOUNT', name, 'ok', flush=True)
                assert os.statvfs(target).f_flag & os.ST_RDONLY
            target = directory + '/version'
            try:
                fd = os.open(target, os.O_WRONLY)
            except OSError as error:
                assert error.errno == errno.EROFS, error
            else:
                os.close(fd)
                raise AssertionError('read-only proc mount admitted write open')
            print('PASS proc bind/remount, readonly metadata and denied data open', flush=True)
        finally:
            assert libc.umount2(os.fsencode(directory), 2) == 0, ctypes.get_errno()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    args = parser.parse_args()
    from test_oci_services import Suite
    suite = Suite(args.build, args.build)
    target = '/tmp/md-proc-policy-' + suite.report['id']
    prefix = [suite.runner, '--store', args.store, '--user', '0:0']
    try:
        suite.transport.upload(suite.client, Path(__file__), suite.base + '/test.py')
        suite.command(prefix + ['--', '/bin/mkdir', target])
        suite.command(prefix + ['--bind-ro', suite.base, target, '--deadline-seconds', '60', '--',
                                '/usr/bin/unshare', '--mount', '/usr/bin/python3', target + '/test.py', '--guest'],
                      timeout=80)
        suite.report['passed'] = True
    finally:
        try:
            suite.command(prefix + ['--', '/bin/rmdir', target])
        finally:
            suite.finish()


if __name__ == '__main__':
    guest() if sys.argv[1:] == ['--guest'] else main()

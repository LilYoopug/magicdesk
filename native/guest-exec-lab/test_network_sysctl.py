#!/usr/bin/env python3
"""Namespace-owned IPv4 policy files through ordinary proc IO, under shell."""
import argparse
import ctypes
import errno
import os
from pathlib import Path
import sys
import tempfile

BASE = '/proc/sys/net/ipv4/'


def denied(action, code):
    try:
        action()
    except OSError as error:
        assert error.errno == code, error
    else:
        raise AssertionError('unexpected success')


def read(name):
    return Path(BASE + name).read_text().split()


def write(name, text):
    fd = os.open(BASE + name, os.O_WRONLY | os.O_TRUNC | os.O_CLOEXEC)
    try:
        assert os.write(fd, text.encode()) == len(text)
    finally:
        os.close(fd)


def guest():
    def descriptors():
        result = {}
        for name in os.listdir('/proc/self/fd'):
            try:
                result[name] = os.readlink('/proc/self/fd/' + name)
            except FileNotFoundError:
                pass
        return result

    port, ping, local = 'ip_unprivileged_port_start', 'ping_group_range', 'ip_local_port_range'
    assert read('ip_forward') == ['0']
    write('ip_forward', '1\n')
    assert read('ip_forward') == ['1']
    for text in ('-1', '2', '1 2', 'garbage'):
        denied(lambda: write('ip_forward', text), errno.EINVAL)
        assert read('ip_forward') == ['1']
    assert read(port) == ['1024']
    write(port, '0\n')
    write(ping, '0 2147483647\n')
    assert read(port) == ['0'] and read(ping) == ['0', '2147483647']
    assert read(local) == ['32768', '60999']
    for text in ('-1', '65536', 'garbage', '1 2', '99999999999999999999999'):
        denied(lambda: write(port, text), errno.EINVAL)
        assert read(port) == ['0']
    write(local, '10000 20000')
    denied(lambda: write(port, '10001'), errno.EINVAL)
    write(port, '10000')
    denied(lambda: write(local, '9999 20000'), errno.EINVAL)
    write(ping, '40 30')
    assert read(ping) == ['1', '0']
    print('PASS namespace IPv4 values, parsing and coordinated port bounds', flush=True)
    fd = os.open(BASE + port, os.O_RDWR | os.O_CLOEXEC)
    assert os.pread(fd, 32, 0) == b'10000\n'
    child = os.fork()
    if child == 0:
        libc = ctypes.CDLL(None, use_errno=True)
        assert libc.unshare(0x40000000) == 0, ctypes.get_errno()
        assert read(port) == ['1024']
        assert read('ip_forward') == ['0']
        write(port, '42')
        assert read(port) == ['42'] and os.pread(fd, 32, 0) == b'10000\n'
        os.setgid(1234)
        os.setuid(1234)
        denied(lambda: write(port, '0'), errno.EACCES)
        denied(lambda: write('ip_forward', '1'), errno.EACCES)
        denied(lambda: os.write(fd, b'0'), errno.EACCES)
        os._exit(0)
    assert os.waitpid(child, 0) == (child, 0)
    assert read(port) == ['10000']
    assert read('ip_forward') == ['1']
    os.close(fd)
    print('PASS network namespace isolation, retained descriptors and writer authority', flush=True)
    fd = os.open(BASE + port, os.O_RDWR | os.O_CLOEXEC)
    alias = os.dup(fd)
    try:
        assert os.write(fd, b'10') == 2
        assert os.write(alias, b'30') == 2 and read(port) == ['10']
        assert os.pwrite(fd, b'20', 1) == 2 and read(port) == ['10']
        assert os.pwrite(fd, b'30', 0) == 2 and read(port) == ['30']
        os.lseek(alias, 0, 0)
        assert os.read(fd, 1) == b'3' and os.read(alias, 16) == b'0\n'
        pathfd = os.open(BASE + port, os.O_PATH)
        try:
            a, b = os.fstat(pathfd), os.fstat(fd)
            assert (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)
            denied(lambda: os.read(pathfd, 1), errno.EBADF)
        finally:
            os.close(pathfd)
    finally:
        os.close(alias)
        os.close(fd)
    print('PASS sysctl independent positional IO and shared dup offsets', flush=True)

    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                           ctypes.c_ulong, ctypes.c_void_p]
    with tempfile.TemporaryDirectory(prefix='md-net-proc-') as directory:
        assert libc.mount(b'proc', os.fsencode(directory), b'proc', 2 | 4 | 8, None) == 0, ctypes.get_errno()
        target = directory + '/sys/net/ipv4/' + port
        fd = os.open(target, os.O_RDWR)
        try:
            assert os.pread(fd, 32, 0) == b'30\n'
            assert libc.mount(None, os.fsencode(directory), None, 32 | 1 | 2 | 4 | 8, None) == 0, ctypes.get_errno()
            denied(lambda: os.open(target, os.O_WRONLY), errno.EROFS)
            denied(lambda: os.pwrite(fd, b'4', 0), errno.EROFS)
            assert os.pread(fd, 32, 0) == b'30\n'
            assert libc.umount2(os.fsencode(directory), 2) == 0, ctypes.get_errno()
            denied(lambda: os.pwrite(fd, b'4', 0), errno.EROFS)
        finally:
            os.close(fd)
    print('PASS mounted sysctl retains readonly policy through remount and detach', flush=True)
    baseline = descriptors()
    for _ in range(80):
        fd = os.open(BASE + port, os.O_RDONLY)
        alias = os.dup(fd)
        try:
            assert os.read(fd, 1) == b'3' and os.read(alias, 32) == b'0\n'
        finally:
            os.close(alias)
            os.close(fd)
    assert descriptors() == baseline, (baseline, descriptors())
    print('PASS repeated sysctl opens release the exact application FD set', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    args = parser.parse_args()
    from test_oci_services import Suite
    suite = Suite(args.build, args.build)
    target = '/tmp/md-net-sysctl-' + suite.report['id']
    prefix = [suite.runner, '--store', args.store, '--user', '0:0']
    try:
        suite.transport.upload(suite.client, Path(__file__), suite.base + '/test.py')
        suite.command(prefix + ['--', '/bin/mkdir', target])
        suite.command(prefix + ['--bind-ro', suite.base, target, '--deadline-seconds', '60', '--',
                                '/usr/bin/unshare', '--net', '--mount', '/usr/bin/python3', target + '/test.py', '--guest'],
                      timeout=80)
        suite.report['passed'] = True
    finally:
        try:
            suite.command(prefix + ['--', '/bin/rmdir', target])
        finally:
            suite.finish()


if __name__ == '__main__':
    guest() if sys.argv[1:] == ['--guest'] else main()

#!/usr/bin/env python3
"""Descriptor mount API and stock util-linux consumers, through actual shell."""
import argparse
import array
import ctypes
import errno
import fcntl
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor


def guest():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long

    def call(nr, *args, error=None):
        converted = [ctypes.c_char_p(arg.encode()) if isinstance(arg, str)
                     else ctypes.c_long(arg) for arg in args]
        result = libc.syscall(ctypes.c_long(nr), *converted)
        code = ctypes.get_errno() if result < 0 else 0
        assert code == (error or 0), (nr, args, result, code, error)
        return result

    def config(fd, key, value=None):
        return call(431, fd, 0 if value is None else 1, key, 0 if value is None else value, 0)

    def create(kind='tmpfs', **options):
        fd = call(430, kind, 1)
        for key, value in options.items():
            config(fd, key, value)
        call(431, fd, 6, 0, 0, 0)
        return fd

    with tempfile.TemporaryDirectory(prefix='md-fsopen-') as directory:
        root = Path(directory)
        call(430, 'unknown', 0, error=errno.ENODEV)
        call(430, 'tmpfs', 2, error=errno.EINVAL)
        call(431, 123456, 6, 0, 0, 0, error=errno.EBADF)
        with open('/dev/null', 'rb') as ordinary:
            call(431, ordinary.fileno(), 6, 0, 0, 0, error=errno.EINVAL)
        fd = call(430, 'tmpfs', 0)
        assert not fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        for action, expected in [(lambda: os.read(fd, 10), errno.ENODATA),
                                 (lambda: os.lseek(fd, 0, os.SEEK_SET), errno.ESPIPE),
                                 (lambda: os.pread(fd, 10, 0), errno.ESPIPE)]:
            try:
                action()
                raise AssertionError('fscontext IO unexpectedly succeeded')
            except OSError as error:
                assert error.errno == expected, error
        call(432, fd, 1, 0, error=errno.EINVAL)
        call(431, fd, 0, 'unsupported', 0, 0, error=errno.EOPNOTSUPP)
        config(fd, 'mode', '0700')
        duplicate = os.dup(fd)
        os.close(fd)
        call(431, duplicate, 6, 0, 0, 0)
        call(431, duplicate, 6, 0, 0, 0, error=errno.EBUSY)
        mount = call(432, duplicate, 1, 0)
        assert fcntl.fcntl(mount, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        assert fcntl.fcntl(mount, fcntl.F_GETFL) & os.O_PATH
        os.close(duplicate)
        assert os.fstat(mount).st_mode & 0o777 == 0o700
        nested = os.open('before-attach', os.O_CREAT | os.O_RDWR, 0o600, dir_fd=mount)
        os.write(nested, b'kept')
        os.close(nested)
        assert not (root / 'before-attach').exists()
        call(429, mount, '', -100, str(root), 4)
        assert (root / 'before-attach').read_bytes() == b'kept'
        (root / 'moved').mkdir()
        call(429, mount, '', -100, str(root / 'moved'), 4, error=errno.EINVAL)
        call(39, str(root), 2)
        assert not (root / 'before-attach').exists()
        call(429, mount, '', -100, str(root), 4, error=errno.EINVAL)
        os.close(mount)
        print('PASS fscontext state, dup, detached IO, attach and unmount', flush=True)

        # Real SCM_RIGHTS transfers retain authority, not the carrier inode.
        left, right = socket.socketpair()
        context = create(mode='0751')
        left.sendmsg([b'x'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [context]))])
        os.close(context)
        _, ancillary, _, _ = right.recvmsg(1, socket.CMSG_SPACE(4))
        received = array.array('i')
        received.frombytes(ancillary[0][2])
        mount = call(432, received[0], 0, 1)
        os.close(received[0])
        assert not fcntl.fcntl(mount, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        call(429, mount, '', -100, str(root), 4)
        os.close(mount)
        try:
            (root / 'readonly').write_text('not allowed')
            raise AssertionError('readonly mount accepted a write')
        except OSError as error:
            assert error.errno == errno.EROFS, error
        call(39, str(root), 2)
        left.close()
        right.close()
        print('PASS SCM_RIGHTS filesystem context and readonly policy', flush=True)

        context = create(mode='0750')
        child = os.fork()
        if child == 0:
            mount = call(432, context, 1, 0)
            call(429, mount, '', -100, str(root), 4)
            os.close(mount)
            os._exit(0)
        # EVENT_WAIT: child completion; outer supervised deadline fails a hang.
        assert os.waitpid(child, 0)[1] == 0
        os.close(context)
        assert root.stat().st_mode & 0o777 == 0o750
        call(39, str(root), 2)
        print('PASS inherited fscontext and shared mount publication', flush=True)

        for kind, options in [('tmpfs', 'mode=0755'), ('cgroup2', None), ('cgroup', 'devices'),
                              ('proc', None), ('devpts', 'newinstance,ptmxmode=0666,mode=0620')]:
            command = ['strace', '-e', 'trace=fsopen,fsconfig,fsmount,move_mount,mount_setattr',
                       'mount', '-t', kind]
            if options:
                command += ['-o', options]
            result = subprocess.run(command + ['none', str(root)], capture_output=True, text=True)
            print(result.stderr, end='', flush=True)
            assert result.returncode == 0, result
            assert 'fsopen(' in result.stderr and 'move_mount(' in result.stderr, result.stderr
            opened = os.open(root, os.O_PATH | os.O_DIRECTORY)
            try:
                link = '/proc/self/fd/' + str(opened)
                assert os.readlink(link) == str(root), (kind, os.readlink(link))
                with ThreadPoolExecutor(max_workers=1) as workers:
                    linked = workers.submit(os.readlink, link).result(timeout=10)
                assert linked == str(root), (kind, 'threaded proc fd', linked)
            finally:
                os.close(opened)
            if kind == 'cgroup':
                entries = Path('/proc/self/mountinfo').read_text().splitlines()
                entry = next(line for line in entries if line.split()[4] == str(root))
                assert 'devices' in entry.split(' - ')[1].split()[2].split(','), entry
            call(39, str(root), 2)
        print('PASS stock util-linux mount using new API', flush=True)

        for part in ('lower', 'upper', 'work', 'merged'):
            (root / part).mkdir()
        (root / 'lower' / 'value').write_text('lower')
        context = create('overlay', lowerdir=str(root / 'lower'), upperdir=str(root / 'upper'),
                         workdir=str(root / 'work'))
        mount = call(432, context, 1, 0)
        os.close(context)
        call(429, mount, '', -100, str(root / 'merged'), 4)
        os.close(mount)
        assert (root / 'merged' / 'value').read_text() == 'lower'
        (root / 'merged' / 'value').write_text('upper')
        assert (root / 'lower' / 'value').read_text() == 'lower'
        assert (root / 'upper' / 'value').read_text() == 'upper'
        call(39, str(root / 'merged'), 2)
        print('PASS overlay through the common filesystem provider', flush=True)

        before = len(os.listdir('/proc/self/fd'))
        for _ in range(96):
            context = create(mode='0700')
            mount = call(432, context, 1, 0)
            os.close(context)
            os.close(mount)
        assert len(os.listdir('/proc/self/fd')) == before
        print('PASS abandoned detached mounts: slot reuse and descriptor release', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    args = parser.parse_args()
    from test_oci_services import Suite
    suite = Suite(args.build, args.build)
    target = '/tmp/md-mount-api-' + suite.report['id']
    prefix = [suite.runner, '--store', args.store, '--user', '0:0']
    try:
        suite.transport.upload(suite.client, Path(__file__), suite.base + '/test.py')
        suite.command(prefix + ['--', '/bin/mkdir', target])
        command = prefix + ['--bind-ro', suite.base, target, '--deadline-seconds', '100', '--',
                            '/usr/bin/unshare', '--user', '--map-users=0:0:65536', '--map-groups=0:0:65536',
                            '--mount', '--pid', '--fork', '/usr/bin/python3', target + '/test.py', '--guest']
        suite.command(command, timeout=120)
        suite.report['passed'] = True
    finally:
        try:
            suite.command(prefix + ['--', '/bin/rmdir', target])
        finally:
            suite.finish()


if __name__ == '__main__':
    if sys.argv[1:] == ['--guest']:
        guest()
    else:
        main()

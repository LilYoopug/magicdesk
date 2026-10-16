#!/usr/bin/env python3
"""Mounted proc policies through real shell, with unmodified guest syscalls."""
import argparse
import ctypes
from contextlib import ExitStack
import errno
import fcntl
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import traceback


def detached_proc():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long

    def call(nr, *args, error=0):
        values = [ctypes.c_char_p(a.encode()) if isinstance(a, str) else ctypes.c_long(a) for a in args]
        value = libc.syscall(ctypes.c_long(nr), *values)
        actual = ctypes.get_errno() if value < 0 else 0
        assert actual == error, (nr, args, value, actual, error)
        return value

    class OpenHow(ctypes.Structure):
        _fields_ = [('flags', ctypes.c_uint64), ('mode', ctypes.c_uint64),
                    ('resolve', ctypes.c_uint64)]

    with ExitStack() as cleanup:
        context = call(430, 'proc', 1)
        cleanup.callback(os.close, context)
        call(431, context, 6, 0, 0, 0)
        root = call(432, context, 1, 0)
        cleanup.callback(os.close, root)
        def mount_id(fd, path=''):
            value = ctypes.create_string_buffer(256)
            call(291, fd, path, 0x100 if path else 0x1000, 0x17ff, ctypes.addressof(value))
            assert struct.unpack_from('I', value)[0] & 0x1000
            return struct.unpack_from('Q', value, 144)[0]
        identity = mount_id(root)
        # NO_XDEV | NO_MAGICLINKS | BENEATH: directories are not magic links.
        how = OpenHow(os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC, 0, 0xb)
        for path in ['thread-self/fd/', 'self/fd', 'thread-self/fdinfo/', 'self/ns/']:
            fd = call(437, root, path, ctypes.addressof(how), ctypes.sizeof(how))
            assert mount_id(fd) == identity, path
            if '/fd' in path and '/fdinfo' not in path:
                assert mount_id(fd, str(root)) == identity, 'magic link lost its mount'
                link = os.open(str(root), os.O_PATH | os.O_NOFOLLOW, dir_fd=fd)
                assert mount_id(link) == identity
                os.close(link)
                dumpable = libc.prctl(3, 0, 0, 0, 0)
                assert dumpable >= 0
                try:
                    assert libc.prctl(4, 0, 0, 0, 0) == 0
                    assert mount_id(fd, str(root)) == identity, 'protected proc link lost its mount'
                    assert os.stat(str(root), dir_fd=fd, follow_symlinks=False).st_mode & 0o170000 == 0o120000
                    link = os.open(str(root), os.O_PATH | os.O_NOFOLLOW, dir_fd=fd)
                    assert mount_id(link) == identity, 'protected O_PATH link lost its mount'
                    os.close(link)
                    leaf_how = OpenHow(os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, 0, 0xb)
                    link = call(437, fd, str(root), ctypes.addressof(leaf_how), ctypes.sizeof(leaf_how))
                    assert mount_id(link) == identity, 'protected openat2 link lost its mount'
                    os.close(link)
                    reopened = os.open('/proc/self/fd/' + str(fd), os.O_RDONLY | os.O_DIRECTORY)
                    assert mount_id(reopened) == identity, 'protected reopen lost its mount'
                    assert str(root) in os.listdir(reopened)
                    os.close(reopened)
                    assert libc.prctl(3, 0, 0, 0, 0) == 0, 'metadata changed dumpability'
                finally:
                    assert libc.prctl(4, dumpable, 0, 0, 0) == 0
            os.close(fd)
        for path in ['thread-self/fd/0', 'thread-self/root/', 'thread-self/cwd/',
                     'thread-self/ns/mnt']:
            call(437, root, path, ctypes.addressof(how), ctypes.sizeof(how), error=errno.ELOOP)
        call(437, root, '../', ctypes.addressof(how), ctypes.sizeof(how), error=errno.EXDEV)
        how.resolve |= 4  # NO_SYMLINKS rejects even the ordinary self symlink.
        call(437, root, 'thread-self/fd/', ctypes.addressof(how), ctypes.sizeof(how), error=errno.ELOOP)
    print('PASS detached proc: scoped directories and rejected magic-link/parent escapes', flush=True)


def guest():
    detached_proc()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long

    def call(nr, *args, error=0):
        values = [ctypes.c_char_p(a.encode()) if isinstance(a, str) else ctypes.c_long(a) for a in args]
        value = libc.syscall(ctypes.c_long(nr), *values)
        actual = ctypes.get_errno() if value < 0 else 0
        assert actual == error, (nr, args, value, actual, error)
        return value

    def denied(fn, error):
        try:
            fn()
        except OSError as failure:
            assert failure.errno == error, failure
        else:
            raise AssertionError(('accepted forbidden operation', error))

    def child(fn):
        pid = os.fork()
        if not pid:
            try:
                fn()
                os._exit(0)
            except BaseException:
                traceback.print_exc()
                os._exit(1)
        assert os.waitpid(pid, 0)[1] == 0

    def user():
        os.setgroups([])
        os.setgid(1000)
        os.setuid(1000)

    def noatime():
        for path in ('/proc/self', '/proc/self/stat', '/proc/self/status',
                     '/proc/self/uid_map', '/proc/self/cgroup'):
            fd = os.open(path, os.O_RDONLY | os.O_NOATIME)
            try:
                assert fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_NOATIME, path
                reopened = os.open('/proc/self/fd/' + str(fd), os.O_RDONLY | os.O_NOATIME)
                os.close(reopened)
                fcntl.fcntl(fd, fcntl.F_SETFL, 0)
                assert not fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_NOATIME
                fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NOATIME)
                assert fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_NOATIME
                if path == '/proc/self':
                    relative = os.open('stat', os.O_RDONLY | os.O_NOATIME, dir_fd=fd)
                    assert os.read(relative, 4096)
                    os.close(relative)
                else:
                    assert os.read(fd, 4096)
            finally:
                os.close(fd)

    noatime()

    call(97, 0x20000)  # Own mount namespace; no host proc changes.
    with tempfile.TemporaryDirectory(prefix='md-proc-policy-') as tmp, ExitStack() as cleanup:
        root = Path(tmp)
        root.chmod(0o755)
        mounts = {}
        for key, options in [('off', 'hidepid=off'), ('one', 'hidepid=1'),
                             ('two', 'hidepid=invisible'), ('four', 'hidepid=ptraceable'),
                             ('group', 'hidepid=2,gid=1000'), ('strict', 'hidepid=4,gid=1000'),
                             ('subset', 'subset=pid')]:
            path = root / key
            path.mkdir()
            cleanup.callback(path.rmdir)
            call(40, 'none', str(path), 'proc', 0, options)
            cleanup.callback(call, 39, str(path), 2)
            mounts[key] = path
        invalid = root / 'invalid'
        invalid.mkdir()
        cleanup.callback(invalid.rmdir)
        for options in ['hidepid=3', 'hidepid=-1', 'gid=-1', 'gid=4294967295', 'subset=bad', 'unknown=1']:
            call(40, 'none', str(invalid), 'proc', 0, options, error=errno.EINVAL)
        context = call(430, 'proc', 1)
        call(431, context, 1, 'hidepid', '2', 0)
        call(431, context, 1, 'subset', 'pid', 0)
        call(431, context, 6, 0, 0, 0)
        detached = call(432, context, 1, 0)
        os.close(context)
        call(429, detached, '', -100, str(invalid), 4)
        cleanup.callback(call, 39, str(invalid), 2)
        os.close(detached)
        mounts['api'] = invalid
        parent = str(os.getpid())
        held = os.open(mounts['two'] / parent, os.O_RDONLY | os.O_DIRECTORY)
        inherited = os.open(mounts['off'] / parent / 'stat', os.O_RDONLY)

        def restricted():
            user()
            noatime()
            for suffix in ('', '/stat', '/status', '/uid_map', '/cgroup'):
                path = str(mounts['off'] / parent) + suffix
                denied(lambda: os.open(path, os.O_RDONLY | os.O_NOATIME), errno.EPERM)
            denied(lambda: fcntl.fcntl(inherited, fcntl.F_SETFL, os.O_NOATIME), errno.EPERM)
            assert not fcntl.fcntl(inherited, fcntl.F_GETFL) & os.O_NOATIME
            for key in ['off', 'one', 'two', 'four', 'group', 'strict', 'api']:
                path = mounts[key]
                names = os.listdir(path)
                assert str(os.getpid()) in names, (key, names)
                assert (path / 'self/status').read_text()
                hidden = key in ['two', 'four', 'strict', 'api']
                assert (parent in names) != hidden, (key, names, parent)
                target = path / parent
                if hidden:
                    denied(lambda: os.stat(target), errno.ENOENT)
                    denied(lambda: (target / 'status').read_text(), errno.ENOENT)
                elif key == 'one':
                    os.stat(target)
                    denied(lambda: (target / 'status').read_text(), errno.EPERM)
                else:
                    assert (target / 'status').read_text()
            denied(lambda: os.listdir(held), errno.ENOENT)
            denied(lambda: os.open('status', os.O_RDONLY, dir_fd=held), errno.ENOENT)

        child(restricted)
        os.close(held)
        os.close(inherited)
        def group_access():
            os.setgroups([1000])
            os.setgid(1001)
            os.setuid(1001)
            assert (mounts['group'] / parent / 'status').read_text()
            denied(lambda: os.stat(mounts['strict'] / parent), errno.ENOENT)
        child(group_access)
        def default_group():
            os.setgroups([])
            os.setuid(1001)
            assert (mounts['two'] / parent / 'status').read_text()
            denied(lambda: os.stat(mounts['four'] / parent), errno.ENOENT)
        child(default_group)
        call(40, 0, str(mounts['two']), 0, 32, 'hidepid=off', error=errno.EOPNOTSUPP)
        subset = mounts['subset']
        assert set(os.listdir(subset)) <= {'self', 'thread-self'} | {x for x in os.listdir(subset) if x.isdigit()}
        for name in ['sys', 'meminfo', 'uptime', 'net', 'cgroups']:
            denied(lambda: os.stat(subset / name), errno.ENOENT)
        assert (subset / 'self/status').read_text()
        table = Path('/proc/self/mountinfo').read_text()
        assert 'hidepid=2' in table and 'subset=pid' in table and 'gid=1000' in table

        left, right = socket.socketpair()
        target = os.fork()
        if not target:
            left.close()
            user()
            right.send(b'R')
            # EVENT_WAIT: the parent's commands delimit credential and
            # dumpability observations; socket timeout fails this fixture.
            right.settimeout(15)
            assert right.recv(1) == b'D'
            call(167, 4, 0)  # PR_SET_DUMPABLE
            right.send(b'D')
            assert right.recv(1) == b'Q'
            os._exit(0)
        right.close()
        left.settimeout(15)
        assert left.recv(1) == b'R'

        def peer(hidden=False):
            user()
            path = mounts['four'] / str(target)
            if hidden:
                denied(lambda: os.stat(path), errno.ENOENT)
            else:
                assert (path / 'status').read_text()

        child(peer)
        def filesystem_identity():
            os.setgroups([])
            os.setgid(1000)
            os.setresuid(1000, 1000, 1001)
            assert call(151, 1001) == 1000
            denied(lambda: os.stat(mounts['four'] / str(target)), errno.ENOENT)
        child(filesystem_identity)
        left.send(b'D')
        assert left.recv(1) == b'D'
        child(lambda: peer(True))
        left.send(b'Q')
        # EVENT_WAIT: retain the child's zombie for peer proc observation;
        # the outer launch deadline bounds missing exit notification.
        os.waitid(os.P_PID, target, os.WEXITED | os.WNOWAIT)
        child(peer)
        assert os.waitpid(target, 0)[1] == 0
        left.close()

        alias = root / 'alias'
        alias.mkdir()
        cleanup.callback(alias.rmdir)
        call(40, str(mounts['two']), str(alias), 0, 4096, 0)
        cleanup.callback(call, 39, str(alias), 2)
        def copied():
            call(97, 0x20000)
            user()
            denied(lambda: os.stat(alias / parent), errno.ENOENT)
        child(copied)
    print('PASS proc: O_NOATIME ownership/reopen/fcntl, hidepid modes/gid, retained FD, credentials/dumpability, subset, fsconfig, bind and namespace copy', flush=True)


def main():
    parser = argparse.ArgumentParser()
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
        suite.command(prefix + ['--bind-ro', suite.base, target, '--deadline-seconds', '90', '--',
                               '/usr/bin/unshare', '--user', '--map-users=0:0:65536',
                               '--map-groups=0:0:65536', '--mount', '--pid', '--fork',
                               '/usr/bin/python3', target + '/test.py', '--guest'], timeout=110)
        suite.report['passed'] = True
    finally:
        try:
            suite.command(prefix + ['--', '/bin/rmdir', target])
        finally:
            suite.finish()


if __name__ == '__main__':
    if sys.argv[1:] == ['--guest']:
        guest()
    elif sys.argv[1:] == ['--guest-detached']:
        detached_proc()
    else:
        main()

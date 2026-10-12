#!/usr/bin/env python3
"""Mounted proc policies through real shell, with unmodified guest syscalls."""
import argparse
import ctypes
from contextlib import ExitStack
import errno
import os
from pathlib import Path
import socket
import sys
import tempfile
import traceback


def guest():
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

        def restricted():
            user()
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
    print('PASS proc: hidepid modes/gid, retained FD, credentials/dumpability, subset, fsconfig, bind and namespace copy', flush=True)


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
    else:
        main()

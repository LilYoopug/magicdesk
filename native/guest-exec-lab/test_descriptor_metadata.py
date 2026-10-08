#!/usr/bin/env python3
"""Anonymous descriptor ownership and lifetime under the real shell executor."""
import argparse
import array
import ctypes
import errno
import os
from pathlib import Path
import select
import socket
import stat
import subprocess
import sys


def guest():
    def metadata(fd):
        value = os.fstat(fd)
        assert stat.S_ISFIFO(value.st_mode), value
        return value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)

    def fails(code, action):
        try:
            action()
        except OSError as error:
            assert error.errno == code, error
        else:
            raise AssertionError('operation unexpectedly succeeded')

    r, w = os.pipe2(os.O_CLOEXEC)
    assert metadata(r) == (0, 0, 0o600)
    os.fchown(w, 1234, 2345)
    os.fchmod(r, 0o620)
    alias = '/proc/self/fd/' + str(w)
    value = os.stat(alias)
    assert (value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)) == (1234, 2345, 0o620)
    os.chown(alias, 1234, 2345)
    os.chmod(alias, 0o620)
    reopened = os.open(alias, os.O_WRONLY | os.O_CLOEXEC)
    assert metadata(reopened) == metadata(r)
    os.fchmod(reopened, 0o640)
    assert metadata(w) == (1234, 2345, 0o640)
    os.fchmod(reopened, 0o620)
    os.close(reopened)
    path = os.open(alias, os.O_PATH | os.O_CLOEXEC)
    assert metadata(path) == metadata(r)
    fails(errno.EBADF, lambda: os.fchmod(path, 0o777))
    os.close(path)
    duplicate = os.dup(w)
    assert metadata(duplicate) == metadata(r) == (1234, 2345, 0o620)
    child = os.fork()
    if not child:
        try:
            os.fchown(duplicate, 42, 42)
            os._exit(0)
        except BaseException:
            os._exit(1)
    assert os.waitpid(child, 0)[1] == 0
    assert metadata(r) == (42, 42, 0o620)
    subprocess.run([sys.executable, '-c',
                    'import os; s=os.fstat(' + str(duplicate) + '); assert (s.st_uid,s.st_gid)==(42,42)'],
                   pass_fds=(duplicate,), check=True, timeout=15)
    sender, receiver = socket.socketpair()
    sender.sendmsg([b'p'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [r, w]))])
    _, ancillary, _, _ = receiver.recvmsg(1, socket.CMSG_SPACE(8))
    received = array.array('i')
    received.frombytes(ancillary[0][2])
    assert len(received) == 2
    os.fchown(received[0], 51, 52)
    assert metadata(received[1]) == metadata(r) == (51, 52, 0o620)
    for fd in received:
        os.close(fd)
    sender.close()
    receiver.close()
    child = os.fork()
    if not child:
        try:
            os.setgroups([])
            os.setgid(99)
            os.setuid(99)
            fails(errno.EPERM, lambda: os.fchown(w, 99, 99))
            fails(errno.EPERM, lambda: os.fchmod(w, 0o777))
            fails(errno.EACCES, lambda: os.open(alias, os.O_WRONLY | os.O_NONBLOCK))
            cr, cw = os.pipe()
            assert metadata(cr) == (99, 99, 0o600)
            os.close(cr)
            os.close(cw)
            os._exit(0)
        except BaseException:
            os._exit(2)
    assert os.waitpid(child, 0)[1] == 0
    os.fchmod(w, 0)
    os.write(w, b'kernel-data')
    assert os.read(r, 11) == b'kernel-data'
    os.close(w)
    os.close(duplicate)
    # EVENT_WAIT: last-writer HUP; a retained data endpoint is a lifetime failure.
    poll = select.poll()
    poll.register(r, select.POLLHUP)
    assert poll.poll(3000), 'metadata owner retained a writer'
    assert os.read(r, 1) == b''
    os.close(r)
    libc = ctypes.CDLL(None, use_errno=True)
    count = len(os.listdir('/proc/self/fd'))
    assert libc.pipe2(ctypes.c_void_p(1), os.O_CLOEXEC) == -1
    assert ctypes.get_errno() == errno.EFAULT
    assert len(os.listdir('/proc/self/fd')) == count
    for _ in range(64):
        r, w = os.pipe()
        assert metadata(r) == (0, 0, 0o600)
        os.close(r)
        os.close(w)
    assert len(os.listdir('/proc/self/fd')) == count
    print('PASS anonymous ownership, dup/fork/exec/SCM_RIGHTS, permissions, EOF and failed publication', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    args = parser.parse_args()
    from test_oci_services import Server, Suite
    suite = Suite(args.build, args.build)
    target = '/tmp/md-descriptor-' + suite.report['id']
    prefix = [suite.runner, '--store', args.store, '--user', '0:0', '--deadline-seconds', '60']
    try:
        suite.transport.upload(suite.client, Path(__file__), suite.base + '/fixture.py')
        suite.command(prefix + ['--', '/bin/mkdir', target])
        run = prefix + ['--bind-ro', suite.base, target, '--']
        for namespace in ([], ['/usr/bin/unshare', '--user', '--map-users=0:0:65536',
                              '--map-groups=0:0:65536', '--mount']):
            suite.command(run + namespace + ['/usr/bin/python3', target + '/fixture.py', '--guest'])
        endpoint = target + '.sock'
        server = Server(suite, run + ['/usr/bin/python3', target + '/fixture.py', '--server', endpoint])
        try:
            server.ready('READY anonymous descriptor sender')
            suite.command(run + ['/usr/bin/python3', target + '/fixture.py', '--client', endpoint])
            server.completed()
        finally:
            server.close()
        suite.report['passed'] = True
    finally:
        try:
            suite.command(prefix + ['--', '/bin/rmdir', target])
        finally:
            suite.finish()


def transfer(role, path):
    if role == '--server':
        listener = socket.socket(socket.AF_UNIX)
        listener.settimeout(20)
        listener.bind(path)
        listener.listen(1)
        r, w = os.pipe()
        os.fchown(w, 123, 124)
        os.fchmod(w, 0o640)
        print('READY anonymous descriptor sender', flush=True)
        peer, _ = listener.accept()
        peer.settimeout(20)
        peer.sendmsg([b'p'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [r, w]))])
        assert peer.recv(1) == b'c'
        value = os.fstat(r)
        assert (value.st_uid, value.st_gid) == (125, 126)
        os.close(r)
        os.close(w)
        peer.close()
        listener.close()
        os.unlink(path)
    else:
        peer = socket.socket(socket.AF_UNIX)
        peer.settimeout(20)
        peer.connect(path)
        _, control, flags, _ = peer.recvmsg(1, socket.CMSG_SPACE(8))
        assert not flags & socket.MSG_CTRUNC
        fds = array.array('i')
        fds.frombytes(control[0][2])
        assert len(fds) == 2
        r, w = fds
        value = os.fstat(r)
        assert (value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)) == (123, 124, 0o640)
        os.fchown(w, 125, 126)
        peer.sendall(b'c')
        # EVENT_WAIT: sender closes its connection; socket timeout fails the test.
        assert peer.recv(1) == b''
        peer.close()
        os.close(w)
        poll = select.poll()
        poll.register(r, select.POLLHUP)
        assert poll.poll(3000), 'portable metadata retained a writer'
        assert os.read(r, 1) == b''
        value = os.fstat(r)
        assert (value.st_uid, value.st_gid) == (125, 126)
        os.close(r)
        print('PASS independent launches: live anonymous metadata and final writer release', flush=True)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] in ('--server', '--client'):
        transfer(sys.argv[1], sys.argv[2])
    else:
        guest() if '--guest' in sys.argv else main()

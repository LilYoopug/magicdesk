#!/usr/bin/env python3
"""Namespace-owned IPv4 policy files through ordinary proc IO, under shell."""
import argparse
from contextlib import ExitStack
import ctypes
import errno
import os
import socket
import struct
import subprocess
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
    os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    with ExitStack() as sockets:
        def netlink(protocol=0):
            return sockets.enter_context(socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, protocol))
        first, second, duplicate = netlink(), netlink(), netlink()
        first.bind((0, 0))
        second.bind((0, 0))
        a, b = first.getsockname()[0], second.getsockname()[0]
        assert a and b and a != b, (a, b)
        denied(lambda: duplicate.bind((a, 0)), errno.EADDRINUSE)
        independent = netlink(16)
        independent.bind((a, 0))
        first.close()
        duplicate.bind((a, 0))
        assert duplicate.getsockname()[0] == a
    print('PASS protocol-scoped netlink ports, collision, autobind and reuse', flush=True)
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0) as sender, \
            socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0) as monitor:
        sender.bind((12345, 1))
        monitor.bind((12346, 1))
        sender.settimeout(5)
        monitor.settimeout(5)
        monitor.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        for sequence in (1, 2):
            request = struct.pack('=IHHII', 32, 18, 0x301, sequence, 0) + bytes(16)
            # A subscribed socket may reuse its multicast address for the
            # initial RTM_GETLINK dump. This also multicasts the user request.
            if sequence == 1:
                assert sender.sendto(request, (0, 1)) == len(request)
            else:
                assert sender.sendmsg([request[:16], request[16:]], [], 0, (0, 1)) == len(request)
            data, ancillary, flags, source = monitor.recvmsg(4096, socket.CMSG_SPACE(12))
            assert data == request and source == (12345, 1) and not flags, (data, source, flags)
            credentials = next(value for level, kind, value in ancillary
                               if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS)
            assert struct.unpack('=iii', credentials) == (os.getpid(), os.getuid(), os.getgid())
            complete = False
            while not complete:
                data, source = sender.recvfrom(65536)
                assert source == (0, 0), source
                offset = 0
                while offset < len(data):
                    size, kind, _, seq, _ = struct.unpack_from('=IHHII', data, offset)
                    assert size >= 16 and seq == sequence and kind in (3, 16)
                    complete |= kind == 3
                    offset += (size + 3) & ~3
        child = os.fork()
        if not child:
            os.setuid(1234)
            denied(lambda: sender.sendto(request, (0, 1)), errno.EPERM)
            os._exit(0)
        assert os.waitpid(child, 0) == (child, 0)
        child = os.fork()
        if not child:
            assert sender.sendto(request, (0, 1)) == len(request)
            os._exit(0)
        assert os.waitpid(child, 0) == (child, 0)
        data, ancillary, flags, source = monitor.recvmsg(4096, socket.CMSG_SPACE(12))
        credentials = next(value for level, kind, value in ancillary
                           if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS)
        assert data == request and source == (12345, 1) and not flags
        assert struct.unpack('=iii', credentials) == (child, os.getuid(), os.getgid()), credentials
        assert sender.sendto(request, (0, 1)) == len(request)
        child = os.fork()
        if not child:
            libc = ctypes.CDLL(None, use_errno=True)
            assert libc.unshare(0x10000000 | 0x20000000) == 0, ctypes.get_errno()
            Path('/proc/self/uid_map').write_text('1234 0 1\n')
            Path('/proc/self/setgroups').write_text('deny\n')
            Path('/proc/self/gid_map').write_text('1234 0 1\n')
            receiver = os.fork()
            if not receiver:
                data, ancillary, flags, source = monitor.recvmsg(4096, socket.CMSG_SPACE(12))
                credentials = next(value for level, kind, value in ancillary
                                   if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS)
                assert data == request and source == (12345, 1) and not flags
                assert struct.unpack('=iii', credentials) == (0, 1234, 1234), credentials
                os._exit(0)
            assert os.waitpid(receiver, 0) == (receiver, 0)
            os._exit(0)
        assert os.waitpid(child, 0) == (child, 0)
    print('PASS netlink subscribed dumps, multicast source, credentials and sender authority', flush=True)
    def descriptors():
        result = {}
        for name in os.listdir('/proc/self/fd'):
            try:
                result[name] = os.readlink('/proc/self/fd/' + name)
            except FileNotFoundError:
                pass
        return result

    port, ping, local = 'ip_unprivileged_port_start', 'ping_group_range', 'ip_local_port_range'
    bridge = Path(BASE).parent / 'bridge/bridge-nf-call-iptables'
    assert bridge.read_text() == '1\n'
    bridge.write_text('1')
    denied(lambda: bridge.write_text('0'), errno.EOPNOTSUPP)
    denied(lambda: bridge.write_text('2'), errno.EINVAL)
    assert bridge.read_text() == '1\n'
    def link(*args):
        subprocess.run(['ip', 'link', *args], check=True, timeout=10)

    assert read('conf/lo/route_localnet') == ['0']
    write('conf/default/route_localnet', '1')
    link('add', 'md-route', 'type', 'bridge')
    assert read('conf/md-route/route_localnet') == ['1']
    write('conf/md-route/rp_filter', '2')
    assert read('conf/md-route/rp_filter') == ['2']
    write('conf/md-route/arp_notify', '1')
    assert read('conf/md-route/arp_notify') == ['1']
    denied(lambda: write('conf/md-route/arp_notify', '2'), errno.EINVAL)
    denied(lambda: write('conf/md-route/rp_filter', '3'), errno.EINVAL)
    write('conf/md-route/route_localnet', '0')
    assert read('conf/default/route_localnet') == ['1']
    fd = os.open(BASE + 'conf/md-route/route_localnet', os.O_RDWR)
    previous = os.fstat(fd)
    link('set', 'md-route', 'name', 'md-renamed')
    assert os.pread(fd, 32, 0) == b'0\n'
    assert Path(BASE + 'conf/md-renamed/route_localnet').stat().st_ino == previous.st_ino
    denied(lambda: read('conf/md-route/route_localnet'), errno.ENOENT)
    link('del', 'md-renamed')
    link('add', 'md-route', 'type', 'bridge')
    denied(lambda: os.pread(fd, 32, 0), errno.ENODEV)
    denied(lambda: os.pwrite(fd, b'1', 0), errno.ENODEV)
    assert read('conf/md-route/route_localnet') == ['1']
    assert Path(BASE + 'conf/md-route/route_localnet').stat().st_ino != previous.st_ino
    os.close(fd)
    link('del', 'md-route')
    write('conf/default/route_localnet', '0')
    print('PASS per-interface sysctl identity across rename, delete and name reuse', flush=True)
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
        assert read('conf/default/route_localnet') == ['0']
        write(port, '42')
        assert read(port) == ['42'] and os.pread(fd, 32, 0) == b'10000\n'
        os.setgid(1234)
        os.setuid(1234)
        denied(lambda: write(port, '0'), errno.EACCES)
        denied(lambda: write('ip_forward', '1'), errno.EACCES)
        denied(lambda: write('conf/lo/route_localnet', '1'), errno.EACCES)
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
    with ExitStack() as cleanup:
        directory = cleanup.enter_context(tempfile.TemporaryDirectory(prefix='md-net-proc-'))
        assert libc.mount(b'proc', os.fsencode(directory), b'proc', 2 | 4 | 8, None) == 0, ctypes.get_errno()
        def detach():
            result = libc.umount2(os.fsencode(directory), 2)
            assert result == 0 or ctypes.get_errno() == errno.EINVAL, ctypes.get_errno()
        cleanup.callback(detach)
        conf = Path(directory + '/sys/net/ipv4/conf')
        entries = sorted(p.name for p in conf.iterdir())
        assert entries == ['all', 'default', 'lo'], entries
        link('add', '12345', 'type', 'bridge')
        try:
            assert sorted(p.name for p in conf.iterdir()) == ['12345', 'all', 'default', 'lo']
            assert (conf / '12345/rp_filter').read_text() == '0\n'
        finally:
            link('del', '12345')
        assert sorted(p.name for p in conf.iterdir()) == ['all', 'default', 'lo']
        link('add', 'md-view', 'type', 'bridge')
        assert sorted(p.name for p in conf.iterdir()) == ['all', 'default', 'lo', 'md-view']
        assert sorted(p.name for p in (conf / 'md-view').iterdir()) == ['arp_notify', 'route_localnet', 'rp_filter']
        scoped = os.open(conf / 'md-view/route_localnet', os.O_RDWR)
        assert os.pwrite(scoped, b'1', 0) == 1
        assert read('conf/md-view/route_localnet') == ['1']
        assert os.fstat(scoped).st_ino == Path(BASE + 'conf/md-view/route_localnet').stat().st_ino
        target = directory + '/sys/net/ipv4/' + port
        fd = os.open(target, os.O_RDWR)
        try:
            assert os.pread(fd, 32, 0) == b'30\n'
            assert libc.mount(None, os.fsencode(directory), None, 32 | 1 | 2 | 4 | 8, None) == 0, ctypes.get_errno()
            denied(lambda: os.open(target, os.O_WRONLY), errno.EROFS)
            denied(lambda: os.pwrite(fd, b'4', 0), errno.EROFS)
            denied(lambda: os.pwrite(scoped, b'0', 0), errno.EROFS)
            assert os.pread(fd, 32, 0) == b'30\n'
            assert libc.umount2(os.fsencode(directory), 2) == 0, ctypes.get_errno()
            denied(lambda: os.pwrite(fd, b'4', 0), errno.EROFS)
        finally:
            os.close(fd)
            os.close(scoped)
            link('del', 'md-view')
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
                                '/usr/bin/unshare', '--net', '--mount', '--pid', '--fork',
                                '/usr/bin/python3', target + '/test.py', '--guest'],
                      timeout=80)
        suite.report['passed'] = True
    finally:
        try:
            suite.command(prefix + ['--', '/bin/rmdir', target])
        finally:
            suite.finish()


if __name__ == '__main__':
    guest() if sys.argv[1:] == ['--guest'] else main()

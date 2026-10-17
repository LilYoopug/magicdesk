#!/usr/bin/env python3
"""Namespace-owned sysfs through both mount APIs and retained descriptors."""
import argparse
from contextlib import ExitStack
import ctypes
import errno
import fcntl
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile


def guest():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long

    def call(nr, *args, error=None):
        converted = [ctypes.c_char_p(str(arg).encode()) if isinstance(arg, (str, Path))
                     else ctypes.c_long(arg) for arg in args]
        result = libc.syscall(ctypes.c_long(nr), *converted)
        code = ctypes.get_errno() if result < 0 else 0
        assert code == (error or 0), (nr, args, result, code, error)
        return result

    def denied(action, expected):
        try:
            action()
            raise AssertionError('unexpected success')
        except OSError as error:
            assert error.errno == expected, error

    def link_up():
        with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0) as route:
            body = struct.pack('BxHiII', 0, 0, 1, 1, 1)
            route.sendto(struct.pack('IHHII', 16 + len(body), 16, 5, 1, 0) + body, (0, 0))
            reply = route.recv(4096)
            assert struct.unpack_from('i', reply, 16)[0] == 0, reply

    def mounted(context, path):
        call(431, context, 6, 0, 0, 0)
        fd = call(432, context, 1, 1)
        os.close(context)
        call(429, fd, '', -100, path, 4)
        os.close(fd)

    with tempfile.TemporaryDirectory(prefix='md-sysfs-') as directory, ExitStack() as cleanup:
        cpu_possible = os.environ['MD_TEST_CPU_POSSIBLE']
        root = Path(directory)
        a, b, alias = [root / name for name in ('a', 'b', 'alias')]
        for path in (a, b, alias):
            path.mkdir()
            cleanup.callback(libc.syscall, ctypes.c_long(39), ctypes.c_char_p(str(path).encode()), ctypes.c_long(2))
        cleanup.callback(libc.syscall, ctypes.c_long(39), ctypes.c_char_p(str(b / 'fs/cgroup').encode()), ctypes.c_long(2))
        # Inherited host networking is not silently replaced with offline data.
        context = call(430, 'sysfs', 1)
        call(431, context, 6, 0, 0, 0, error=errno.EOPNOTSUPP)
        os.close(context)
        call(97, 0x40000000)  # NEWNET, retaining initial logical user authority.
        first = os.open('/proc/self/ns/net', os.O_RDONLY)
        call(40, 'sysfs', a, 'sysfs', 15, 0)
        for name in ('block', 'bus', 'dev/block', 'dev/char'):
            assert (a / name).is_dir() and os.listdir(a / name) == [], name
        assert set(os.listdir(a / 'devices/system')) <= {'cpu', 'node'}
        cpu = a / 'devices/system/cpu/possible'
        assert cpu.read_text() == cpu_possible
        assert not (a / 'devices/system/cpux').exists()
        assert not (a / 'devices/platform').exists()
        assert not (a / 'class/thermal').exists()
        cpu_fd = os.open(cpu, os.O_RDONLY)
        cpu_duplicate = os.dup(cpu_fd)
        assert os.read(cpu_fd, 1) + os.read(cpu_duplicate, 4096) == cpu_possible.encode()
        assert os.pread(cpu_fd, 4096, 0) == cpu_possible.encode()
        os.close(cpu_duplicate)
        denied(lambda: cpu.write_text('0'), errno.EROFS)
        net = a / 'class/net'
        lo = net / 'lo'
        assert sorted(os.listdir(net)) == ['lo']
        assert os.readlink(lo) == '../../devices/virtual/net/lo'
        assert lo.resolve() == a / 'devices/virtual/net/lo'
        assert (lo / 'subsystem').resolve() == net
        for name, expected in [('ifindex', '1\n'), ('iflink', '1\n'), ('mtu', '65536\n'),
                               ('type', '772\n'), ('address', '00:00:00:00:00:00\n'),
                               ('broadcast', '00:00:00:00:00:00\n'), ('flags', '0x8\n'),
                               ('operstate', 'down\n')]:
            assert (lo / name).read_text() == expected, name
        denied(lambda: (lo / 'carrier').read_text(), errno.EINVAL)
        denied(lambda: (net / 'wlan0/ifindex').read_text(), errno.ENOENT)
        st = (lo / 'mtu').stat()
        assert st.st_size == 4096 and st.st_mode & 0o777 == 0o444 and st.st_uid == 0
        fsstat = (ctypes.c_long * 32)()
        call(43, a, ctypes.addressof(fsstat))
        assert fsstat[0] == 0x62656572
        entry = next(line for line in Path('/proc/self/mountinfo').read_text().splitlines()
                     if line.split()[4] == str(a))
        assert ' - sysfs ' in entry and 'ro' in entry.split()[5].split(','), entry
        denied(lambda: (lo / 'mtu').write_text('1500'), errno.EROFS)
        print('PASS sysfs layout, metadata, links, statfs, mountinfo and readonly policy', flush=True)

        fd = os.open(lo / 'mtu', os.O_RDONLY)
        assert os.read(fd, 2) == b'65'
        duplicate = os.dup(fd)
        assert os.read(duplicate, 10) == b'536\n'
        assert os.pread(fd, 6, 0) == b'65536\n'
        assert os.read(fd, 1) == b''
        with open('/proc/self/fd/' + str(fd), 'rb') as reopened:
            assert reopened.read() == b'65536\n'
        assert os.fstat(fd).st_ino == st.st_ino
        os.close(duplicate)
        pathfd = os.open(lo / 'mtu', os.O_PATH)
        assert os.fstat(pathfd).st_ino == st.st_ino
        denied(lambda: os.read(pathfd, 1), errno.EBADF)
        os.close(pathfd)
        print('PASS sysfs shared offsets, positional IO and proc FD reopening', flush=True)

        context = call(430, 'sysfs', 1)
        retained = os.open(lo / 'flags', os.O_RDONLY)
        link_up()
        assert os.pread(retained, 64, 0) == b'0x9\n'
        assert (lo / 'operstate').read_text() == 'unknown\n'
        assert (lo / 'carrier').read_text() == '1\n'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
            request = struct.pack('16s24s', b'lo', b'')
            flags = struct.unpack_from('H', fcntl.ioctl(control, 0x8913, request), 16)[0]
            assert flags & 0x49 == 0x49
        call(97, 0x40000000)
        second = os.open('/proc/self/ns/net', os.O_RDONLY)
        mounted(context, b)
        assert (b / 'class/net/lo/flags').read_text() == '0x9\n'
        call(39, b, 2)
        call(40, 'sysfs', b, 'sysfs', 15, 0)
        assert (b / 'class/net/lo/flags').read_text() == '0x8\n'
        assert os.pread(retained, 64, 0) == b'0x9\n'
        call(268, first, 0x40000000)
        call(40, a, alias, 0, 4096, 0)
        bound = root / 'bound-flags'
        bound.touch()
        cleanup.callback(libc.syscall, ctypes.c_long(39), ctypes.c_char_p(str(bound).encode()), ctypes.c_long(2))
        call(40, lo / 'flags', bound, 0, 4096, 0)
        call(39, a, 2)
        assert os.pread(cpu_fd, 4096, 0) == cpu_possible.encode()
        with open('/proc/self/fd/' + str(cpu_fd)) as reopened_cpu:
            assert reopened_cpu.read() == cpu_possible
        os.close(cpu_fd)
        assert (alias / 'class/net/lo/flags').read_text() == '0x9\n'
        assert os.pread(fd, 6, 0) == b'65536\n'
        call(39, alias, 2)
        assert bound.read_text() == '0x9\n'
        call(39, bound, 2)
        assert os.pread(retained, 64, 0) == b'0x9\n'
        os.close(first)
        os.close(fd)
        os.close(retained)
        print('PASS sysfs live netlink state, fsopen capture, setns, bind and detached descriptors', flush=True)

        call(268, second, 0x40000000)
        os.close(second)
        call(40, 'cgroup2', b / 'fs/cgroup', 'cgroup2', 14, 0)
        assert (b / 'fs/cgroup/cgroup.controllers').is_file()
        denied(lambda: os.truncate(b / 'fs/cgroup/cgroup.procs', 0), errno.EOPNOTSUPP)
        call(39, b / 'fs/cgroup', 2)
        call(39, b, 2)
        call(40, 'sysfs', b, 'sysfs', 14, 0)
        assert (b / 'devices/system/cpu/possible').read_text() == cpu_possible
        denied(lambda: (b / 'devices/system/cpu/online').write_text('0'), errno.EROFS)
        cpu = b / 'devices/system/cpu/possible'
        denied(lambda: os.chmod(cpu, 0o444), errno.EROFS)
        denied(lambda: os.setxattr(cpu, 'user.test', b'value'), errno.EROFS)
        with cpu.open() as opened_cpu:
            denied(lambda: os.fchmod(opened_cpu.fileno(), 0o444), errno.EROFS)
            denied(lambda: os.setxattr(opened_cpu.fileno(), 'user.test', b'value'), errno.EROFS)
        value = b / 'class/net/lo/mtu'
        denied(lambda: value.write_text('1500'), errno.EOPNOTSUPP)
        denied(lambda: os.truncate(value, 0), errno.EOPNOTSUPP)
        denied(lambda: os.chmod(value, 0o777), errno.EOPNOTSUPP)
        denied(lambda: os.setxattr(value, 'user.test', b'value'), errno.EOPNOTSUPP)
        assert value.read_text() == '65536\n'
        # The child owns a new user namespace, not the inherited network view.
        child = os.fork()
        if child == 0:
            try:
                call(97, 0x20000)
                assert (b / 'class/net/lo/flags').read_text() == '0x8\n'
                call(39, b, 2)
                call(97, 0x10000000 | 0x20000)
                Path('/proc/self/uid_map').write_text('0 0 1\n')
                Path('/proc/self/setgroups').write_text('deny\n')
                Path('/proc/self/gid_map').write_text('0 0 1\n')
                call(430, 'sysfs', 1, error=errno.EPERM)
                call(40, 'sysfs', a, 'sysfs', 15, 0, error=errno.EPERM)
                call(97, 0x40000000)
                call(40, 'sysfs', a, 'sysfs', 15, 0)
                assert (a / 'class/net/lo/flags').read_text() == '0x8\n'
                call(39, a, 2)
                os._exit(0)
            except BaseException:
                import traceback
                traceback.print_exc()
                os._exit(1)
        # EVENT_WAIT: namespace child termination; supervised deadline fails a hang.
        assert os.waitpid(child, 0)[1] == 0
        assert (b / 'class/net/lo/flags').read_text() == '0x8\n'
        call(39, b, 2)
        print('PASS cgroup over sysfs and network namespace mount authority', flush=True)

        result = subprocess.run(['strace', '-e', 'trace=fsopen,fsconfig,fsmount,move_mount',
                                 'mount', '-t', 'sysfs', '-o', 'ro', 'sysfs', str(a)],
                                capture_output=True, text=True)
        print(result.stderr, end='', flush=True)
        assert result.returncode == 0 and 'move_mount(' in result.stderr, result
        call(39, a, 2)
        before = len(os.listdir('/proc/self/fd'))
        for _ in range(40):
            context = call(430, 'sysfs', 1)
            call(431, context, 6, 0, 0, 0)
            mount = call(432, context, 1, 1)
            os.close(context)
            os.close(mount)
        assert len(os.listdir('/proc/self/fd')) == before
        print('PASS stock util-linux mount and abandoned sysfs resource retirement', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    args = parser.parse_args()
    from test_oci_services import Suite
    suite = Suite(args.build, args.build)
    target = '/tmp/md-sysfs-' + suite.report['id']
    cpu_possible = suite.command(['cat', '/sys/devices/system/cpu/possible'], quiet=True)
    prefix = [suite.runner, '--store', args.store, '--user', '0:0',
              '--env', 'MD_TEST_CPU_POSSIBLE=' + cpu_possible]
    try:
        suite.transport.upload(suite.client, Path(__file__), suite.base + '/test.py')
        suite.command(prefix + ['--', '/bin/mkdir', target])
        suite.command(prefix + ['--bind-ro', suite.base, target, '--deadline-seconds', '100', '--',
                                '/usr/bin/unshare', '--mount', '/usr/bin/python3', target + '/test.py', '--guest'],
                      timeout=120)
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

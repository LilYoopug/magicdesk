#!/usr/bin/env python3
"""Logical cgroup-device BPF lifecycle in the permissive shell provider."""
import argparse
import array
import ctypes
import errno
import fcntl
import os
from pathlib import Path
import resource
import socket
import struct
import sys
import tempfile

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


def call(number, *args):
    values = [ctypes.c_char_p(str(a).encode()) if isinstance(a, (str, Path))
              else ctypes.c_long(a) for a in args]
    result = libc.syscall(ctypes.c_long(number), *values)
    if result < 0:
        raise OSError(ctypes.get_errno(), str(number))
    return result


def denied(action, code):
    try:
        action()
        raise AssertionError('unexpected success')
    except OSError as error:
        assert error.errno == code, error


def bpf(command, data):
    buffer = ctypes.create_string_buffer(data, len(data))
    result = call(280, command, ctypes.addressof(buffer), len(data))
    return result, buffer.raw


def load(value=1, instructions=None, kind=15):
    code = ctypes.create_string_buffer(instructions or struct.pack('<BBhiBBhi', 0xb7, 0, 0, value, 0x95, 0, 0, 0))
    license = ctypes.create_string_buffer(b'MIT')
    fd, _ = bpf(5, struct.pack('<IIQQIIQII16sII', kind, (len(code)-1)//8,
        ctypes.addressof(code), ctypes.addressof(license), 0, 0, 0, 0, 0, b'md_device', 0, 0))
    assert fcntl.fcntl(fd, fcntl.F_GETFD) == fcntl.FD_CLOEXEC
    return fd


def info(fd, expected_kind=15):
    value = ctypes.create_string_buffer(256)
    _, response = bpf(15, struct.pack('<IIQ', fd, len(value), ctypes.addressof(value)))
    kind, identity = struct.unpack_from('<II', value.raw)
    assert kind == expected_kind and identity and value.raw[64:74] == b'md_device\0'
    assert struct.unpack_from('<I', response, 4)[0] >= 80
    return identity


def by_id(identity):
    return bpf(13, struct.pack('<III', identity, 0, 0))[0]


def attach(target, program, flags=2):
    return bpf(8, struct.pack('<IIIII', target, program, 6, flags, 0))[0]


def detach(target, program):
    return bpf(9, struct.pack('<IIIII', target, program, 6, 0, 0))[0]


def query(target, count=64, flags=0, pointer=None, expected=0):
    values = (ctypes.c_uint32 * count)()
    address = ctypes.addressof(values) if pointer is None else pointer
    buffer = ctypes.create_string_buffer(struct.pack('<IIIIQII', target, 6, flags, 0, address, count, 0))
    try:
        call(280, 16, ctypes.addressof(buffer), 32)
        assert not expected
    except OSError as error:
        if not expected:
            raise
        assert error.errno == expected, (error, expected)
    attached = struct.unpack_from('<I', buffer.raw, 12)[0]
    total = struct.unpack_from('<I', buffer.raw, 24)[0]
    return list(values)[:min(count, total)], total, attached


def guest():
    def descriptors():
        result = {}
        for name in os.listdir('/proc/self/fd'):
            try:
                result[name] = os.readlink('/proc/self/fd/' + name)
            except FileNotFoundError:
                pass
        return result
    # Warm the table-owned SCM transport before measuring application FD
    # cleanup; this one lazy infrastructure socket is retained until exec/exit.
    left, right = socket.socketpair()
    warm = os.open('/dev/null', os.O_RDONLY)
    try:
        left.sendmsg([b'w'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [warm]))])
        _, ancillary, flags, _ = right.recvmsg(1, socket.CMSG_SPACE(4))
        assert not flags and len(ancillary) == 1
        received = array.array('i')
        received.frombytes(ancillary[0][2])
        assert len(received) == 1
        os.close(received[0])
    finally:
        os.close(warm)
        left.close()
        right.close()
    before = descriptors()
    with tempfile.TemporaryDirectory(prefix='md-bpf-') as temp:
        root = Path(temp) / 'groups'
        root.mkdir()
        call(40, 'none', root, 'cgroup2', 0, 0)
        try:
            target = root / 'test'
            target.mkdir()
            directory = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            try:
                assert query(directory) == ([], 0, 0)
                first, second = load(), load(0)
                one, two = info(first), info(second)
                assert one != two
                attach(directory, first)
                denied(lambda: attach(directory, first), errno.EEXIST)
                attach(directory, second)
                assert query(directory) == ([one, two], 2, 2)
                assert query(directory, 1, expected=errno.ENOSPC) == ([one], 2, 2)
                assert query(directory, 0, pointer=0) == ([], 2, 2)
                query(directory, 2, pointer=1, expected=errno.EFAULT)
                assert query(directory)[0] == [one, two]
                # Explicitly permissive: accepting a logical program is not
                # executing its return-zero predicate or granting native IO.
                with open('/dev/null', 'wb') as stream:
                    assert stream.write(b'x') == 1
                print('PASS load, info, attach, query, ENOSPC/EFAULT and permissive policy', flush=True)

                nested = target / 'child'
                nested.mkdir()
                child_dir = os.open(nested, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    assert query(child_dir) == ([], 0, 0)
                    assert query(child_dir, flags=1) == ([one, two], 2, 0)
                    child_program = load()
                    child_id = info(child_program)
                    attach(child_dir, child_program)
                    os.close(child_program)
                    assert query(child_dir, flags=1) == ([child_id, one, two], 3, 0)
                    nested.rmdir()
                    denied(lambda: query(child_dir), errno.ENODEV)
                    denied(lambda: by_id(child_id), errno.ENOENT)
                finally:
                    os.close(child_dir)
                print('PASS inherited queries and group-removal program release', flush=True)

                duplicate = os.dup(first)
                os.close(first)
                assert info(duplicate) == one
                pid = os.fork()
                if not pid:
                    try:
                        call(167, 4, 0, 0, 0, 0)  # PR_SET_DUMPABLE
                        assert info(duplicate) == one and query(directory)[0] == [one, two]
                        fd = by_id(one)
                        assert info(fd) == one
                        os.close(fd)
                        os.set_inheritable(duplicate, True)
                        os.execv(sys.executable, [sys.executable, __file__, '--inspect', str(duplicate), str(one)])
                    except BaseException:
                        import traceback
                        traceback.print_exc()
                        os._exit(1)
                # EVENT_WAIT: exact child exit; the supervised deadline bounds it.
                assert os.waitpid(pid, 0)[1] == 0
                os.close(duplicate)
                first = by_id(one)
                detach(directory, first)
                os.close(first)
                denied(lambda: by_id(one), errno.ENOENT)
                detach(directory, second)
                assert info(second) == two
                os.close(second)
                denied(lambda: by_id(two), errno.ENOENT)
                print('PASS dup/fork/protected exec, last-FD release and attached lifetime', flush=True)

                fd = load()
                identity = info(fd)
                left, right = socket.socketpair()
                try:
                    left.sendmsg([b'p'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
                    os.close(fd)
                    _, ancillary, flags, _ = right.recvmsg(1, socket.CMSG_SPACE(4))
                    assert not flags and len(ancillary) == 1
                    received = array.array('i')
                    received.frombytes(ancillary[0][2])
                    assert len(received) == 1
                    fd = received[0]
                    assert info(fd) == identity
                    denied(lambda: os.read(fd, 1), errno.EINVAL)
                    denied(lambda: os.write(fd, b'x'), errno.EINVAL)
                    denied(lambda: os.lseek(fd, 0, os.SEEK_SET), errno.ESPIPE)
                    assert os.fstat(fd).st_uid == 0
                    call(40, 0, root, 0, 32 | 1, 0)  # MS_REMOUNT|MS_RDONLY
                    try:
                        assert query(directory) == ([], 0, 0)
                        denied(lambda: attach(directory, fd), errno.EROFS)
                    finally:
                        call(40, 0, root, 0, 32, 0)
                    attach(directory, fd)
                    detach(directory, fd)
                    os.close(fd)
                    denied(lambda: by_id(identity), errno.ENOENT)
                finally:
                    left.close()
                    right.close()
                print('PASS SCM_RIGHTS identity, control IO and live readonly policy', flush=True)

                # Full-table failure must discard the unpublished program,
                # not leave a registry entry with no application owner.
                fd = load()
                last = info(fd)
                os.close(fd)
                limits = resource.getrlimit(resource.RLIMIT_NOFILE)
                fillers = []
                resource.setrlimit(resource.RLIMIT_NOFILE, (32, limits[1]))
                try:
                    while True:
                        try:
                            fillers.append(os.open('/dev/null', os.O_RDONLY))
                        except OSError as error:
                            assert error.errno == errno.EMFILE
                            break
                    denied(load, errno.EMFILE)
                finally:
                    for fd in fillers:
                        os.close(fd)
                    resource.setrlimit(resource.RLIMIT_NOFILE, limits)
                denied(lambda: by_id(last + 1), errno.ENOENT)
                fd = load()
                assert info(fd) > last
                os.close(fd)
                # Zero extension and unknown fields follow bpf_attr's ABI,
                # without interpreting unimplemented request extensions.
                raw = struct.pack('<IIIIQII', directory, 6, 0, 0, 0, 0, 0)
                assert bpf(16, raw[:28])[0] == 0
                assert bpf(16, raw + bytes(128))[0] == 0
                denied(lambda: bpf(16, raw + b'\x01'), errno.E2BIG)
                print('PASS failed-publication cleanup and short/extended attribute ABI', flush=True)

                programs = [load() for _ in range(65)]
                identities = [info(fd) for fd in programs]
                paths, directories = [], []
                try:
                    for fd in programs[:64]:
                        attach(directory, fd)
                    denied(lambda: attach(directory, programs[64]), errno.E2BIG)
                    assert query(directory)[0] == identities[:64]
                    path = target
                    for index in range(17):
                        path /= 'child' + str(index)
                        path.mkdir()
                        paths.append(path)
                        child = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
                        directories.append(child)
                        for fd in programs[:64]:
                            attach(child, fd)
                    expected = identities[:64] * 18
                    # 4608 ID bytes exceed the small fs_response inline area.
                    assert query(directories[-1], len(expected), flags=1) == (expected, len(expected), 0)
                    for fd in programs[:64]:
                        detach(directory, fd)
                finally:
                    for child in directories:
                        os.close(child)
                    for path in reversed(paths):
                        path.rmdir()
                    for fd in programs:
                        os.close(fd)
                for identity in identities:
                    denied(lambda: by_id(identity), errno.ENOENT)
                instruction = struct.pack('<BBhi', 0xb7, 0, 0, 1)
                exit_instruction = struct.pack('<BBhi', 0x95, 0, 0, 0)
                fd = load(instructions=instruction * 4095 + exit_instruction)
                os.close(fd)
                denied(lambda: load(instructions=instruction * 4096 + exit_instruction), errno.E2BIG)
                print('PASS attachment quota, large inherited query and instruction bound', flush=True)

                denied(lambda: load(kind=1), errno.EOPNOTSUPP)
                fd = load(kind=8)  # CGROUP_SKB load does not imply a network hook
                identity = info(fd, 8)
                denied(lambda: attach(directory, fd), errno.EINVAL)
                denied(lambda: bpf(8, struct.pack('<IIIII', directory, fd, 0, 0, 0)), errno.EOPNOTSUPP)
                os.close(fd)
                denied(lambda: by_id(identity), errno.ENOENT)
                for command in (0, 18, 0xffffffff):  # maps, BTF, unknown command
                    denied(lambda: bpf(command, bytes(64)), errno.EINVAL)
                denied(lambda: load(instructions=struct.pack('<BBhiBBhi', 0x85, 0, 0, 1, 0x95, 0, 0, 0)), errno.EOPNOTSUPP)
                denied(lambda: load(instructions=struct.pack('<BBhiBBhi', 0x05, 0, 4, 0, 0x95, 0, 0, 0)), errno.EINVAL)
                invalid = os.open('/dev/null', os.O_RDONLY)
                try:
                    denied(lambda: query(invalid), errno.EINVAL)
                    denied(lambda: info(invalid), errno.EINVAL)
                finally:
                    os.close(invalid)
                pid = os.fork()
                if not pid:
                    os.setuid(123)
                    denied(load, errno.EPERM)
                    os._exit(0)
                assert os.waitpid(pid, 0)[1] == 0
                print('PASS unsupported features, invalid programs/targets and guest authority', flush=True)

                ids = set()
                for _ in range(80):
                    fd = load()
                    identity = info(fd)
                    assert identity not in ids
                    ids.add(identity)
                    attach(directory, fd)
                    detach(directory, fd)
                    os.close(fd)
                    denied(lambda: by_id(identity), errno.ENOENT)
                assert query(directory) == ([], 0, 0)
                print('PASS repeated program disposal without stale IDs or attachments', flush=True)
            finally:
                os.close(directory)
            target.rmdir()
        finally:
            call(39, root, 2)
    after = descriptors()
    assert after == before, (before, after)
    print('PASS exact guest FD cleanup', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    args = parser.parse_args()
    from test_oci_services import Suite
    suite = Suite(args.build, args.build)
    target = '/tmp/md-bpf-' + suite.report['id']
    prefix = [suite.runner, '--store', args.store, '--user', '0:0']
    try:
        suite.transport.upload(suite.client, Path(__file__), suite.base + '/test.py')
        suite.command(prefix + ['--', '/bin/mkdir', target])
        suite.command(prefix + ['--bind-ro', suite.base, target, '--deadline-seconds', '90', '--',
                                '/usr/bin/unshare', '--mount', '/usr/bin/python3', target + '/test.py', '--guest'],
                      timeout=110)
        suite.report['passed'] = True
    finally:
        try:
            suite.command(prefix + ['--', '/bin/rmdir', target])
        finally:
            suite.finish()


if __name__ == '__main__':
    if sys.argv[1:] == ['--guest']:
        guest()
    elif sys.argv[1:2] == ['--inspect']:
        assert info(int(sys.argv[2])) == int(sys.argv[3])
        print('PASS program descriptor after protected exec', flush=True)
    else:
        main()

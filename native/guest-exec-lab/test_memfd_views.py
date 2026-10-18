#!/usr/bin/env python3
"""Live read-only anonymous-file aliases, mappings and confined FD transfer."""
import argparse
import array
import ctypes
import errno
import fcntl
import mmap
import os
from pathlib import Path
import socket
import select
import resource
import signal
import sys


def guest():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.restype = ctypes.c_void_p
    page = mmap.PAGESIZE

    def fd_count():
        # F_GETFD is native and counts real slots, not proc's view.
        return sum(libc.syscall(25, number, fcntl.F_GETFD, 0) >= 0
                   for number in range(512))

    def confine():
        class Filter(ctypes.Structure):
            _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                        ('jf', ctypes.c_ubyte), ('value', ctypes.c_uint)]
        class Program(ctypes.Structure):
            _fields_ = [('length', ctypes.c_ushort), ('filter', ctypes.POINTER(Filter))]
        instructions = (Filter * 9)(
            Filter(0x20, 0, 0, 0), Filter(0x15, 5, 0, 277),
            Filter(0x15, 4, 0, 220), Filter(0x15, 3, 0, 435),
            Filter(0x15, 0, 3, 167), Filter(0x20, 0, 0, 16),
            Filter(0x15, 0, 1, 22), Filter(0x06, 0, 0, 0x50000 | errno.EPERM),
            Filter(0x06, 0, 0, 0x7fff0000))
        program = Program(len(instructions), instructions)
        assert libc.prctl(38, 1, 0, 0, 0) == 0
        assert libc.syscall(277, 1, 0, ctypes.byref(program)) == 0
        assert libc.syscall(277, 1, 0, ctypes.byref(program)) == -1
        assert ctypes.get_errno() == errno.EPERM
        assert libc.syscall(220, 0, 0, 0, 0, 0) == -1
        assert ctypes.get_errno() == errno.EPERM

    def denied(operation, expected):
        try:
            operation()
        except OSError as error:
            assert error.errno == expected, (error, expected)
        else:
            raise AssertionError('forbidden operation succeeded')

    def check_mapping(fd, source=None, private_copy=True):
        address = libc.mmap(None, page, mmap.PROT_READ, mmap.MAP_SHARED, fd, 0)
        assert address != ctypes.c_void_p(-1).value, ctypes.get_errno()
        try:
            assert ctypes.string_at(address, 4) == b'live'
            if source is not None:
                assert os.pwrite(source, b'next', 0) == 4
                assert ctypes.string_at(address, 4) == b'next', 'mapping must not be a snapshot'
                assert os.pwrite(source, b'live', 0) == 4
            assert libc.mprotect(ctypes.c_void_p(address), page, mmap.PROT_READ | mmap.PROT_WRITE) == -1
            assert ctypes.get_errno() == errno.EACCES
        finally:
            assert libc.munmap(ctypes.c_void_p(address), page) == 0
        if private_copy:
            with mmap.mmap(fd, page, access=mmap.ACCESS_COPY) as private:
                private[:4] = b'copy'
        assert os.pread(fd, 4, 0) == b'live'

    def shared_table_cancellation(fd):
        before = fd_count()
        for _ in range(12):
            ready, written = os.pipe()
            # Fork-like address space with a retained shared table. Python is
            # single-threaded here; the child neither closes inherited FDs nor
            # returns into application cleanup after the mapping loop.
            pid = libc.syscall(220, 0x400 | signal.SIGCHLD, 0, 0, 0, 0)
            assert pid >= 0, ctypes.get_errno()
            if not pid:
                assert libc.prctl(4, 0, 0, 0, 0) == 0
                confine()
                while True:
                    address = libc.mmap(None, page, mmap.PROT_READ, mmap.MAP_SHARED, fd, 0)
                    if address == ctypes.c_void_p(-1).value:
                        os._exit(2)
                    os.write(written, b'x')
                    if libc.munmap(ctypes.c_void_p(address), page):
                        os._exit(3)
            try:
                assert os.read(ready, 1) == b'x'
                os.kill(pid, signal.SIGKILL)
                assert os.waitpid(pid, 0)[1] == signal.SIGKILL
            finally:
                os.close(ready)
                os.close(written)
            assert fd_count() == before, 'dead mapping caller left an FD in the shared table'

    for protected in (False, True):
        assert libc.prctl(4, int(not protected), 0, 0, 0) == 0
        for flags in (3, 11):  # MFD_CLOEXEC | ALLOW_SEALING, optionally NOEXEC_SEAL.
            try:
                fd = os.memfd_create('md-readonly-view', flags)
            except OSError as error:
                if flags == 11 and error.errno == errno.EINVAL:
                    continue  # Optional Linux 6.3 flag; the baseline uses flags=3.
                raise
            os.ftruncate(fd, page)
            os.write(fd, b'live')
            ro = os.open(f'/proc/self/fd/{fd}', os.O_RDONLY | os.O_CLOEXEC)
            other = os.open(f'/proc/self/fd/{ro}', os.O_RDONLY | os.O_CLOEXEC)
            assert os.lseek(ro, 0, os.SEEK_CUR) == 0
            assert os.read(ro, 4) == b'live'
            assert os.lseek(other, 0, os.SEEK_CUR) == 0
            assert os.fstat(ro).st_ino == os.fstat(fd).st_ino
            assert fcntl.fcntl(ro, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
            poll = select.poll()
            poll.register(ro, select.POLLIN | select.POLLOUT)
            ready = poll.poll(0)
            assert ready == [(ro, select.POLLIN | select.POLLOUT)], ready
            with select.epoll() as epoll:
                denied(lambda: epoll.register(ro, select.EPOLLIN), errno.EPERM)
            assert os.lseek(other, 0, os.SEEK_END) == page
            denied(lambda: os.write(ro, b'x'), errno.EBADF)
            denied(lambda: os.pwrite(ro, b'x', 0), errno.EBADF)
            denied(lambda: fcntl.fcntl(ro, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SHRINK), errno.EPERM)
            check_mapping(ro, fd)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | 16)
            assert fcntl.fcntl(ro, fcntl.F_GET_SEALS) & 6 == 6
            limits = resource.getrlimit(resource.RLIMIT_NOFILE)
            resource.setrlimit(resource.RLIMIT_NOFILE, (80, limits[1]))
            copies = []
            try:
                while True:
                    try:
                        copies.append(os.dup(fd))
                    except OSError as error:
                        assert error.errno == errno.EMFILE
                        break
                check_mapping(ro, private_copy=False)
            finally:
                for duplicate in copies:
                    os.close(duplicate)
                resource.setrlimit(resource.RLIMIT_NOFILE, limits)
            if not protected and flags == 3:
                shared_table_cancellation(ro)
            parent, child = socket.socketpair()
            pid = os.fork()
            if not pid:
                try:
                    parent.close()
                    os.close(fd)
                    os.close(ro)
                    os.close(other)
                    assert libc.prctl(4, 0, 0, 0, 0) == 0
                    confine()
                    _, anc, _, _ = child.recvmsg(1, socket.CMSG_SPACE(4))
                    received = array.array('i', anc[0][2])[0]
                    assert fcntl.fcntl(received, fcntl.F_GET_SEALS) & 6 == 6
                    check_mapping(received)
                    before = fd_count()
                    for _ in range(24):
                        check_mapping(received)
                        bad = libc.mmap(ctypes.c_void_p(1), page, mmap.PROT_READ,
                                        mmap.MAP_SHARED | 0x10, received, 0)
                        assert bad == ctypes.c_void_p(-1).value
                        assert ctypes.get_errno() == errno.EINVAL
                    assert fd_count() == before, 'temporary mapping FD leaked'
                    os.close(received)
                    os._exit(0)
                except BaseException:
                    import traceback
                    traceback.print_exc()
                    os._exit(1)
            child.close()
            parent.sendmsg([b'x'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [ro]))])
            parent.close()
            os.close(fd)
            os.close(ro)
            os.close(other)
            assert os.waitpid(pid, 0)[1] == 0
    print('PASS live readonly memfd: seals, independent offsets, shared/COW mappings, fork and SCM_RIGHTS', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--store', required=True)
    parser.add_argument('--libc-registry')
    args = parser.parse_args()
    from test_oci_services import Suite
    suite = Suite(Path('build/memfd-view-results'), args.build)
    target = '/tmp/md-memfd-' + suite.report['id']
    prefix = [suite.runner, '--store', args.store, '--user', '0:0']
    if args.libc_registry:
        prefix += ['--libc-registry', args.libc_registry]
    try:
        suite.transport.upload(suite.client, Path(__file__), suite.base + '/test.py')
        suite.command(prefix + ['--', '/bin/mkdir', target])
        suite.command(prefix + ['--bind-ro', suite.base, target, '--deadline-seconds', '90', '--',
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

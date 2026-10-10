#!/usr/bin/env python3
"""Descriptor dispatch follows the current object, not stacked filter order."""
import ctypes
import errno
import fcntl
import os
import struct
import sys
import tempfile
import traceback

libc = ctypes.CDLL(None, use_errno=True)


def checked(result):
    if result < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return result


def proc(slot=None):
    fd = os.open('/proc/self/stat', os.O_RDONLY | os.O_CLOEXEC)
    try:
        assert slot is None or fd == slot, (fd, slot)
        expected = str(os.getpid()).encode() + b' ('
        data = os.read(fd, 4096)
        assert data.startswith(expected), (fd, data)
        assert os.lseek(fd, 0, os.SEEK_SET) == 0
        buffers = [bytearray(8), bytearray(4096)]
        length = os.readv(fd, buffers)
        assert b''.join(buffers)[:length].startswith(expected)
        assert os.pread(fd, 4096, 0).startswith(expected)
        try:
            fcntl.ioctl(fd, 0x5401, bytearray(64))  # TCGETS requires a terminal.
        except OSError as error:
            assert error.errno == errno.ENOTTY, error
        else:
            raise AssertionError('proc carrier exposed through ioctl')
    finally:
        os.close(fd)
    return fd


def watch(slot=None):
    fd = checked(libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC))
    try:
        assert slot is None or fd == slot, (fd, slot)
        with tempfile.TemporaryDirectory() as directory:
            wd = checked(libc.inotify_add_watch(fd, os.fsencode(directory), 0x100))
            created = os.open(directory + '/created', os.O_WRONLY | os.O_CREAT, 0o600)
            os.close(created)
            # EVENT_WAIT: kernel/provider event publication, bounded by poll.
            import select
            poll = select.poll()
            poll.register(fd, select.POLLIN)
            assert poll.poll(2000), 'inotify creation event missing'
            available = bytearray(4)
            fcntl.ioctl(fd, 0x541B, available)  # FIONREAD on the actual watch queue.
            assert struct.unpack('i', available)[0] >= 16
            data = os.read(fd, 4096)
            found, mask, _, _ = struct.unpack_from('iIII', data)
            assert found == wd and mask & 0x100, data
            assert b'created\0' in data, data
    finally:
        os.close(fd)
    return fd


def ordinary(slot):
    read, write = os.pipe()
    try:
        assert read == slot, (read, slot)
        assert os.write(write, b'native') == 6
        assert os.read(read, 6) == b'native'
    finally:
        os.close(read)
        os.close(write)


def child(call):
    pid = os.fork()
    if pid == 0:
        try:
            call()
        except BaseException:
            traceback.print_exc()
            os._exit(1)
        os._exit(0)
    assert os.waitpid(pid, 0)[1] == 0


def ordered(first, second):
    slot = first()
    second(slot)
    for _ in range(3):
        proc(slot)
        watch(slot)
        ordinary(slot)
    child(lambda: proc(slot))
    child(lambda: os.execv(sys.executable, [sys.executable, __file__, '--inherited', str(slot)]))
    print('PASS descriptor selector order:', first.__name__, second.__name__, flush=True)


if __name__ == '__main__':
    if sys.argv[1:2] == ['--inherited']:
        proc(int(sys.argv[2]))
        watch(int(sys.argv[2]))
        ordinary(int(sys.argv[2]))
    else:
        child(lambda: ordered(proc, watch))
        child(lambda: ordered(watch, proc))

#!/usr/bin/env python3
"""Exercise a stock read-only FUSE filesystem, including concurrent readers."""
from concurrent.futures import ThreadPoolExecutor
import errno
import ctypes
import mmap
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

work = Path(tempfile.mkdtemp(prefix='md-fuse-squashfs-'))
source, mount = work / 'source', work / 'mount'
blocked = work / 'noexec'
source.mkdir()
mount.mkdir()
blocked.mkdir()
content = bytes(range(256)) * 1024
(source / 'file').write_bytes(content)
(source / 'link').symlink_to('file')
(source / 'directory').mkdir()
(source / 'directory' / 'small').write_text('nested\n')
shutil.copy2('/usr/bin/true', source / 'program')
shutil.copy2('/usr/lib/libm.so.6', source / 'library.so')
(source / 'script').write_text('#!/bin/sh\nprintf "fuse-script-ok\\n"\n')
(source / 'script').chmod(0o755)
subprocess.run(['mksquashfs', str(source), str(work / 'image'), '-noappend',
                '-processors', '1', '-no-progress'], check=True)
log = open(work / 'daemon.log', 'w+')
daemon = subprocess.Popen(['squashfuse_ll', '-f', '-d', '-o', 'ro', str(work / 'image'), str(mount)],
                          stdout=log, stderr=log)
try:
    deadline = time.monotonic() + 15
    while str(mount) not in Path('/proc/self/mountinfo').read_text():
        assert daemon.poll() is None, 'daemon exited before mounting'
        assert time.monotonic() < deadline, 'FUSE mount not observed'
        # Bounded mount-state observation, never a readiness settling delay.
        time.sleep(0.02)
    assert mount.stat().st_dev != source.stat().st_dev
    assert sorted(p.name for p in mount.iterdir()) == ['directory', 'file', 'library.so', 'link', 'program', 'script']
    assert (mount / 'directory' / 'small').read_text() == 'nested\n'
    assert os.readlink(mount / 'link') == 'file'
    print('FUSE exec source', (mount / 'program').stat(), flush=True)
    print('FUSE exec mount', next(line for line in Path('/proc/self/mountinfo').read_text().splitlines()
          if line.split()[4] == str(mount)), flush=True)
    subprocess.run([str(mount / 'program')], check=True)
    assert subprocess.check_output([str(mount / 'script')]) == b'fuse-script-ok\n'
    library = ctypes.CDLL(str(mount / 'library.so'))
    library.cos.argtypes = [ctypes.c_double]
    library.cos.restype = ctypes.c_double
    assert library.cos(0.0) == 1.0
    with open(mount / 'file', 'rb') as stream:
        with mmap.mmap(stream.fileno(), len(content), flags=mmap.MAP_PRIVATE,
                       prot=mmap.PROT_READ | mmap.PROT_WRITE) as mapped:
            assert mapped[:] == content
            mapped[0] = 73
            assert (mount / 'file').read_bytes() == content
        with mmap.mmap(stream.fileno(), mmap.PAGESIZE, flags=mmap.MAP_PRIVATE,
                       prot=mmap.PROT_READ, offset=mmap.PAGESIZE) as mapped:
            assert mapped[:] == content[mmap.PAGESIZE:2*mmap.PAGESIZE]
        try:
            mmap.mmap(stream.fileno(), mmap.PAGESIZE, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ)
        except OSError as error:
            assert error.errno == errno.EOPNOTSUPP, error
        else:
            raise AssertionError('unimplemented shared mapping was accepted')
    subprocess.run(['mount', '--bind', str(mount), str(blocked)], check=True)
    subprocess.run(['mount', '-o', 'remount,bind,ro,noexec', str(blocked)], check=True)
    with open(blocked / 'file', 'rb') as stream:
        try:
            mmap.mmap(stream.fileno(), mmap.PAGESIZE, flags=mmap.MAP_PRIVATE,
                      prot=mmap.PROT_READ | mmap.PROT_EXEC)
        except OSError as error:
            assert error.errno == errno.EPERM, error
        else:
            raise AssertionError('noexec mapping was accepted')
        with mmap.mmap(stream.fileno(), mmap.PAGESIZE, flags=mmap.MAP_PRIVATE,
                       prot=mmap.PROT_READ | mmap.PROT_WRITE) as mapped:
            address = ctypes.addressof(ctypes.c_char.from_buffer(mapped))
            libc = ctypes.CDLL(None, use_errno=True)
            libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            assert libc.mprotect(address, mmap.PAGESIZE, mmap.PROT_READ | mmap.PROT_EXEC) == -1
            assert ctypes.get_errno() in (errno.EPERM, errno.EACCES)
    subprocess.run(['umount', str(blocked)], check=True)
    print('FUSE private mappings, dynamic library and noexec checks passed', flush=True)
    def read(index):
        path = mount / ('link' if index % 2 else 'file')
        with open(path, 'rb') as stream:
            assert stream.seek(0, os.SEEK_END) == len(content)
            stream.seek(0)
            assert stream.read() == content
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(read, range(16)))
    for path in (mount / 'file', mount / 'new'):
        try:
            with open(path, 'wb'):
                pass
        except OSError as error:
            assert error.errno == errno.EROFS, error
        else:
            raise AssertionError('read-only mount allowed writing')
    with open(mount / 'file', 'rb') as retained:
        subprocess.run(['umount', '-l', str(mount)], check=True)
        assert retained.read() == content
        assert not (mount / 'file').exists()
    daemon.wait(timeout=10)
    print('PASS squashfuse: reads, ELF/script execution, private mappings, shared library, noexec and concurrent IO', flush=True)
finally:
    subprocess.run(['umount', '-l', str(blocked)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['umount', '-l', str(mount)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if daemon.poll() is None:
        daemon.terminate()
        try:
            daemon.wait(timeout=10)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait(timeout=10)
    log.flush()
    log.seek(0)
    print(log.read(), flush=True)
    log.close()
    shutil.rmtree(work)

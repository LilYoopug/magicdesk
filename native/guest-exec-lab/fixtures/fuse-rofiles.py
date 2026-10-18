#!/usr/bin/env python3
"""Exercise stock libfuse through the guest syscall and descriptor adapters."""
import os
import errno
import ctypes
import fcntl
import concurrent.futures
from pathlib import Path
import shutil
import signal
import select
import struct
import subprocess
import tempfile
import time


def watch_events(watch):
    events = []
    while True:
        try:
            packet = os.read(watch, 65536)
        except BlockingIOError:
            return events
        at = 0
        while at < len(packet):
            descriptor, mask, cookie, length = struct.unpack_from('iIII', packet, at)
            name = packet[at + 16:at + 16 + length].rstrip(b'\0')
            events.append((descriptor, mask, cookie, name))
            at += 16 + length


def append_and_watches(mount, source):
    def append(worker):
        fd = os.open(mount / 'append', os.O_WRONLY | os.O_APPEND)
        try:
            for index in range(40):
                record = f'{worker:02}:{index:04}\n'.encode()
                assert os.write(fd, record) == len(record)
            assert os.lseek(fd, 0, os.SEEK_CUR) > 0
        finally:
            os.close(fd)

    (mount / 'append').write_bytes(b'')
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(append, range(4)))
    assert sorted((source / 'append').read_bytes().splitlines()) == sorted(
        f'{worker:02}:{index:04}'.encode() for worker in range(4) for index in range(40))
    fd = os.open(mount / 'append', os.O_RDWR)
    try:
        end = os.fstat(fd).st_size
        fcntl.fcntl(fd, fcntl.F_SETFL, os.O_APPEND)
        assert os.write(fd, b'tail') == 4
        assert os.lseek(fd, 0, os.SEEK_CUR) == end + 4
        assert os.pwrite(fd, b'positional', 0) == 10
        assert os.lseek(fd, 0, os.SEEK_CUR) == end + 4
        fcntl.fcntl(fd, fcntl.F_SETFL, 0)
        assert os.pwrite(fd, b'HEAD', 0) == 4
        assert (source / 'append').read_bytes().endswith(b'tailpositional')
        assert (source / 'append').read_bytes().startswith(b'HEAD')
    finally:
        os.close(fd)
    (mount / 'append').unlink()

    libc = ctypes.CDLL(None, use_errno=True)
    libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    watch = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    assert watch >= 0, ctypes.get_errno()
    try:
        wd = libc.inotify_add_watch(watch, os.fsencode(mount), 0xfff)
        assert wd > 0, ctypes.get_errno()
        os.close(os.open(mount, os.O_PATH | os.O_DIRECTORY))
        assert not watch_events(watch), 'O_PATH is not an open/close data event'
        list(mount.iterdir())
        events = watch_events(watch)
        assert any(d == wd and m & 0x1 and m & 0x40000000 and not n
                   for d, m, c, n in events), events
        fd = os.open(mount / 'watched', os.O_CREAT | os.O_RDWR, 0o600)
        os.write(fd, b'first')
        os.rename(mount / 'watched', mount / 'moved')
        os.write(fd, b'second')
        os.chmod(mount / 'moved', 0o640)
        os.close(fd)
        (mount / 'moved').unlink()
        poller = select.poll()
        poller.register(watch, select.POLLIN)
        # EVENT_WAIT: the watch queue must become readable; timeout is failure.
        assert poller.poll(5000), 'FUSE inotify queue was not signalled'
        events = watch_events(watch)
        def contains(mask, name):
            return any(d == wd and m & mask and n == name for d, m, c, n in events)
        assert contains(0x100, b'watched') and contains(0x20, b'watched'), events
        assert contains(0x2, b'moved') and contains(0x4, b'moved'), events
        assert contains(0x8, b'moved') and contains(0x200, b'moved'), events
        before = [c for d, m, c, n in events if m & 0x40 and n == b'watched']
        after = [c for d, m, c, n in events if m & 0x80 and n == b'moved']
        assert before == after and len(before) == 1 and before[0], events
        assert libc.inotify_rm_watch(watch, wd) == 0
        watch_events(watch)
        # A one-shot subscription is retired only by a matching event.
        wd = libc.inotify_add_watch(watch, os.fsencode(mount), 0x80000000 | 0x100)
        assert wd > 0
        (mount / 'one-shot').write_bytes(b'once')
        events = watch_events(watch)
        assert [m for d, m, c, n in events if d == wd] == [0x100, 0x8000], events
        (mount / 'one-shot').unlink()
        assert not watch_events(watch)
        # Parent EXCL_UNLINK must not retire the still-open inode watch.
        wd = libc.inotify_add_watch(watch, os.fsencode(mount), 0x04000000 | 0xfff)
        assert wd > 0
        fd = os.open(mount / 'retained', os.O_CREAT | os.O_RDWR, 0o600)
        child = libc.inotify_add_watch(watch, os.fsencode(mount / 'retained'), 0xfff)
        assert child > 0
        assert libc.inotify_add_watch(watch, os.fsencode(mount / 'retained'), 0x10000000 | 0x2) == -1
        assert ctypes.get_errno() == errno.EEXIST
        watch_events(watch)
        (mount / 'retained').unlink()
        events = watch_events(watch)
        assert not any(d == child and m & (0x400 | 0x8000) for d, m, c, n in events), events
        assert os.write(fd, b'unlinked') == 8
        os.close(fd)
        # Final file release is asynchronous; wait on its actual watch event.
        deadline = time.monotonic() + 5
        while not any(d == child and m & 0x8000 for d, m, c, n in events):
            assert time.monotonic() < deadline, events
            assert poller.poll(max(1, int((deadline - time.monotonic()) * 1000))), events
            events.extend(watch_events(watch))
        assert any(d == child and m & 0x2 for d, m, c, n in events), events
        assert any(d == child and m & 0x8 for d, m, c, n in events), events
        assert any(d == child and m & 0x400 for d, m, c, n in events), events
        assert not any(d == wd and m & (0x2 | 0x8) for d, m, c, n in events), events
        assert libc.inotify_rm_watch(watch, wd) == 0
        watch_events(watch)
        # O_PATH does not emit open/close but still retains the watched inode.
        (mount / 'path-only').write_bytes(b'path')
        fd = os.open(mount / 'path-only', os.O_PATH)
        child = libc.inotify_add_watch(watch, os.fsencode(mount / 'path-only'), 0xfff)
        assert child > 0
        (mount / 'path-only').unlink()
        events = watch_events(watch)
        assert not any(m & (0x400 | 0x8000) for d, m, c, n in events), events
        os.close(fd)
        deadline = time.monotonic() + 5
        while not any(d == child and m & 0x8000 for d, m, c, n in events):
            assert time.monotonic() < deadline, events
            assert poller.poll(max(1, int((deadline - time.monotonic()) * 1000))), events
            events.extend(watch_events(watch))
        assert any(m & 0x400 for d, m, c, n in events), events
        assert not any(m & (0x8 | 0x10 | 0x20) for d, m, c, n in events), events
    finally:
        os.close(watch)
    print('PASS FUSE concurrent append, F_SETFL, positional IO and live inotify rename events', flush=True)


def mount_ready(daemon, mount):
    deadline = time.monotonic() + 15
    while str(mount) not in Path('/proc/self/mountinfo').read_text():
        assert daemon.poll() is None, 'daemon exited before mounting'
        assert time.monotonic() < deadline, 'FUSE mount not observed'
        # Bounded mount-state observation, never a readiness settling delay.
        time.sleep(0.02)


def stopped_request(daemon, mount, source, crash=False, cwd=False):
    print('FUSE stopped-daemon case', 'crash' if crash else 'resume', flush=True)
    previous = os.open('.', os.O_PATH | os.O_DIRECTORY) if cwd else -1
    directory = os.open(mount, os.O_PATH | os.O_DIRECTORY) if cwd else -1
    daemon.send_signal(signal.SIGSTOP)
    # EVENT_WAIT: wait for the actual stopped child, not a scheduling delay.
    pid, status = os.waitpid(daemon.pid, os.WUNTRACED)
    assert pid == daemon.pid and os.WIFSTOPPED(status)
    print('FUSE daemon stop observed', flush=True)
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    pending = pool.submit(os.fchdir, directory) if cwd else pool.submit((mount / 'file').stat)
    try:
        (source / 'independent').write_bytes(b'worker-remains-available')
        assert (source / 'independent').read_bytes() == b'worker-remains-available'
        (source / 'independent').unlink()
        try:
            # EVENT_WAIT: stopped daemon must not finish the request, even past
            # the RPC handshake deadline; expiry here proves it is still pending.
            pending.result(timeout=6)
            raise AssertionError('stopped daemon unexpectedly answered')
        except concurrent.futures.TimeoutError:
            pass
        if cwd:
            os.dup2(previous, directory)
        if crash:
            daemon.kill()
            daemon.wait(timeout=10)
            try:
                pending.result(timeout=10)
                raise AssertionError('dead daemon unexpectedly answered')
            except OSError as error:
                # Linux fs/fuse/dev.c end_requests() completes queued requests
                # with ECONNABORTED when the last daemon descriptor closes.
                assert error.errno == errno.ECONNABORTED, error
        else:
            daemon.send_signal(signal.SIGCONT)
            result = pending.result(timeout=10)
            if cwd:
                assert result is None and Path.cwd() == mount
            else:
                assert result.st_size > 0
    finally:
        if daemon.poll() is None:
            daemon.send_signal(signal.SIGCONT)
        if not pending.done():
            daemon.kill()
            daemon.wait(timeout=10)
        pool.shutdown(wait=True)
        if cwd:
            os.fchdir(previous)
            os.close(previous)
            os.close(directory)

work = Path(tempfile.mkdtemp(prefix='md-fuse-rofiles-'))
source = work / 'source'
mount = work / 'mount'
bound = work / 'bound'
source.mkdir()
mount.mkdir()
bound.mkdir()
(source / 'file').write_bytes(b'original')
(source / 'link').symlink_to('file')
log = open(work / 'daemon.log', 'w+')
daemon = subprocess.Popen(['rofiles-fuse', '-f', '-d', '-o', 'default_permissions', str(source), str(mount)],
                          stdout=log, stderr=log)
try:
    mount_ready(daemon, mount)
    assert (mount / 'file').read_bytes() == b'original'
    device = mount.stat().st_dev
    assert device != source.stat().st_dev
    assert (mount / 'file').stat().st_dev == device
    with open(mount / 'file', 'rb') as opened:
        assert os.fstat(opened.fileno()).st_dev == device
    entry = next(line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()
                 if line.split()[4] == str(mount))
    assert entry[2] == f'{os.major(device)}:{os.minor(device)}'
    assert (mount / 'link').read_bytes() == b'original'
    assert sorted(p.name for p in mount.iterdir()) == ['file', 'link']
    previous = os.open('.', os.O_PATH | os.O_DIRECTORY)
    try:
        os.chdir(mount)
        assert Path('file').read_bytes() == b'original'
    finally:
        os.fchdir(previous)
        os.close(previous)
    (mount / 'file').write_bytes(b'changed')
    assert (source / 'file').read_bytes() == b'changed'
    with open(mount / 'file', 'r+b', buffering=0) as opened:
        opened.seek(2)
        os.ftruncate(opened.fileno(), 4)
        assert opened.tell() == 2
        os.fsync(opened.fileno())
        os.fdatasync(opened.fileno())
        assert (source / 'file').read_bytes() == b'chan'
    (mount / 'file').write_bytes(b'changed')
    os.setxattr(mount / 'file', 'user.shroot-test', b'xattr-value')
    assert os.getxattr(mount / 'file', 'user.shroot-test') == b'xattr-value'
    assert 'user.shroot-test' in os.listxattr(mount / 'file')
    assert os.getxattr(source / 'file', 'user.shroot-test') == b'xattr-value'
    os.removexattr(mount / 'file', 'user.shroot-test')
    with open(mount / 'file', 'rb') as retained:
        assert retained.seek(0, os.SEEK_END) == len(b'changed')
        (source / 'file').write_bytes(b'externally-changed')
        assert retained.seek(0, os.SEEK_END) == len(b'externally-changed')
        retained.seek(0)
        assert retained.read() == b'externally-changed'
    (mount / 'new').write_bytes(b'created')
    (mount / 'new').rename(mount / 'renamed')
    assert (source / 'renamed').read_bytes() == b'created'
    os.link(mount / 'renamed', mount / 'alias')
    # libfuse's high-level API substitutes path-based st_ino unless its
    # filesystem enables fuse_config.use_ino. Check the actual backing link.
    assert (source / 'alias').stat().st_ino == (source / 'renamed').stat().st_ino
    assert (mount / 'alias').stat().st_nlink == 2
    (mount / 'renamed').unlink()
    assert (mount / 'alias').read_bytes() == b'created'
    assert (mount / 'alias').stat().st_nlink == 1
    (mount / 'alias').unlink()
    (mount / 'directory').mkdir()
    (mount / 'directory' / 'nested').write_bytes(b'bind-source')
    subprocess.run(['mount', '--bind', str(mount / 'directory'), str(bound)], check=True)
    assert (bound / 'nested').read_bytes() == b'bind-source'
    assert (bound / 'nested').stat().st_dev == device
    (bound / 'nested').write_bytes(b'bind-updated')
    assert (source / 'directory' / 'nested').read_bytes() == b'bind-updated'
    fd = os.open(bound, os.O_PATH | os.O_DIRECTORY)
    try:
        subprocess.run(['mount', '-o', 'remount,bind,ro,nosuid,nodev,noexec', str(bound)], check=True)
        required = os.ST_RDONLY | os.ST_NOSUID | os.ST_NODEV | os.ST_NOEXEC
        assert os.statvfs(bound).f_flag & required == required
        assert os.fstatvfs(fd).f_flag & required == required
        assert not os.statvfs(mount).f_flag & os.ST_RDONLY
        try:
            (bound / 'nested').write_bytes(b'rejected')
        except OSError as error:
            assert error.errno == errno.EROFS, error
        else:
            raise AssertionError('read-only bind accepted a write')
        assert (source / 'directory' / 'nested').read_bytes() == b'bind-updated'
    finally:
        os.close(fd)
    subprocess.run(['umount', str(bound)], check=True)
    (mount / 'directory' / 'nested').unlink()
    (mount / 'directory').rmdir()
    append_and_watches(mount, source)
    print('FUSE filesystem operations passed', flush=True)
    subprocess.run(['umount', str(mount)], check=True)
    assert daemon.wait(timeout=10) == 0
    # The wait tests require an actual daemon request. A valid attribute lease
    # can legally satisfy stat/fchdir while the daemon is stopped. Keep normal
    # TTLs above, and explicitly request uncached metadata for these cases.
    daemon = subprocess.Popen(['rofiles-fuse', '-f', '-d', '-o',
        'default_permissions,attr_timeout=0,entry_timeout=0', str(source), str(mount)],
        stdout=log, stderr=log)
    mount_ready(daemon, mount)
    stopped_request(daemon, mount, source)
    stopped_request(daemon, mount, source, cwd=True)
    stopped_request(daemon, mount, source, crash=True)
    assert subprocess.run(['umount', str(mount)], check=False).returncode == 0
    daemon.wait(timeout=10)
    print('PASS stock rofiles-fuse: mount, metadata, IO, mutations, bind, suspended and dead daemon', flush=True)
finally:
    subprocess.run(['umount', '-l', str(bound)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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

#!/usr/bin/env python3
"""Exercise stock libfuse through the guest syscall and descriptor adapters."""
import os
import errno
import concurrent.futures
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time


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
    deadline = time.monotonic() + 15
    while str(mount) not in Path('/proc/self/mountinfo').read_text():
        assert daemon.poll() is None, 'daemon exited before mounting'
        assert time.monotonic() < deadline, 'FUSE mount not observed'
        # Bounded mount-state observation, never a readiness settling delay.
        time.sleep(0.02)
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
    subprocess.run(['umount', str(bound)], check=True)
    (mount / 'directory' / 'nested').unlink()
    (mount / 'directory').rmdir()
    print('FUSE filesystem operations passed', flush=True)
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

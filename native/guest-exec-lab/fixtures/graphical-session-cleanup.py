#!/usr/bin/env python3
"""Exercise the production session wrapper against real, session-owned FUSE mounts."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


def mounted(path):
    encoded = str(path).replace('\\', '\\134').replace(' ', '\\040').replace('\t', '\\011').replace('\n', '\\012')
    return any(line.split()[1] == encoded for line in Path('/proc/self/mounts').read_text().splitlines())


def start_fuse(source, target):
    daemon = subprocess.Popen(['rofiles-fuse', '-f', str(source), str(target)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 15
    while not mounted(target):
        assert daemon.poll() is None, 'rofiles-fuse exited before mounting'
        assert time.monotonic() < deadline, 'FUSE mount was not published'
        # Bounded mount-state observation, not a readiness settling delay.
        time.sleep(.02)
    return daemon


def child():
    work = Path(os.environ['MD_SESSION_TEST_WORK'])
    runtime = Path(os.environ['XDG_RUNTIME_DIR'])
    (work / 'runtime').write_text(str(runtime))
    target = runtime / "unrelated ' fuse"
    target.mkdir()
    daemon = start_fuse(work / 'source', target)
    assert (target / 'keep').read_text() == 'must survive cleanup'
    if os.environ['MD_SESSION_TEST_MODE'] == 'dead':
        daemon.kill()
        daemon.wait(timeout=10)
        assert mounted(target), 'dead FUSE mount must remain until explicit unmount'
    # Retain the export until session shutdown. The wrapper must not remove its
    # backing file, even though the exported document permits deletion.
    document = subprocess.check_output(['timeout', '30', 'flatpak', 'document-export',
        '--unique', '--transient', '--app=org.chromium.Chromium', '--allow-read',
        '--allow-write', '--allow-delete', str(work / 'source' / 'keep')], text=True).strip()
    assert Path(document).read_text() == 'must survive cleanup'
    assert mounted(runtime / 'doc')
    print('PASS live document export and unrelated FUSE mount ready', flush=True)
    return 23 if os.environ['MD_SESSION_TEST_MODE'] == 'dead' else 0


def parent():
    for mode in ('live', 'dead'):
        work = Path(tempfile.mkdtemp(prefix='md-session-cleanup-'))
        source, foreign = work / 'source', work / 'foreign'
        source.mkdir()
        foreign.mkdir()
        (source / 'keep').write_text('must survive cleanup')
        daemon = start_fuse(source, foreign)
        try:
            env = dict(os.environ, MD_SESSION_TEST_WORK=str(work), MD_SESSION_TEST_MODE=mode)
            # EVENT_WAIT: command and production cleanup exit; timeout is failure.
            result = subprocess.run(['/bin/sh', '/mnt/session'], env=env,
                                    capture_output=True, text=True, timeout=90)
            print(result.stdout, result.stderr, flush=True)
            assert result.returncode == (23 if mode == 'dead' else 0), result
            assert 'PASS live document export' in result.stdout, result
            assert 'runtime cleanup failed' not in result.stderr, result
            runtime = Path((work / 'runtime').read_text())
            assert not runtime.exists(), runtime
            assert not mounted(runtime / 'doc')
            assert not mounted(runtime / "unrelated ' fuse")
            assert mounted(foreign), 'another session mount was detached'
            assert (foreign / 'keep').read_text() == 'must survive cleanup'
            assert (source / 'keep').read_text() == 'must survive cleanup'
            print('PASS production session cleanup:', mode, 'source intact, foreign mount retained', flush=True)
        finally:
            subprocess.run(['fusermount3', '-u', '-z', str(foreign)], check=True)
            daemon.wait(timeout=10)
            shutil.rmtree(work)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'child':
        sys.exit(child())
    parent()

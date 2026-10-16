#!/usr/bin/env python3
"""Prepared Holo/SteamOS ARM64 userspace under shell, without booting the OS."""
import argparse
from pathlib import Path

from test_oci_services import Suite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    parser.add_argument('--archive', help='Host rootfs tar; import into a new store')
    parser.add_argument('--user', default='steamos')
    parser.add_argument('--socket-owner', action='store_true',
                        help='Also require Python/lsof TCP owner discovery used by Steam UI authentication')
    args = parser.parse_args()
    suite = Suite(args.build, args.build)
    suite.report.update(store=args.store, probe='steamos-userspace', user=args.user,
                        fullOsBoot=False)
    try:
        if args.archive:
            suite.report['archiveSha256'] = suite.command(['sha256sum', args.archive], quiet=True).split()[0]
            suite.command([suite.image, 'rootfs', args.archive, args.store + '-image'], timeout=600)
            suite.command([suite.image, 'create', args.store + '-image', args.store])
        root = [suite.runner, '--store', args.store, '--user', '0:0', '--deadline-seconds', '60', '--']
        user = [suite.runner, '--store', args.store, '--user', args.user, '--deadline-seconds', '60', '--']
        suite.report['distribution'] = suite.command(root + ['/bin/sh', '-ec', '''
cat /etc/os-release
getconf GNU_LIBC_VERSION
pacman --version
getent passwd "$1"
''', 'fixture', args.user])
        checks = (
            ('guest-identity-and-ipc', '''
set -eu
export LC_ALL=C
id
test "$(id -u)" -ne 0
sem= shm= msg=
trap 'test -z "$sem" || ipcrm -s "$sem"; test -z "$shm" || ipcrm -m "$shm"; test -z "$msg" || ipcrm -q "$msg"' EXIT
out=$(ipcmk -S 1); printf '%s\n' "$out"; sem=${out##* }
out=$(ipcmk -M 4096); printf '%s\n' "$out"; shm=${out##* }
out=$(ipcmk -Q); printf '%s\n' "$out"; msg=${out##* }
test -n "$sem" && test -n "$shm" && test -n "$msg"
echo MD_STEAMOS_IPC_OK
'''),
            ('fifo', '''
set -eu
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
mkfifo "$d/pipe"
printf 'shroot-steam-fifo\n' >"$d/pipe" &
writer=$!
read -r value <"$d/pipe"
wait "$writer"
test "$value" = shroot-steam-fifo
echo MD_STEAMOS_FIFO_OK
'''),
            ('private-user-pid-mount', '''
set -eu
unshare --user --map-root-user --pid --fork --mount-proc /bin/sh -ec '
    test "$(id -u)" = 0
    test "$$" = 1
    cat /proc/self/uid_map
    cat /proc/self/status
'
echo MD_STEAMOS_NAMESPACES_OK
'''),
            ('dns-and-https', '''
set -eu
getent ahostsv4 store.steampowered.com
curl --fail --silent --show-error --connect-timeout 10 --max-time 20 --head https://store.steampowered.com/
echo MD_STEAMOS_NETWORK_OK
'''),
        )
        if args.socket_owner:
            checks += (('tcp-owner-discovery', '''
python - <<'PY'
import ctypes
import os
import socket
import subprocess
import sys
import time

# Desktop launchers inherit both proc and inotify selectors. lsof must see
# real process metadata even when its FD number has both filter histories.
with open('/proc/self/stat', 'rb') as stream:
    assert stream.read()
libc = ctypes.CDLL(None, use_errno=True)
watch = libc.inotify_init1(os.O_CLOEXEC)
assert watch >= 0, ctypes.get_errno()
os.close(watch)

def owners(port, expected):
    started = time.monotonic()
    # EVENT_WAIT: stock lsof completion; expiry fails ownership discovery.
    result = subprocess.run(['lsof', '-P', '-F', 'upnR', '-i',
                             'TCP@127.0.0.1:' + str(port)],
                            capture_output=True, text=True, timeout=20)
    print('lsof:', result.returncode, 'seconds:', time.monotonic() - started,
          result.stdout, result.stderr, flush=True)
    assert result.returncode == 0, 'TCP owner not discoverable'
    records = {}
    current = None
    for line in result.stdout.splitlines():
        if line.startswith('p'):
            current = int(line[1:])
            records[current] = {}
        elif current is not None and line[:1] in ('u', 'R'):
            records[current][line[0]] = int(line[1:])
    for pid, parent in expected.items():
        assert pid in records, ('Wrong owner PID', pid, records)
        assert records[pid].get('u') == os.getuid(), ('Wrong owner UID', records)
        assert records[pid].get('R') == parent, ('Wrong owner parent', records)

with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    pid = os.getpid()
    port = listener.getsockname()[1]
    print('Socket owner:', pid, os.getuid(), 'port:', port, flush=True)
    owners(port, {pid: os.getppid()})
    child = subprocess.Popen([sys.executable, '-c',
        'import socket,sys; '
        's=socket.create_connection(("127.0.0.1",int(sys.argv[1])),timeout=5); '
        'sys.stdin.buffer.read(1); s.close()', str(port)], stdin=subprocess.PIPE)
    try:
        listener.settimeout(5)
        # EVENT_WAIT: the child's connection; expiry fails before owner inspection.
        connection, peer = listener.accept()
        with connection:
            owners(peer[1], {pid: os.getppid(), child.pid: pid})
    finally:
        # EVENT_WAIT: pipe EOF releases the child; expiry requires explicit cleanup.
        child.stdin.close()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)
    assert child.returncode == 0, 'Socket peer did not exit cleanly'
PY
'''),)
        for name, script in checks:
            case = {'name': name, 'passed': False}
            suite.report['cases'].append(case)
            suite.command(user + ['/bin/sh', '-ec', script])
            case['passed'] = True
        suite.report['passed'] = True
    finally:
        suite.finish()


if __name__ == '__main__':
    main()

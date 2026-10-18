#!/usr/bin/env python3
"""Stock snapd under systemd, using a disposable Debian-like Shroot store."""
import argparse
from pathlib import Path
import shlex

from init_fixture import PREPARE as INIT_PREPARE
from test_oci_services import Suite


PREPARE = INIT_PREPARE.replace('for device in null zero full random urandom tty;',
                             'for device in null zero full random urandom tty fuse;') + r'''
# Snap needs shared mount propagation before its image mounts exist. systemd
# inside a container leaves this to the launcher; unshare defaults to private.
mount --make-rshared /
mkdir -p /run/systemd/system
mkdir -p /run/systemd/system/snapd.service.d
cat > /run/systemd/system/snapd.service.d/90-test-log.conf <<EOF
[Service]
StandardOutput=append:$1/daemon.log
StandardError=inherit
EOF
cat > /run/systemd/system/md-snap.target <<EOF
[Unit]
DefaultDependencies=no
Requires=md-snap.service
After=md-snap.service
EOF
cat > /run/systemd/system/md-snap.service <<EOF
[Unit]
DefaultDependencies=no
[Service]
Type=simple
ExecStart=/bin/sh $1/driver.sh $1
StandardOutput=append:$1/snap.log
StandardError=inherit
EOF
cat > "$1/driver.sh" <<'EOF'
set -eux
trap 'code=$?; journalctl --no-pager -u snapd.service -n 100 > "$1/journal.log" || :; systemctl exit "$code"' EXIT
systemctl start dbus.socket snapd.socket
systemctl start snapd.service
snap version
snap debug sandbox-features
snap watch '--last=remove?'
snap watch '--last=install?'
snap install hello-world
snap run hello-world
snap refresh hello-world
snap remove --purge hello-world
test ! -e /snap/hello-world/current
if grep -q ' /snap/hello-world/' /proc/self/mountinfo; then exit 1; fi
printf 'PASS snapd install, run, refresh and remove\n' > "$1/result"
EOF
exec /usr/lib/systemd/systemd --system --unit=md-snap.target --show-status=no --crash-shell=no --crash-reboot=no
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--store', required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=Path('build/fuse-results'))
    parser.add_argument('--trace', action='store_true')
    args = parser.parse_args()
    suite = Suite(args.output, args.build)
    suite.report['store'] = args.store
    target = '/opt/md-snap-' + suite.report['id']
    prefix = [suite.runner, '--store', args.store, '--user', '0:0', '--network', 'routed']
    created = False
    try:
        suite.command(prefix + ['--', '/bin/mkdir', target])
        created = True
        prepare = PREPARE
        if args.trace:
            prepare = prepare.replace('snap run hello-world',
                'SNAPD_DEBUG=1 strace -f -s 200 -o "$1/trace.log" '
                '-e trace=openat,readlinkat,fcntl,close,unshare,mount,pivot_root,chroot,execve '
                'snap run hello-world')
        boot = ['/usr/bin/unshare', '--mount', '--pid', '--fork', '--mount-proc',
                '--uts', '--ipc', '--cgroup', '/bin/sh', '-ec', prepare, 'snap-test', target]
        suite.command(prefix + ['--bind', suite.base, target, '--deadline-seconds', '240', '--',
                                '/usr/bin/script', '-q', '-e', '-c', shlex.join(boot), '/dev/null'], timeout=260)
        result = suite.command(['/system/bin/cat', suite.base + '/result'])
        assert 'PASS snapd' in result
        suite.report['passed'] = True
    finally:
        try:
            for name in ('snap.log', 'daemon.log', 'journal.log', 'trace.log', 'result'):
                suite.command(['/system/bin/sh', '-c', 'test ! -f "$1" || tail -100 "$1"',
                               'snap-log', suite.base + '/' + name])
        finally:
            try:
                if created:
                    suite.command(prefix + ['--', '/bin/rmdir', target])
            finally:
                suite.finish()


if __name__ == '__main__':
    main()

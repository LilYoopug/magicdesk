#!/usr/bin/env python3
"""Real systemd poweroff with a service retaining a host bind and private libc."""
import argparse
from pathlib import Path
import re
import shlex

from init_fixture import PREPARE
from test_oci_services import Suite


BOOT = r'''set -eu
mkdir -p /run/udev
mount -t tmpfs tmpfs /run/udev
''' + PREPARE + r'''
export SYSTEMD_LOG_LEVEL=debug
mount --make-rshared /
mkdir -p /mnt/md-shutdown
mount -t tmpfs tmpfs /mnt/md-shutdown
for n in $(seq 1 32); do
    mkdir /mnt/md-shutdown/$n
    mount -t tmpfs tmpfs /mnt/md-shutdown/$n
done
mkdir -p /run/systemd/system
cat > /run/systemd/system/md-shutdown.target <<EOF
[Unit]
DefaultDependencies=no
Requires=md-shutdown.service
After=md-shutdown.service
EOF
cat > /run/systemd/system/md-shutdown.service <<EOF
[Unit]
DefaultDependencies=no
Conflicts=shutdown.target
Before=shutdown.target
[Service]
Type=simple
WorkingDirectory=$1
ExecStart=/bin/sh $1/driver.sh
ExecStopPost=/bin/echo PASS shutdown-service-stopped
StandardOutput=append:$1/service.log
StandardError=inherit
EOF
cat > "$1/driver.sh" <<'EOF'
set -eu
for path in /opt/shroot/libc/*; do
    test -f "$path/manifest" || continue
    unit=$(systemd-escape --path --suffix=mount "$path")
    test "$(systemctl show -p DefaultDependencies --value "$unit")" = no
    systemctl is-active "$unit"
    echo "PASS shutdown-runtime-retained $unit"
done
systemctl poweroff --no-block
exec sleep infinity
EOF
exec /usr/lib/systemd/systemd --system --unit=md-shutdown.target --show-status=no --crash-shell=no --crash-reboot=no
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True, type=Path)
    parser.add_argument('--store', required=True)
    parser.add_argument('--libc-registry')
    parser.add_argument('--output', type=Path, default=Path('build/init-shutdown-results'))
    args = parser.parse_args()
    suite = Suite(args.output, args.build)
    target = '/opt/md-shutdown-' + suite.report['id']
    prefix = [suite.runner, '--store', args.store, '--user', '0:0', '--network', 'routed']
    if args.libc_registry:
        prefix += ['--libc-registry', args.libc_registry]
    try:
        suite.command(prefix + ['--', '/bin/mkdir', target])
        boot = ['/usr/bin/unshare', '--mount', '--pid', '--fork', '--mount-proc',
                '--uts', '--ipc', '--cgroup', '/bin/sh', '-ec', BOOT, 'sh', target]
        command = prefix + ['--bind', suite.base, target,
            '--deadline-seconds', '90', '--', '/usr/bin/script', '-q', '-e', '-c',
            shlex.join(boot), '/dev/null']
        suite.command(['/system/bin/sh', '-c', shlex.join(command) +
                       ' > ' + shlex.quote(suite.base + '/shutdown.log') + ' 2>&1'], timeout=110)
        archive = args.output / (suite.report['id'] + '-shutdown.log')
        suite.transport.download(suite.client, suite.base + '/shutdown.log', archive)
        log = archive.read_text()
        service_archive = args.output / (suite.report['id'] + '-service.log')
        suite.transport.download(suite.client, suite.base + '/service.log', service_archive)
        service_log = service_archive.read_text()
        assert 'PASS shutdown-service-stopped' in service_log, service_log
        mount = 'opt-' + target.removeprefix('/opt/').replace('-', r'\x2d') + '.mount'
        assert mount + ': Deactivated successfully.' in log, log
        assert 'run-udev.mount: Deactivated successfully.' in log, log
        assert "Couldn't remount submount" not in log, log
        assert not re.search(r'\.mount: (?:Failed with result|Mount process exited, code=exited, status=[1-9])', log), log
        if '/system-generators/snapd-generator' in log:
            assert '/system-generators/snapd-generator succeeded.' in log, log
        if args.libc_registry:
            assert 'PASS shutdown-runtime-retained opt-shroot-libc-' in service_log, service_log
            assert not re.search(r'opt-shroot-libc-\w+\.mount: Unmounting', log), log
        assert len(re.findall(r'mnt-md\\x2dshutdown-\d+\.mount: Deactivated successfully\.', log)) == 32, log
        assert 'Exiting container.' in log, log
        suite.report['passed'] = True
    finally:
        try:
            suite.command(prefix + ['--', '/bin/rmdir', target])
        finally:
            suite.finish()


if __name__ == '__main__':
    main()

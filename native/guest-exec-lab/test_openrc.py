#!/usr/bin/env python3
"""Stock OpenRC runlevels and daemon lifecycle in an isolated shell-owned guest.

Requires an Alpine Shroot store with openrc and util-linux installed. Uses a
dedicated runlevel tree, not the distribution's hardware/boot/shutdown services.
"""
import argparse
from pathlib import Path

from test_oci_services import Suite


SCRIPT = r'''set -eux
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
test "$$" = 1
mount -t tmpfs -o mode=755 tmpfs /run
mount -t sysfs sysfs /sys
mount -t cgroup2 none /sys/fs/cgroup
mount -t tmpfs tmpfs /etc/init.d
mount -t tmpfs tmpfs /etc/runlevels
mkdir -p /etc/runlevels/sysinit /etc/runlevels/boot /etc/runlevels/md-test /etc/runlevels/md-empty
cat > /etc/init.d/md-base <<'EOF'
#!/sbin/openrc-run
description="Shroot dependency fixture"
start() {
    echo base-start >> /run/md-order
    touch /run/md-base
}
stop() {
    echo base-stop >> /run/md-order
    rm /run/md-base
}
EOF
cat > /etc/init.d/md-sleeper <<'EOF'
#!/sbin/openrc-run
description="Shroot daemon fixture"
command=/bin/sleep
command_args=600
command_background=yes
pidfile=/run/md-sleeper.pid
depend() { need md-base; }
start_pre() {
    test -f /run/md-base || return 1
    echo daemon-start >> /run/md-order
}
stop_post() { echo daemon-stop >> /run/md-order; }
EOF
chmod 755 /etc/init.d/md-base /etc/init.d/md-sleeper
openrc --version
rc-update add md-sleeper md-test
openrc sysinit
openrc boot
openrc md-test
rc-service md-base status
rc-service md-sleeper status
first=$(cat /run/md-sleeper.pid)
test "$(tr '\000' ' ' < /proc/$first/cmdline)" = '/bin/sleep 600 '
rc-service md-sleeper restart
second=$(cat /run/md-sleeper.pid)
test "$first" != "$second"
test ! -e /proc/$first
test "$(tr '\000' ' ' < /proc/$second/cmdline)" = '/bin/sleep 600 '
rc-service md-sleeper status
openrc md-empty
test ! -e /proc/$second
test ! -e /run/md-base
if rc-service md-sleeper status; then exit 1; fi
if rc-service md-base status; then exit 1; fi
test "$(cat /run/md-order)" = "$(printf 'base-start\ndaemon-start\ndaemon-stop\ndaemon-start\ndaemon-stop\nbase-stop')"
rc-status --all
printf 'PASS OpenRC init, dependencies, daemon restart, runlevel stop and cleanup\n'
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--store', required=True)
    parser.add_argument('--build', type=Path)
    parser.add_argument('--output', type=Path, default=Path('build/openrc-results'))
    args = parser.parse_args()
    suite = Suite(args.output, args.build)
    try:
        # EVENT_WAIT: synchronous OpenRC lifecycle, bounded by the supervisor's
        # launch deadline. Missing service readiness is a failure, not a delay.
        output = suite.command([suite.runner, '--store', args.store, '--user', '0:0',
                               '--network', 'routed', '--deadline-seconds', '90', '--',
                               '/usr/bin/unshare', '--mount', '--pid', '--fork', '--mount-proc',
                               '--uts', '--ipc', '--cgroup', '/bin/sh', '-ec', SCRIPT], timeout=110)
        assert 'PASS OpenRC init, dependencies' in output
        suite.report['passed'] = True
    finally:
        suite.finish()


if __name__ == '__main__':
    main()

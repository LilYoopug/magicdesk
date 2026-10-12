#!/usr/bin/env python3
"""Boot an installed distribution's default userspace under actual shell UID.

The observer supplements, but does not replace, the distribution's boot units.
Uses a disposable store. Does not request a host reboot or shutdown.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import select
import shlex
import stat
import subprocess
import sys
import time

SYSTEMD = r'''
mkdir -p /run/systemd/system/default.target.wants
date +%s > "$1/started"
if test "$2" = diagnostic; then
    mkdir -p /run/systemd/system/systemd-journald.service.d
    printf '[Service]\nStandardOutput=append:%s/journald.log\nStandardError=inherit\n' "$1" > /run/systemd/system/systemd-journald.service.d/diagnostics.conf
fi
cat > /run/systemd/system/md-boot-observer.service <<EOF
[Unit]
DefaultDependencies=no
After=basic.target
[Service]
Type=simple
ExecStart=/bin/sh $1/observe.sh $1
StandardOutput=append:$1/boot.log
StandardError=inherit
EOF
ln -s ../md-boot-observer.service /run/systemd/system/default.target.wants/md-boot-observer.service
cat > "$1/observe.sh" <<'EOF'
set -ux
# EVENT_WAIT: systemd's startup job completion, bounded by the launch deadline.
systemctl is-system-running --wait > "$1/state"
code=$?
cat "$1/state"
systemctl --failed --no-pager
systemctl list-jobs --no-pager
systemctl status --no-pager
journalctl -b --since="@$(cat "$1/started")" -p warning --no-pager > "$1/journal.log"
systemctl show -p ActiveState -p SubState systemd-journald.service dbus.service systemd-logind.service
printf '%s\n' "$code" > "$1/result"
systemctl exit "$code"
EOF
exec /usr/lib/systemd/systemd --system --show-status=yes --crash-shell=no --crash-reboot=no
'''

OPENRC = r'''
# The image has no enabled runlevels. Select OpenRC's container service policy,
# without changing packaged init or service scripts. All configuration is private.
cp /etc/rc.conf /run/rc.conf
printf '\nrc_sys="docker"\nrc_verbose=yes\nrc_nocolor=yes\n' >> /run/rc.conf
mount --bind /run/rc.conf /etc/rc.conf
cp -a /etc/conf.d /run/conf.d
printf '\nlog_dmesg=no\n' >> /run/conf.d/bootmisc
mount --bind /run/conf.d /etc/conf.d
mount -t tmpfs tmpfs /etc/runlevels
mkdir -p /etc/runlevels/sysinit /etc/runlevels/boot /etc/runlevels/default /etc/runlevels/shutdown
for service in procfs sysfs cgroups; do rc-update add "$service" sysinit; done
for service in bootmisc hostname; do rc-update add "$service" boot; done
for service in syslog crond local; do rc-update add "$service" default; done
mount -t tmpfs tmpfs /etc/local.d
mkdir -p /run/openrc
printf '#!/bin/sh\nexec /usr/bin/python3 %s/observer.py --openrc-observer %s\n' "$1" "$1" > /etc/local.d/observer.start
chmod 755 /etc/local.d/observer.start
exec /sbin/openrc-init
'''


def observe_openrc(target):
    # Install the watch before returning from local.start. openrc-init creates
    # its command FIFO only after sysinit, boot and the default runlevel return.
    libc = ctypes.CDLL(None, use_errno=True)
    watch = libc.inotify_init1(os.O_CLOEXEC)
    if watch < 0 or libc.inotify_add_watch(watch, b'/run/openrc', 0x100 | 0x80) < 0:
        raise OSError(ctypes.get_errno(), 'boot inotify admission')
    if os.fork():
        os.close(watch)
        return
    try:
        with open(target + '/boot.log', 'w', buffering=1) as log:
            os.dup2(log.fileno(), 1)
            os.dup2(log.fileno(), 2)
            fifo = Path('/run/openrc/init.ctl')
            poll = select.poll()
            poll.register(watch, select.POLLIN)
            deadline = time.monotonic() + 60
            # EVENT_WAIT: PID1 creates its command FIFO after boot. Deadline
            # fails the observer; it is not a readiness/settling delay.
            while not fifo.exists():
                remaining = deadline - time.monotonic()
                assert remaining > 0 and poll.poll(int(remaining * 1000)), 'OpenRC did not finish its boot runlevels'
                os.read(watch, 4096)
            os.close(watch)
            assert stat.S_ISFIFO(fifo.stat().st_mode)
            assert os.readlink('/proc/1/exe') == '/sbin/openrc-init'

            def run(*argv):
                result = subprocess.check_output(argv, stderr=subprocess.STDOUT, text=True)
                print(result, end='', flush=True)
                return result

            assert run('rc-status', '--runlevel').strip() == 'default'
            for service in ('syslog', 'crond'):
                run('rc-service', service, 'status')
            # Stop dependants before their provider; stopping syslog also stops
            # crond through the stock OpenRC dependency graph.
            for service in ('crond', 'syslog'):
                run('rc-service', service, 'status')
                before = Path('/run/' + ('syslogd' if service == 'syslog' else service) + '.pid')
                previous = int(before.read_text())
                run('rc-service', service, 'restart')
                current = int(before.read_text())
                assert previous != current
                assert not Path('/proc/' + str(previous)).exists()
                run('rc-service', service, 'status')
                run('rc-service', service, 'stop')
                assert not Path('/proc/' + str(current)).exists()
            run('rc-status', '--all')
            assert not list(Path('/run/openrc/failed').glob('*'))
            Path(target + '/result').write_text('0\n')
            with open('/dev/console', 'w') as console:
                console.write('PASS OpenRC stock PID1 boot and service lifecycle\n')
    except BaseException:
        import traceback
        traceback.print_exc()
        Path(target + '/result').write_text('1\n')
        with open('/dev/console', 'w') as console:
            console.write('FAIL OpenRC stock PID1 boot and service lifecycle\n')
    finally:
        os._exit(0)


def main():
    from test_oci_services import Server, Suite
    from init_fixture import PREPARE, TRACE_SYSCALLS

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--store', required=True)
    parser.add_argument('--build', type=Path)
    parser.add_argument('--diagnostic-console', action='store_true')
    parser.add_argument('--trace', action='store_true', help='Trace filesystem and mount setup; requires strace')
    parser.add_argument('--init', choices=('systemd', 'openrc'), default='systemd')
    parser.add_argument('--output', type=Path, default=Path('build/os-boot-results'))
    args = parser.parse_args()
    if args.init == 'openrc' and args.trace:
        parser.error('--trace is currently a systemd diagnostic')
    suite = Suite(args.output, args.build)
    target = '/md-boot-' + suite.report['id']
    prefix = [suite.runner, '--store', args.store, '--user', '0:0', '--network', 'routed']
    label = 'os-boot-' + suite.report['id']
    created = False
    try:
        suite.command(prefix + ['--', '/bin/mkdir', target])
        created = True
        if args.init == 'openrc':
            suite.transport.upload(suite.client, Path(__file__), suite.base + '/observer.py')
        boot = ['/usr/bin/unshare', '--mount', '--pid', '--fork', '--mount-proc',
                '--uts', '--ipc', '--cgroup', '/bin/sh', '-ec', PREPARE + (SYSTEMD if args.init == 'systemd' else OPENRC), 'boot-test', target,
                'diagnostic' if args.diagnostic_console else 'normal']
        if args.trace:
            boot = ['/usr/bin/strace', '-f', '-s', '256', '-e',
                    'trace=' + TRACE_SYSCALLS,
                    '-o', target + '/boot.trace'] + boot
        # EVENT_WAIT: PTY and PID1 completion, never an elapsed-time boot verdict.
        command = prefix + ['--env', 'MAGICDESK_GUEST_LABEL=' + label,
                            '--bind', suite.base, target, '--deadline-seconds', '180', '--',
                            '/usr/bin/script', '-q', '-e', '-c', shlex.join(boot), '/dev/null']
        if args.init == 'systemd':
            suite.command(command, timeout=205)
        else:
            server = Server(suite, command)
            try:
                server.ready('OpenRC stock PID1 boot and service lifecycle', timeout=120)
            finally:
                try:
                    # The registry pins the exact supervisor with pidfd. Closing
                    # the console alone need not terminate its detached init tree.
                    def launches():
                        records = suite.command(suite.image_command('launches', args.store))
                        return [json.loads(line) for line in records.splitlines() if line.strip()]

                    active = launches()
                    owned = [item for item in active if item['label'] == label]
                    assert len(owned) <= 1, owned
                    for launch in owned:
                        suite.command(suite.image_command('stop', args.store, launch['launchId']))
                    # EVENT_WAIT: the cancelled launch returns and closes its
                    # inherited output. The bound is failure, not readiness.
                    server.process.join(30)
                    assert not server.process.is_alive(), 'init cancellation did not complete'
                    assert server.error is None, server.error
                    remaining = launches()
                    assert not any(item['label'] == label for item in remaining), remaining
                finally:
                    server.close()
        result = suite.command(['cat', suite.base + '/result'])
        assert result.strip() == '0', result
        suite.report['passed'] = True
    finally:
        try:
            for name in ('boot.log', 'journal.log', 'journald.log', 'state', 'result'):
                suite.command(['/system/bin/sh', '-c', 'test ! -f "$1" || tail -200 "$1"',
                               'boot-log', suite.base + '/' + name])
            if args.trace:
                suite.transport.download(suite.client, suite.base + '/boot.trace',
                                         args.output / (suite.report['id'] + '.trace'))
        finally:
            try:
                if created:
                    suite.command(prefix + ['--', '/bin/rmdir', target])
            finally:
                suite.finish()


if __name__ == '__main__':
    if '--openrc-observer' in sys.argv:
        observe_openrc(sys.argv[-1])
    else:
        main()

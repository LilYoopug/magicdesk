#!/usr/bin/env python3
"""Stock system D-Bus and PipeWire in a private PID/run namespace under shell."""
import argparse
from pathlib import Path
from test_oci_services import Suite

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('build', type=Path)
parser.add_argument('store')
args = parser.parse_args()
suite = Suite(args.build, args.build)
store = args.store
script = '''set -eu
mount -t tmpfs -o mode=755 tmpfs /run
mkdir -p /run/dbus
mkfifo /run/dbus/ready
dbus-daemon --system --nofork --nopidfile --print-address=3 3>/run/dbus/ready &
bus=$!
trap 'kill "$bus" || :; wait "$bus" || :' EXIT
read -r address </run/dbus/ready
rm /run/dbus/ready
echo READY
setpriv --reuid=developer --regid=developer --init-groups \
    dbus-send --system --print-reply --reply-timeout=5000 \
    --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ListNames
echo PASS
mkdir -p /run/user/1000
chown developer:developer /run/user/1000
mkfifo /run/pw-log
exec 4<>/run/pw-log
setpriv --reuid=developer --regid=developer --init-groups env PIPEWIRE_DEBUG=3 XDG_RUNTIME_DIR=/run/user/1000 \
    /usr/sbin/pipewire >&4 2>&1 &
pw=$!
while IFS= read -r line <&4; do
    printf '%s\\n' "$line"
    case "$line" in *'start main loop'*) break;; esac
done
setpriv --reuid=developer --regid=developer --init-groups \
    env XDG_RUNTIME_DIR=/run/user/1000 pw-cli info 0
kill "$pw"
wait "$pw"
echo CONTEXT-PASS
'''
try:
    argv = [suite.runner, '--store', store, '--user', '0:0',
            '--deadline-seconds', '90', '--', '/usr/bin/unshare', '--mount',
            '--pid', '--fork', '--mount-proc']
    suite.command(argv + ['/bin/sh', '-ec', script], timeout=100)
    suite.report['passed'] = True
finally:
    suite.finish()

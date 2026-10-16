#!/usr/bin/env python3
"""Run the packaged RTKit with its chroot, UID drop, limits and watchdog intact."""
import argparse
from pathlib import Path
from test_oci_services import Suite

PROGRAM = r'''
set -eu
work=$(mktemp -d /tmp/md-rtkit-XXXXXX)
daemon= bus= logger=
cleanup() {
    test -z "$daemon" || { kill "$daemon" 2>/dev/null || :; wait "$daemon" || :; }
    test -z "$bus" || { kill "$bus" 2>/dev/null || :; }
    test -z "$logger" || wait "$logger" || :
    cat "$work/rtkit.log" 2>/dev/null || :
    rm -rf "$work"
}
trap cleanup EXIT
export DBUS_SYSTEM_BUS_ADDRESS=unix:path=$work/bus
dbus-daemon --session --address="$DBUS_SYSTEM_BUS_ADDRESS" --fork --print-pid > "$work/bus.pid"
bus=$(cat "$work/bus.pid")
rtkit=/usr/libexec/rtkit-daemon
test -x "$rtkit" || rtkit=/usr/lib/rtkit-daemon
# RTKit intentionally sets RLIMIT_FSIZE=0. Its stderr must be a stream, as
# under journald, not a regular file written by the restricted daemon.
mkfifo "$work/log.pipe"
cat "$work/log.pipe" > "$work/rtkit.log" & logger=$!
"$rtkit" --stderr > "$work/log.pipe" 2>&1 &
daemon=$!
# BOUNDED_STATE_WAIT: D-Bus name publication; outer deadline fails a stalled startup.
until busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" get-property org.freedesktop.RealtimeKit1 \
    /org/freedesktop/RealtimeKit1 org.freedesktop.RealtimeKit1 MaxRealtimePriority > "$work/property" 2>/dev/null; do
    kill -0 "$daemon"
    sleep 0.05
done
cat "$work/property"
# The bus name precedes watchdog startup. Require all three live tasks, not just the name.
until test "$(awk '/^Threads:/ {print $2}' /proc/$daemon/status)" = 3; do
    kill -0 "$daemon"
    sleep 0.05
done
grep '^Max processes ' /proc/$daemon/limits
test "$(awk '/^Max processes / {print $3, $4}' /proc/$daemon/limits)" = '3 3'
test "$(awk '/^Uid:/ {print $2}' /proc/$daemon/status)" = "$(id -u rtkit)"
busctl --address="$DBUS_SYSTEM_BUS_ADDRESS" call org.freedesktop.RealtimeKit1 \
    /org/freedesktop/RealtimeKit1 org.freedesktop.DBus.Peer Ping
# BOUNDED_STATE_WAIT: stream logger publishes both watchdog startup records.
until grep -q 'Watchdog thread running' "$work/rtkit.log" && grep -q 'Canary thread running' "$work/rtkit.log"; do
    kill -0 "$daemon"
    sleep 0.05
done
echo 'PASS packaged RTKit: private bus, chroot, logical UID, NPROC=3 and three live threads'
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    args = parser.parse_args()
    suite = Suite(args.build, args.build)
    try:
        suite.command([suite.runner, '--store', args.store, '--user', 'root', '--deadline-seconds', '60',
                       '--', '/usr/bin/unshare', '-mpf', '--mount-proc', '/bin/sh', '-c', PROGRAM], timeout=80)
        suite.report['passed'] = True
    finally:
        suite.finish()


if __name__ == '__main__':
    main()

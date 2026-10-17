#!/bin/sh
# Run inside the desktop's guest process tree and existing D-Bus session.
set -eu
: "${DBUS_SESSION_BUS_ADDRESS:?Run this fixture from the guest desktop terminal}"
: "${XDG_RUNTIME_DIR:?Run this fixture from the guest desktop terminal}"
app=${1:-org.chromium.Chromium}
work=$(mktemp -d "${TMPDIR:-/tmp}/md-flatpak-chromium.XXXXXXXX")
printf 'Logs: %s\n' "$work"

fail() {
    cat "$work"/*.log >&2
    echo 'FAIL Flatpak Chromium; logs retained.' >&2
    exit 1
}

# EVENT_WAIT: Flatpak sandbox command exit; the deadline fails a stuck launch.
timeout 60 flatpak run --command=sh "$app" -ec '
    test -d /sys/block
    test -d /sys/bus
    test -d /sys/dev/block
    test -s /sys/devices/system/cpu/possible
    cat /sys/devices/system/cpu/possible
    test ! -e /sys/devices/platform
    memory=$(mktemp /dev/shm/md-flatpak-check.XXXXXXXX)
    printf shared-memory > "$memory"
    test "$(cat "$memory")" = shared-memory
    rm "$memory"
' > "$work/sysfs.log" 2>&1 || fail
echo 'PASS Flatpak CPU topology, filtered hardware and writable shared memory'

for cycle in 1 2 3; do
    # Flatpak owns its private /tmp; do not touch the installed browser profile.
    # EVENT_WAIT: browser DOM output and exit; timeout is a failure, not cleanup success.
    timeout 90 flatpak run "$app" --headless \
        --user-data-dir="/tmp/${work##*/}-$cycle" --dump-dom \
        'data:text/html,<body><script>document.body.textContent="shroot-js-"+(6*7)</script>' \
        > "$work/$cycle.html" 2> "$work/$cycle.log" || fail
    grep -Fq '<body>shroot-js-42</body>' "$work/$cycle.html" || fail
    printf 'PASS Chromium JavaScript and normal exit: cycle %s\n' "$cycle"
done
echo 'PASS Flatpak Chromium lifecycle (sandbox enabled)'

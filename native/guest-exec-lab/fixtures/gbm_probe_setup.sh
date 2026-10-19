#!/bin/sh
set -eu
# Only populate the explicitly selected laboratory tree.
root=$1
mkdir -p "$root/dev/dri" "$root/sys/dev/char/226:128/device/drm/renderD128"
touch "$root/dev/dri/renderD128"
ln -snf /sys/bus/platform "$root/sys/dev/char/226:128/device/subsystem"
printf '%s\n' 'MODALIAS=platform:shroot-probe' > "$root/sys/dev/char/226:128/device/uevent"

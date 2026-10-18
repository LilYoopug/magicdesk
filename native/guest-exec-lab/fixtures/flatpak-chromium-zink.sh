#!/bin/sh
# Run in the guest desktop's process tree with a prepared Flatpak GL extension.
set -eu
: "${DBUS_SESSION_BUS_ADDRESS:?Run this fixture from the guest desktop terminal}"
: "${XDG_RUNTIME_DIR:?Run this fixture from the guest desktop terminal}"
# Normally GL.host is selected automatically; FLATPAK_GL_DRIVERS may select a control build.
app=${1:-org.chromium.Chromium}
work=$(mktemp -d "${TMPDIR:-/tmp}/md-flatpak-zink.XXXXXXXX")
printf 'Logs: %s\n' "$work"
fail() {
    cat "$work"/*.html "$work"/*.log >&2
    echo 'FAIL Flatpak Zink; logs retained.' >&2
    exit 1
}
for cycle in 1 2 3; do
    # EVENT_WAIT: rendered DOM and normal browser exit; a timeout fails this cycle.
    timeout 90 flatpak run "$app" --headless --enable-gpu --no-first-run \
        --user-data-dir="/tmp/${work##*/}-$cycle" --dump-dom \
        'data:text/html,<body><script>let c=document.createElement("canvas"),g=c.getContext("webgl2");if(g){let e=g.getExtension("WEBGL_debug_renderer_info"),p=new Uint8Array(4);g.clearColor(0.25,0.5,0.75,1);g.clear(g.COLOR_BUFFER_BIT);g.readPixels(0,0,1,1,g.RGBA,g.UNSIGNED_BYTE,p);document.body.textContent=JSON.stringify({renderer:e?g.getParameter(e.UNMASKED_RENDERER_WEBGL):g.getParameter(g.RENDERER),pixel:Array.from(p),error:g.getError()});}else document.body.textContent="NO_WEBGL";</script>' \
        > "$work/$cycle.html" 2> "$work/$cycle.log" || fail
    grep -Fq 'zink Vulkan' "$work/$cycle.html" || fail
    grep -Fq 'MESA_TURNIP' "$work/$cycle.html" || fail
    grep -Fq '"pixel":[64,128,191,255],"error":0' "$work/$cycle.html" || fail
    if grep -Eq 'GPU process exited unexpectedly|Exiting GPU process|FATAL:' "$work/$cycle.log"; then
        fail
    fi
    printf 'PASS Zink pixel readback and GPU lifecycle: cycle %s\n' "$cycle"
done
echo 'PASS Flatpak Zink (sandbox and GPU watchdog enabled)'

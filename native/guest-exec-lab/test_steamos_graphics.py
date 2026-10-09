#!/usr/bin/env python3
"""Prepared Holo ARM64 clients through shell Shroot and ordinary graphics hosts."""
import argparse
import base64
from pathlib import Path
import shlex
import subprocess
import tempfile
import time

from test_oci_services import Suite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    parser.add_argument('--client', choices=['steam', 'glx', 'vulkan', 'gles'], required=True)
    parser.add_argument('--trace', action='store_true')
    parser.add_argument('--timeout', type=int, default=180, help='Owned launch deadline, including client downloads')
    parser.add_argument('--window-title', help='Exact expected client window, rather than an updater or splash')
    args = parser.parse_args()
    if not 1 <= args.timeout <= 1800:
        parser.error('--timeout must be between 1 and 1800 seconds')
    suite = Suite(args.build, args.build)
    client = suite.client
    protocol = 'x11' if args.client in ('steam', 'glx') else 'wayland'
    session = display = None
    log, receipt, pidfile = [suite.base + '/' + n for n in ('client.log', 'exit', 'pid')]
    suite.report.update(store=args.store, probe='steamos-' + args.client,
                        protocol=protocol, sandboxFlagsDisabled=False)
    print('Fixture:', suite.base, flush=True)

    def wait(condition, **selection):
        # EVENT_WAIT: production catalog/host event; timeout fails observation.
        deadline = time.monotonic() + (args.timeout if condition == 'graphics_window_present' else 60)
        while True:
            remaining = deadline - time.monotonic()
            assert remaining > 0, 'Deadline waiting for ' + condition
            value = client.call('wait_for_state', dict(condition=condition,
                timeoutMillis=max(1, min(60000, int(remaining * 1000))), **selection))
            if value.get('matched'):
                return value
            ended = suite.command(['/system/bin/sh', '-c',
                'test ! -f "$1" || cat "$1"', 'fixture', receipt], quiet=True).strip()
            assert not ended, 'Client exited before window: ' + ended

    try:
        before = client.call('get_state')
        assert before['readiness']['interactive'] and not before['readiness']['deviceLocked']
        suite.command([suite.image, 'export-tree', args.store, '/usr/share/xkeyboard-config-2', suite.base + '/xkb'])
        with tempfile.TemporaryDirectory() as temporary:
            wrapper = Path(temporary) / 'magicdesk-guest'
            wrapper.write_text('#!/system/bin/sh\nprintf "%s\\n" "$$" > ' + shlex.quote(pidfile)
                               + '\nexec ' + shlex.quote(suite.runner)
                               + ' --diagnostics --deadline-seconds ' + str(args.timeout) + ' "$@"\n')
            suite.transport.upload(client, wrapper, suite.base + '/magicdesk-guest')
        suite.transport.upload(client, args.build / 'md-await-exit', suite.base + '/md-await-exit')
        suite.command(['chmod', '700', suite.base + '/magicdesk-guest', suite.base + '/md-await-exit'])
        display = client.call('create_display', dict(type='virtual', width=1280, height=800, densityDpi=160))
        session = client.call('graphics.start', dict(protocol=protocol, backend='shell', connection='routed',
            name='Holo ARM64 ' + args.client, keyboardDirectory=suite.base + '/xkb'))['sessionId']
        suite.report['sessionId'] = session
        state = wait('graphics_ready', sessionId=session)['session']
        assert state['executorUid'] == 2000 and state['serverUid'] not in (0, 2000)
        programs = {
            'steam': 'mkdir -p "$HOME/.steam"; '
                     'ln -sfn "$HOME/client" "$HOME/.steam/steam"; '
                     'ln -sfn "$HOME/client" "$HOME/.steam/root"; '
                     'for spec in bin32:ubuntu12_32 bin64:ubuntu12_64 sdk32:linux32 '
                     'sdk64:linux64 sdkarm64:linuxarm64 binarm64:steamrtarm64; do '
                     'name=${spec%%:*}; directory=${spec#*:}; '
                     'if test -d "$HOME/client/$directory"; then '
                     'ln -sfn "$HOME/client/$directory" "$HOME/.steam/$name"; fi; done; '
                     'export LD_LIBRARY_PATH=/opt/steam-gtk2; '
                     'cd /home/steamlab/client; exec ./steamrtarm64/steam',
            'glx': 'export LD_LIBRARY_PATH=/opt/mesa-debian/usr/lib/aarch64-linux-gnu; '
                   'export LIBGL_DRIVERS_PATH=$LD_LIBRARY_PATH/dri MESA_LOADER_DRIVER_OVERRIDE=kgsl; '
                   'glxinfo -B; exec glxgears -info',
            'vulkan': 'export LD_LIBRARY_PATH=/opt/mesa/usr/lib VK_DRIVER_FILES=/opt/mesa/turnip.json; '
                      'vulkaninfo --summary; exec vkcube --wsi wayland --width 640 --height 480 --c 1800',
            'gles': 'export LD_LIBRARY_PATH=/opt/mesa-debian/usr/lib/aarch64-linux-gnu; '
                    'export LIBGL_DRIVERS_PATH=$LD_LIBRARY_PATH/dri MESA_LOADER_DRIVER_OVERRIDE=kgsl; '
                    'export __EGL_VENDOR_LIBRARY_FILENAMES=/opt/mesa-debian/usr/share/glvnd/egl_vendor.d/50_mesa.json; '
                    'eglinfo -B -p wayland; exec es2gears_wayland -info',
        }
        program = programs[args.client]
        if args.trace:
            program = 'exec strace -f -tt -s 160 -o /tmp/md-steamos.trace /bin/sh -ec ' + shlex.quote(program)
        recipe = subprocess.check_output(['java', '-cp', str(args.build / 'recipe-classes'),
            'io.github.mekhontsev.magicdesk.GraphicalRecipe', 'routed', protocol, args.store,
            '/home/steamlab', program, 'steamlab'], text=True, timeout=20)
        launch = ('{ env PATH=' + shlex.quote(suite.base + ':/system/bin')
                  + ' /system/bin/sh -c ' + shlex.quote(recipe)
                  + '; r=$?; printf "%s\\n" "$r" > ' + shlex.quote(receipt)
                  + '; } > ' + shlex.quote(log) + ' 2>&1')
        suite.report['launch'] = launch
        client.call('graphics.execute', dict(sessionId=session, command=launch))
        selection = dict(windowTitle=args.window_title) if args.window_title else {}
        mapped = wait('graphics_window_present', sessionId=session, **selection)['session']
        window = next(w for w in mapped['windows'] if w['mapped'] and not w['parentWindowId']
                      and (not args.window_title or w['title'] == args.window_title))
        suite.report['window'] = window
        client.call('graphics.open_window', dict(sessionId=session, windowId=window['windowId'],
                    placement='display', displayId=display['id'], uniqueId=display['uniqueId']))
        host = wait('graphics_host_attached', sessionId=session, windowId=window['windowId'])['matchingHosts'][0]
        suite.report['host'] = host
        wait('app_ready', taskId=host['taskId'], displayId=display['id'])
        previous = None
        for frame in range(2):
            # Bounded pixel observation: attachment precedes the first rendered
            # frame. Each capture is a fresh compositor snapshot; no settle delay.
            deadline = time.monotonic() + 60
            while True:
                result = client.call_result('capture_screenshot', dict(taskId=host['taskId']))
                png = base64.b64decode(next(c['data'] for c in result['content'] if c['type'] == 'image'))
                rgb = subprocess.check_output(['magick', 'png:-', '-depth', '8', 'rgb:-'], input=png)
                pixels = list(zip(rgb[::3], rgb[1::3], rgb[2::3]))
                populated = args.client != 'steam' or sum(max(pixel) > 8 for pixel in pixels) > len(pixels) // 5
                if populated and len(set(pixels)) > 100:
                    break
                assert time.monotonic() < deadline, 'Window remained blank or at its initial loading indicator'
            path = args.build / ('steamos-' + args.client + '-' + suite.report['id'] + '-' + str(frame) + '.png')
            path.write_bytes(png)
            suite.report.setdefault('captures', []).append(str(path))
            print('Capture:', path, flush=True)
            if previous is not None and args.client != 'steam':
                assert previous != rgb, 'Graphics did not change between captures'
            previous = rgb
        suite.report['mappedAndCaptured'] = True
        if args.client != 'steam':
            output = suite.command(['cat', log], quiet=True)
            expected = {'vulkan': 'DRIVER_ID_MESA_TURNIP',
                        'glx': 'GL_RENDERER   = Adreno',
                        'gles': 'OpenGL ES profile renderer: Adreno'}[args.client]
            assert expected in output and 'supervisor failure' not in output, 'No confirmed hardware renderer'
        after = client.call('get_state')
        assert before['homeLease'] == after['homeLease'] and before['workspaces'] == after['workspaces']
        suite.report['passed'] = args.client != 'steam' or bool(args.window_title)
        if args.client == 'steam':
            suite.report['coverage'] = 'Requested window rendered; no account login or games tested'
    except Exception as error:
        suite.report['failure'] = repr(error)
        raise
    finally:
        errors = []
        try:
            suite.command(['/system/bin/sh', '-ec', '''
if test -f "$1"; then
    pid=$(cat "$1")
    if test "$(readlink "/proc/$pid/exe")" = "$2"; then
        kill -TERM "$pid"
    fi
    timeout 200 "$3" "$4" || test -s "$4"
fi
''', 'fixture', pidfile, suite.runner, suite.base + '/md-await-exit', receipt], timeout=210)
            local_log = args.build / ('steamos-' + args.client + '-' + suite.report['id'] + '.log')
            suite.transport.download(client, log, local_log, overwrite=True)
            suite.report['logFile'] = str(local_log)
            suite.report['logTail'] = '\n'.join(local_log.read_text(errors='replace').splitlines()[-200:])
            suite.report['exit'] = suite.command(['cat', receipt], quiet=True).strip()
            if args.trace:
                suite.report['trace'] = suite.command([suite.runner, '--store', args.store,
                    '--user', '0:0', '--deadline-seconds', '20', '--', '/usr/bin/tail', '-400', '/tmp/md-steamos.trace'], quiet=True)
        except Exception as error:
            errors.append(str(error))
        for action in ([lambda: client.call('graphics.stop', dict(sessionId=session)),
                        lambda: wait('graphics_session_absent', sessionId=session)] if session else []) + (
                       [lambda: client.call('remove_display', dict(displayId=display['id'], uniqueId=display['uniqueId'])),
                        lambda: wait('display_absent', displayId=display['id'])] if display else []):
            try:
                action()
            except Exception as error:
                errors.append(str(error))
        suite.report['cleanupErrors'] = errors
        suite.report['passed'] &= not errors
        suite.finish()
        if errors:
            raise RuntimeError(errors)


if __name__ == '__main__':
    main()

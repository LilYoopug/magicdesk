#!/usr/bin/env python3
"""Retained init fixture with optional Weston in an installed environment.

Default-target boot is independently checked by test_os_boot.py. This focused
session hosts the existing browser, portal, container and VS Code fixtures.
Use stop after inspection; state and logs are kept under build/installed-NAME.
"""
import argparse
import base64
import errno
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess
import threading
import time
import tomllib
import urllib.error
import urllib.request
import uuid

from graphical_recipe import compile_recipe
from init_fixture import installed_boot
from test_oci_services import Suite, port


def wait_controller(state, timeout=90, *, user=False):
    deadline = time.monotonic() + timeout
    port_key, uid = ('userPort', state['userUid']) if user else ('rootPort', 0)
    request = urllib.request.Request('http://127.0.0.1:' + str(state[port_key]),
                                     headers={'Authorization': 'Bearer ' + state['token']})
    while True:
        remaining = deadline - time.monotonic()
        assert remaining > 0, port_key + ' controller did not become ready'
        try:
            with urllib.request.urlopen(request, timeout=min(remaining, 5)) as response:
                result = json.load(response)
            assert result['uid'] == uid, result
            return
        except urllib.error.URLError as error:
            if not isinstance(error.reason, OSError) or error.reason.errno != errno.ECONNREFUSED:
                raise
        # PROTOCOL_BACKOFF: retry only an unbound control socket. The deadline
        # fails startup; success requires an authenticated response from this run.
        threading.Event().wait(min(0.1, remaining))


def attach_window(client, state, statefile):
    def wait(condition, **kwargs):
        # EVENT_WAIT: exact graphics state; timeout retains the failed fixture
        # for diagnosis and does not claim that its window became ready.
        value = client.call('wait_for_state', dict(condition=condition, timeoutMillis=60000,
                                                 sessionId=state['sessionId'], **kwargs))
        assert value['matched'], value
        return value

    ready = wait('graphics_window_present')
    window = next(w['windowId'] for w in ready['session']['windows'] if w['mapped'] and not w['parentWindowId'])
    display = state['display']
    client.call('graphics.open_window', dict(sessionId=state['sessionId'], windowId=window,
                placement='display', displayId=display['id'], uniqueId=display['uniqueId']))
    wait('graphics_host_attached', windowId=window)
    state['windowId'] = window
    statefile.write_text(json.dumps(state, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('start', 'attach', 'run', 'shell', 'capture', 'status', 'stop', 'upload', 'download'))
    parser.add_argument('--name', required=True)
    parser.add_argument('--user', default='mdtester')
    parser.add_argument('--root', action='store_true')
    parser.add_argument('--wait', action='store_true', help='Wait for run completion and retain its log')
    parser.add_argument('--timeout', type=int, default=300, help='Shell command failure bound in seconds')
    parser.add_argument('--init', choices=('systemd', 'openrc', 'runit'), default='systemd')
    parser.add_argument('--headless', action='store_true', help='Boot control/init only, without user session, display or GPU')
    parser.add_argument('--build', type=Path, help='Stage a native build; otherwise use the installed APK')
    parser.add_argument('--entry', choices=('lazy', 'base'), default='lazy')
    parser.add_argument('value', nargs='?')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-zA-Z0-9_-]+', args.name) or not re.fullmatch(r'[a-z_][a-z0-9_-]*', args.user):
        parser.error('Use a simple environment and guest account name')
    out = Path('build/installed-' + args.name)
    out.mkdir(parents=True, exist_ok=True)
    statefile = out / 'session.json'
    target = '/opt/md-installed-fixture'

    if args.action == 'start':
        if statefile.exists() and not json.loads(statefile.read_text()).get('closed'):
            parser.error('Stop the previous exact fixture before starting another')
        suite = Suite(out,args.build)
        client = suite.client
        before = client.call('get_state')
        if not args.headless and (before['workspaces'] or before['graphics']):
            suite.finish()
            parser.error('Stop the active graphics fixture before starting an isolated desktop fixture')
        state = suite.report
        state.update(name=args.name, user=args.user, init=args.init, headless=args.headless, entryMode=args.entry, token=uuid.uuid4().hex,
                     rootPort=port(), userPort=port(), target=target)
        state['homeLeaseBefore'] = before['homeLease']
        try:
            info = suite.installed_environment(args.name)
            assert not info['launches'], 'Environment must be idle before boot'
        except Exception as error:
            suite.report['preparationFailure'] = repr(error)
            suite.finish()
            raise
        state['environment'] = info
        store = info['store']
        entry = 'SHROOT_MACHINE_ENTRY=' + ('0' if args.entry == 'base' else '1')
        prefix = [suite.runner, '--store', store, '--user', '0:0', '--env', entry]
        state['runner'] = suite.runner
        state['prefix'] = prefix
        suite.command(prefix + ['--', '/bin/mkdir', '-p', target])
        boot, driver = installed_boot(target, state['rootPort'], state['token'], args.init,
                                      None if args.headless else args.user)
        if args.headless:
            files = {'boot.sh': boot, 'session-controller.py':
                     (Path(__file__).with_name('fixtures') / 'session-controller.py').read_text()}
            for name, content in files.items():
                path = out / name
                path.write_text(content)
                suite.transport.upload(client, path, suite.base + '/' + name)
            suite.command(['chmod', '755', suite.base])
            suite.command(['chmod', '644', suite.base + '/boot.sh', suite.base + '/session-controller.py'])
            command = shlex.join(['/usr/bin/unshare', '--mount', '--pid', '--fork', '--mount-proc',
                                  '--uts', '--ipc', '--cgroup', '/bin/sh', target + '/boot.sh'])
            launch = shlex.join([*prefix, '--network', 'routed', '--env', 'MAGICDESK_GUEST_LABEL=' + state['id'],
                                '--bind', suite.base, target, '--', '/usr/bin/script', '-q', '-e', '-c', command, '/dev/null'])
            state['launch'] = launch
            statefile.write_text(json.dumps(state, indent=2))
            state['supervisorPid'] = int(suite.command(['/system/bin/sh', '-c',
                launch + ' >' + shlex.quote(suite.base + '/boot.log') + ' 2>&1 </dev/null & echo $!'], quiet=True))
            statefile.write_text(json.dumps(state, indent=2))
            wait_controller(state)
            state['ready'] = True
            statefile.write_text(json.dumps(state, indent=2))
            print(statefile)
            return
        account = suite.command(prefix + ['--', '/usr/bin/getent', 'passwd', args.user], quiet=True).strip().split(':')
        assert len(account) == 7 and account[0] == args.user, 'Expected the selected guest account'
        state['userUid'] = int(account[2])
        assert state['userUid'] > 0, 'Desktop fixtures require an ordinary guest account'
        home = account[5]
        assert home.startswith('/home/')
        state['home'] = home
        user = shlex.quote(args.user)
        control = '/usr/bin/python3 ' + target + '/session-controller.py ' + target
        autostart = ('#!/bin/sh\nset -eu\nenv > ' + target + '/desktop.env\n'
                     'magicdesk-desktop-session --ready\n'
                     'exec ' + control + ' ')
        autostart += str(state['userPort']) + ' ' + state['token'] + '\n'
        bus = ('export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus\n'
               if args.init == 'systemd' else 'unset DBUS_SESSION_BUS_ADDRESS\n')
        session = f'''#!/bin/bash
set -eux
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export HOME={shlex.quote(home)} USER={user} LOGNAME={user}
export XDG_RUNTIME_DIR=/run/user/$(id -u)
{bus.rstrip()}
export WAYLAND_DISPLAY=/tmp/magicdesk-wayland/wayland-0
exec magicdesk-desktop-session weston --socket=wayland-1 --config={target}/weston.ini --width=1200 --height=800 --idle-time=0
'''
        files = {'boot.sh': boot, 'driver.sh': driver, 'session.sh': session, 'autostart.sh': autostart,
                 'weston.ini': '[core]\nxwayland=true\n[autolaunch]\npath=' + target + '/autostart.sh\n'}
        fixtures = Path(__file__).with_name('fixtures')
        for name in ('session-controller.py', 'sandbox-browser-gui.py', 'vscode-gui.py', 'vscode-debug.js',
                     'flatpak-chromium-smoke.sh', 'flatpak-chromium-zink.sh', 'flatpak-document-portal.sh'):
            files[name] = (fixtures / name).read_text()
        for name, content in files.items():
            path = out / name
            path.write_text(content)
            suite.transport.upload(client, path, suite.base + '/' + name)
        suite.command(['chmod', '777', suite.base])
        suite.command(['chmod', '755', suite.base + '/autostart.sh'])
        suite.command(['chmod', '-R', 'a+rX', suite.base])
        classes = out / 'classes'
        state['sourceHashes'] = compile_recipe(classes)
        boot_command = shlex.join(['/usr/bin/unshare', '--mount', '--pid', '--fork', '--mount-proc',
                                  '--uts', '--ipc', '--cgroup', '/bin/sh', target + '/boot.sh'])
        command = shlex.join(['/usr/bin/script', '-q', '-e', '-c', boot_command, '/dev/null'])
        recipe = subprocess.check_output(['java', '-cp', str(classes),
            'io.github.mekhontsev.magicdesk.GraphicalRecipe', 'routed', 'wayland', store, '/root', command, '0:0'], text=True)
        wrapper = out / 'shroot'
        wrapper.write_text('#!/system/bin/sh\nexec ' + shlex.join([suite.runner, '--network', 'routed', '--env', entry,
            '--env', 'MAGICDESK_GUEST_LABEL=' + state['id'], '--bind', suite.base, target]) + ' "$@"\n')
        suite.transport.upload(client, wrapper, suite.base + '/shroot')
        suite.command(['chmod', '755', suite.base + '/shroot'])
        before = client.call('get_state')
        assert not before['workspaces'] and not before['graphics']
        state['homeLeaseBefore'] = before['homeLease']
        state['display'] = client.call('create_display', dict(type='virtual', width=1200, height=800, densityDpi=160))
        statefile.write_text(json.dumps(state, indent=2))
        state['sessionId'] = client.call('graphics.start', dict(protocol='wayland', backend='shell',
            connection='routed', wholeDesktop=True, name=args.name + ' ' + args.init, keyboardDirectory='guest:' + store))['sessionId']
        statefile.write_text(json.dumps(state, indent=2))

        def wait(condition, **kwargs):
            # EVENT_WAIT: exact graphics state; timeout fails startup.
            value = client.call('wait_for_state', dict(condition=condition, timeoutMillis=60000, **kwargs))
            assert value['matched'], value
            return value

        wait('graphics_ready', sessionId=state['sessionId'])
        launch = ('env PATH=' + shlex.quote(suite.base + ':/system/bin') + ' /system/bin/sh -c ' +
                  shlex.quote(recipe) + ' >' + shlex.quote(suite.base + '/boot.log') + ' 2>&1')
        # The fixture carries the exact production session payload, not a
        # desktop Exec entry. Keep that payload in a file, outside Exec's limit.
        launcher = out / 'launch.sh'
        launcher.write_text('#!/system/bin/sh\n' + launch + '\n')
        suite.transport.upload(client, launcher, suite.base + '/launch.sh')
        state['launch'] = launch
        statefile.write_text(json.dumps(state, indent=2))
        client.call('graphics.execute', dict(sessionId=state['sessionId'],
                    command=shlex.join(['/system/bin/sh', suite.base + '/launch.sh'])))
        attach_window(client, state, statefile)
        wait_controller(state)
        wait_controller(state, user=True)
        state['ready'] = True
        statefile.write_text(json.dumps(state, indent=2))
        print(statefile)
        return

    state = json.loads(statefile.read_text())
    spec = importlib.util.spec_from_file_location('transport', Path(__file__).resolve().parents[2] / 'scripts/mcp-client.py')
    transport = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transport)
    config = tomllib.loads((Path.home() / '.codex/config.toml').read_text())['mcp_servers']['magicdesk']
    client = transport.Client(config['url'], config['http_headers']['Authorization'].removeprefix('Bearer '),
                              timeout=args.timeout+30, request_timeout=args.timeout)

    def shell(command):
        result = client.call('console.execute', dict(sessionId=state['consoleId'], command=command))
        assert result['exitCode'] == 0, result
        return result['output']

    if args.action == 'attach':
        assert not state.get('closed') and not state.get('headless'), 'No retained graphical fixture'
        attach_window(client, state, statefile)
    elif args.action == 'run':
        assert args.root or not state.get('headless'), 'Headless fixture exposes only --root commands'
        ident = uuid.uuid4().hex
        request = urllib.request.Request('http://127.0.0.1:' + str(state['rootPort' if args.root else 'userPort']),
            data=json.dumps(dict(id=ident, command=args.value, wait=args.wait)).encode(),
            headers={'Authorization': 'Bearer ' + state['token']})
        print('Command log: ' + state['directory'] + '/' + ident + '.log', flush=True)
        # EVENT_WAIT: this command's completion; a transport timeout never replays it.
        response=json.loads(urllib.request.urlopen(request, timeout=1900 if args.wait else 10).read())
        print(json.dumps(response))
        if args.wait:
            log=out / (ident + '.log')
            transport.download(client,state['directory'] + '/' + ident + '.log',log)
            print(log.read_text())
            raise SystemExit(response['exitCode'])
    elif args.action == 'shell':
        print(shell(args.value.replace('@BASE@', state['directory'])))
    elif args.action in ('upload', 'download'):
        path = Path(args.value)
        if args.action == 'upload':
            transport.upload(client, path, state['directory'] + '/' + path.name, overwrite=True)
            shell(shlex.join(['chmod', '644', state['directory'] + '/' + path.name]))
        else:
            assert not path.is_absolute() and '..' not in path.parts
            destination = out / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            transport.download(client, state['directory'] + '/' + path.as_posix(), destination, overwrite=True)
    elif args.action == 'capture':
        assert not state.get('headless'), 'Headless fixture has no display'
        result = client.call_result('capture_screenshot', dict(displayId=state['display']['id']))
        path = out / (args.value or 'desktop.png')
        path.write_bytes(base64.b64decode(next(i['data'] for i in result['content'] if i['type'] == 'image')))
        print(path)
    elif args.action == 'status':
        print(shell('tail -60 ' + shlex.quote(state['directory'] + '/boot.log')))
        print(json.dumps(client.call('graphics.list'), indent=2))
    elif args.action == 'stop':
        store = state['environment']['store']
        image = ([state['directory'] + '/libmagicdesk_guest_image.so'] if state.get('nativeBuild')
                 else [state['runner'], 'image'])
        launches = shell(shlex.join([*image, 'launches', store]))
        for line in launches.splitlines():
            launch = json.loads(line)
            if launch['label'] == state['id']:
                shell(shlex.join([*image, 'stop', store, launch['launchId']]))
        if state.get('sessionId'):
            client.call('graphics.stop', dict(sessionId=state['sessionId']))
            assert client.call('wait_for_state', dict(condition='graphics_session_absent',
                sessionId=state['sessionId'], timeoutMillis=30000))['matched']
        if state.get('display'):
            display = state['display']
            client.call('remove_display', dict(displayId=display['id'], uniqueId=display['uniqueId']))
            assert client.call('wait_for_state', dict(condition='display_absent',
                displayId=display['id'], timeoutMillis=30000))['matched']
        for name in ('boot.log', 'control.log', 'desktop.log', 'driver.log', 'desktop.env'):
            if shell('test ! -f ' + shlex.quote(state['directory'] + '/' + name) + ' || echo present').strip():
                transport.download(client, state['directory'] + '/' + name, out / name, overwrite=True)
        after = client.call('get_state')
        assert after['homeLease'] == state['homeLeaseBefore']
        if not state.get('headless'):
            assert not after['workspaces']
        client.call('console.close', dict(sessionId=state['consoleId']))
        state['closed'] = True
        statefile.write_text(json.dumps(state, indent=2))


if __name__ == '__main__':
    main()

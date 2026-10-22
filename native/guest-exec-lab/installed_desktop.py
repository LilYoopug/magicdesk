#!/usr/bin/env python3
"""Retained Weston/systemd fixture using an installed named environment and APK.

Default-target boot is independently checked by test_os_boot.py. This focused
session hosts the existing browser, portal, container and VS Code fixtures.
Use stop after inspection; state and logs are kept under build/installed-NAME.
"""
import argparse
import base64
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess
import tomllib
import urllib.request
import uuid

from graphical_recipe import compile_recipe
from init_fixture import PREPARE
from test_oci_services import Suite, port


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('start', 'run', 'shell', 'capture', 'status', 'stop', 'upload', 'download'))
    parser.add_argument('--name', required=True)
    parser.add_argument('--user', default='mdtester')
    parser.add_argument('--root', action='store_true')
    parser.add_argument('--build', type=Path, help='Stage a native build; otherwise use the installed APK')
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
        if before['workspaces'] or before['graphics']:
            suite.finish()
            parser.error('Stop the active graphics fixture before starting an isolated desktop fixture')
        state = suite.report
        state.update(name=args.name, user=args.user, token=uuid.uuid4().hex,
                     rootPort=port(), userPort=port(), target=target)
        info = json.loads(suite.command(['shroot', 'inspect', args.name], quiet=True))
        assert not info['launches'], 'Environment must be idle before boot'
        state['environment'] = info
        store = info['store']
        prefix = [suite.runner, '--store', store, '--user', '0:0']
        state['runner'] = suite.runner
        state['prefix'] = prefix
        suite.command(prefix + ['--', '/bin/mkdir', '-p', target])
        home = suite.command(prefix + ['--', '/bin/sh', '-ec',
                             'getent passwd "$1" | cut -d: -f6', 'fixture', args.user], quiet=True).strip()
        assert home.startswith('/home/')
        state['home'] = home
        user = shlex.quote(args.user)
        control = '/usr/bin/python3 ' + target + '/session-controller.py ' + target
        autostart = ('#!/bin/sh\nset -eu\nenv > ' + target + '/desktop.env\n'
                     'dbus-update-activation-environment --systemd DISPLAY WAYLAND_DISPLAY XDG_CURRENT_DESKTOP\n'
                     'exec ' + control + ' ')
        autostart += str(state['userPort']) + ' ' + state['token'] + '\n'
        boot = PREPARE.replace('umount /run/md-host-dev', '''
for node in kgsl-3d0 fuse dma_heap dri; do
    if [ -d /run/md-host-dev/$node ]; then mkdir -p /dev/$node
    elif [ -e /run/md-host-dev/$node ]; then touch /dev/$node
    else continue
    fi
    mount --bind /run/md-host-dev/$node /dev/$node
done
umount /run/md-host-dev
''') + '''
mount --make-rshared /
mkdir -p /run/systemd/system
unset XDG_DATA_DIRS XDG_CONFIG_DIRS XDG_RUNTIME_DIR DBUS_SESSION_BUS_ADDRESS
cat > /run/systemd/system/md-installed.target <<EOF
[Unit]
DefaultDependencies=no
Requires=md-installed.service md-installed-control.service
After=md-installed.service
EOF
cat > /run/systemd/system/md-installed.service <<EOF
[Unit]
DefaultDependencies=no
Conflicts=shutdown.target
Before=shutdown.target
[Service]
Type=simple
ExecStart=/bin/bash /opt/md-installed-fixture/driver.sh
StandardOutput=append:/opt/md-installed-fixture/driver.log
StandardError=inherit
EOF
exec /usr/bin/setpriv --bounding-set=-sys_module /usr/lib/systemd/systemd --system --unit=md-installed.target --show-status=no --crash-shell=no --crash-reboot=no
'''
        boot = boot.replace('cat > /run/systemd/system/md-installed.service', f'''cat > /run/systemd/system/md-installed-control.service <<EOF
[Unit]
DefaultDependencies=no
Conflicts=shutdown.target
Before=shutdown.target
[Service]
Type=simple
ExecStart={control} {state['rootPort']} {state['token']}
StandardOutput=append:{target}/control.log
StandardError=inherit
EOF
cat > /run/systemd/system/md-installed.service''')
        driver = f'''#!/bin/bash
set -eux
uid=$(id -u {user})
systemctl start dbus.socket systemd-logind.service systemd-user-sessions.service
systemctl start user@$uid.service
exec systemd-run --unit=md-installed-desktop --wait --collect --uid={user} --property=PAMName=login /bin/bash {target}/session.sh
'''
        session = f'''#!/bin/bash
set -eux
export HOME={shlex.quote(home)} USER={user} LOGNAME={user}
export XDG_RUNTIME_DIR=/run/user/$(id -u)
export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus
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
        wrapper.write_text('#!/system/bin/sh\nexec ' + shlex.join([suite.runner, '--network', 'routed',
            '--env', 'MAGICDESK_GUEST_LABEL=' + state['id'], '--bind', suite.base, target]) + ' "$@"\n')
        suite.transport.upload(client, wrapper, suite.base + '/shroot')
        suite.command(['chmod', '755', suite.base + '/shroot'])
        before = client.call('get_state')
        assert not before['workspaces'] and not before['graphics']
        state['homeLeaseBefore'] = before['homeLease']
        state['display'] = client.call('create_display', dict(type='virtual', width=1200, height=800, densityDpi=160))
        statefile.write_text(json.dumps(state, indent=2))
        state['sessionId'] = client.call('graphics.start', dict(protocol='wayland', backend='shell',
            connection='routed', wholeDesktop=True, name=args.name + ' systemd', keyboardDirectory='guest:' + store))['sessionId']
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
        ready = wait('graphics_window_present', sessionId=state['sessionId'])
        window = next(w['windowId'] for w in ready['session']['windows'] if w['mapped'] and not w['parentWindowId'])
        display = state['display']
        client.call('graphics.open_window', dict(sessionId=state['sessionId'], windowId=window,
                    placement='display', displayId=display['id'], uniqueId=display['uniqueId']))
        wait('graphics_host_attached', sessionId=state['sessionId'], windowId=window)
        state['windowId'] = window
        statefile.write_text(json.dumps(state, indent=2))
        print(statefile)
        return

    state = json.loads(statefile.read_text())
    spec = importlib.util.spec_from_file_location('transport', Path(__file__).resolve().parents[2] / 'scripts/mcp-client.py')
    transport = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transport)
    config = tomllib.loads((Path.home() / '.codex/config.toml').read_text())['mcp_servers']['magicdesk']
    client = transport.Client(config['url'], config['http_headers']['Authorization'].removeprefix('Bearer '),
                              timeout=300, request_timeout=270)

    def shell(command):
        result = client.call('console.execute', dict(sessionId=state['consoleId'], command=command))
        assert result['exitCode'] == 0, result
        return result['output']

    if args.action == 'run':
        ident = uuid.uuid4().hex
        request = urllib.request.Request('http://127.0.0.1:' + str(state['rootPort' if args.root else 'userPort']),
            data=json.dumps(dict(id=ident, command=args.value)).encode(),
            headers={'Authorization': 'Bearer ' + state['token']})
        print(urllib.request.urlopen(request, timeout=10).read().decode())
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
        display = state['display']
        client.call('remove_display', dict(displayId=display['id'], uniqueId=display['uniqueId']))
        assert client.call('wait_for_state', dict(condition='display_absent',
            displayId=display['id'], timeoutMillis=30000))['matched']
        for name in ('boot.log', 'driver.log', 'desktop.env'):
            if shell('test ! -f ' + shlex.quote(state['directory'] + '/' + name) + ' || echo present').strip():
                transport.download(client, state['directory'] + '/' + name, out / name, overwrite=True)
        after = client.call('get_state')
        assert not after['workspaces'] and after['homeLease'] == state['homeLeaseBefore']
        client.call('console.close', dict(sessionId=state['consoleId']))
        state['closed'] = True
        statefile.write_text(json.dumps(state, indent=2))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Run the full machinectl fixture in a retained installed systemd environment.

The selected /var/lib/machines/MACHINE must already contain a bootable rootfs
with systemd, dbus, iproute2 and Python. No unit overrides or sandbox switches
are installed by this test.
"""
import argparse
import json
from pathlib import Path
import shlex
import urllib.request
import uuid

from test_oci_services import Suite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--session', type=Path, required=True)
    parser.add_argument('--machine', required=True)
    args = parser.parse_args()
    state = json.loads(args.session.read_text())
    assert not state.get('closed')
    suite = Suite(args.session.parent)
    tag = uuid.uuid4().hex
    suite.report.update(session=state['id'], environment=state['environment'],
                        nativeHashes=state.get('nativeHashes'), machine=args.machine)
    try:
        fixture = Path(__file__).with_name('fixtures') / 'nspawn-boot.py'
        suite.transport.upload(suite.client, fixture, state['directory'] + '/nspawn-boot.py', overwrite=True)
        suite.command(['chmod', '644', state['directory'] + '/nspawn-boot.py'])
        result_name = 'nspawn-' + tag + '.json'
        command = shlex.join(['python3', state['target'] + '/nspawn-boot.py', args.machine,
                             state['target'] + '/' + result_name])
        request = urllib.request.Request('http://127.0.0.1:' + str(state['rootPort']),
            data=json.dumps(dict(id=tag, command=command, wait=True)).encode(),
            headers={'Authorization': 'Bearer ' + state['token']})
        print('Nspawn log: ' + state['directory'] + '/' + tag + '.log', flush=True)
        # EVENT_WAIT: exact root-controller job; a timeout never replays the request.
        response = json.loads(urllib.request.urlopen(request, timeout=900).read())
        log = args.session.parent / ('nspawn-' + tag + '.log')
        result = args.session.parent / result_name
        suite.transport.download(suite.client, state['directory'] + '/' + tag + '.log', log)
        suite.transport.download(suite.client, state['directory'] + '/' + result_name, result)
        suite.report.update(log=str(log), probe=json.loads(result.read_text()))
        assert response['exitCode'] == 0 and suite.report['probe']['passed'], log.read_text()[-6000:]
        suite.report['passed'] = True
        print('PASS machinectl boot/shell/service/network/stop in ' + state['name'], flush=True)
    finally:
        suite.finish()


if __name__ == '__main__':
    main()

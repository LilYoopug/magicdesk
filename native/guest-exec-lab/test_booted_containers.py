#!/usr/bin/env python3
"""Run existing container network probes in a retained installed systemd session."""
import argparse
import json
from pathlib import Path
import shlex
import urllib.request
import uuid

from docker_network_fixture import Observer
from test_oci_services import Suite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--session', required=True, type=Path)
    parser.add_argument('--engine', choices=('docker', 'podman'), required=True)
    parser.add_argument('--docker-profile', choices=('routed', 'iptables', 'nftables'), default='nftables')
    parser.add_argument('--internet', action='store_true')
    args = parser.parse_args()
    state = json.loads(args.session.read_text())
    assert not state.get('closed')
    suite = Suite(args.session.parent)
    observer = Observer()
    tag = uuid.uuid4().hex
    suite.report.update(engine=args.engine, session=state['id'], environment=state['environment'],
                        nativeHashes=state.get('nativeHashes'))
    try:
        for name in ('probe_docker_runtime.py', 'probe_podman_runtime.py', 'docker_network_fixture.py'):
            remote = state['directory'] + '/' + name
            suite.transport.upload(suite.client, Path(__file__).with_name(name), remote, overwrite=True)
            suite.command(['chmod', '644', remote])
        if args.engine == 'docker':
            argv = ['python3', state['target'] + '/probe_docker_runtime.py', '--guest',
                    args.docker_profile, 'python:3.14-alpine', '0', 'none', 'private',
                    '0', '0', '0', '0', '0', observer.address, 'overlay2',
                    '/var/lib/md-fixture-docker', str(int(args.docker_profile == 'routed')),
                    str(int(args.internet))]
        else:
            options = dict(directory='/tmp/md-podman-' + tag, cache='/var/lib/md-fixture-podman',
                storage='overlay', network='bridge', image='docker.io/library/alpine:3.23',
                cgroups='enabled', internet=args.internet, portsImage='docker.io/library/python:3.14-alpine',
                trace=False, hostLimits=False, unlimitedPids=False, execRepeats=3, observer=observer.address)
            argv = ['python3', state['target'] + '/probe_podman_runtime.py', '--guest', json.dumps(options)]
        request = urllib.request.Request('http://127.0.0.1:' + str(state['rootPort']),
            data=json.dumps(dict(id=tag, command=shlex.join(argv), wait=True)).encode(),
            headers={'Authorization': 'Bearer ' + state['token']})
        print('Container log: ' + state['directory'] + '/' + tag + '.log', flush=True)
        # EVENT_WAIT: probe completion through the exact booted session; no replay on timeout.
        response = json.loads(urllib.request.urlopen(request, timeout=1900).read())
        local = args.session.parent / (args.engine + '-' + tag + '.log')
        suite.transport.download(suite.client, state['directory'] + '/' + tag + '.log', local)
        output = local.read_text()
        suite.report['log'] = str(local)
        assert response['exitCode'] == 0, output[-6000:]
        marker = args.engine.upper() + '_REPORT '
        reports = [json.loads(line.removeprefix(marker)) for line in output.splitlines() if line.startswith(marker)]
        assert len(reports) == 1, output[-6000:]
        report = reports[0]
        suite.report['probe'] = report
        if args.engine == 'podman':
            assert report['passed'], report.get('failure')
        else:
            assert report.get('portPublicationPassed') and report.get('containerPeerExchangePassed'), report
            assert report['daemonExitCode'] == 0 and report['readerDrained'], report
            if args.internet:
                assert report['internetPassed'], report
            for item in report['commands']:
                argv = item['command']
                if 'md-port-conflict' in argv and 'run' in argv:
                    continue
                if argv[3:5] == ['image', 'inspect']:
                    continue
                assert item.get('exitCode') == 0, item
        suite.report['passed'] = True
        print('PASS ' + args.engine + ' in booted ' + state['name'], flush=True)
    finally:
        observer.close()
        suite.report['externalPortChecks'] = observer.records
        suite.finish()


if __name__ == '__main__':
    main()

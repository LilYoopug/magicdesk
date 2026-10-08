#!/usr/bin/env python3
"""Stock namespace consumers in a prepared disposable userspace, actual shell."""
import argparse
import importlib.util
import json
from pathlib import Path
import shlex
import tomllib
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    parser.add_argument('--trace', action='store_true')
    parser.add_argument('--case', choices=('all', 'basic', 'readonly', 'identity', 'nested', 'pid', 'pid-debugger'), default='all')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location('transport', repo / 'scripts/mcp-client.py')
    transport = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transport)
    config = tomllib.loads((Path.home() / '.codex/config.toml').read_text())['mcp_servers']['magicdesk']
    client = transport.Client(config['url'], config['http_headers']['Authorization'].removeprefix('Bearer '))
    state = client.call('get_state')
    assert state['shell']['uid'] == 2000
    tag = uuid.uuid4().hex
    base = '/data/local/tmp/md-namespace-apps-' + tag
    session = client.call('console.open', {'directory': '/data/local/tmp'})['sessionId']
    report = {'id': tag, 'directory': base, 'device': state['device'], 'app': state['app'],
              'store': args.store, 'checks': [], 'passed': False}

    def command(argv, marker=None, logged=False):
        text = shlex.join(map(str, argv))
        log = base + '/command.log'
        invocation = text + ' >' + shlex.quote(log) + ' 2>&1' if logged else text
        result = client.call('console.execute', {'sessionId': session, 'command': invocation})
        if logged:
            local = args.build / ('namespace-apps-' + tag + '-' + str(len(report['checks'])) + '.log')
            transport.download(client, log, local)
            result['output'] = local.read_text(errors='replace')
            result['log'] = str(local)
        passed = result['exitCode'] == 0 and (marker is None or marker in result['output'])
        report['checks'].append({'command': text, 'passed': passed, **result})
        print(result['output'], end='', flush=True)
        assert passed, text
        return result

    try:
        command(['mkdir', base])
        for name in ('bootstrap', 'supervisor', 'run', 'service'):
            filename = 'libmagicdesk_guest_' + name + '.so'
            destination = base + '/' + filename
            transport.upload(client, args.build / filename, destination)
            command(['chmod', '700', destination])
        command(['id'])
        run = [base + '/libmagicdesk_guest_run.so', '--store', args.store,
               '--user', '2000:2000', '--deadline-seconds', '60', '--diagnostics', '--']
        command(run + ['/usr/bin/bwrap', '--version'])
        trace = ['/usr/bin/strace', '-f', '-s', '160'] if args.trace else []
        # EVENT_WAIT: the runtime observes owned children; its deadline cancels
        # a stalled process tree rather than treating elapsed time as readiness.
        cases = {
            'pid-debugger': (['--unshare-pid', '--ro-bind', '/', '/', '--proc', '/proc',
                             '--dev-bind', '/dev', '/dev', '--tmpfs', '/tmp', '--',
                             '/usr/bin/gdb', '-nx', '-batch',
                             '-ex', 'set disable-randomization off', '-ex', 'starti',
                             '-ex', 'info inferiors', '-ex', 'continue', '--args', '/usr/bin/true'],
                            'exited normally'),
            'pid': (['--unshare-pid', '--ro-bind', '/', '/', '--proc', '/proc', '--dev-bind', '/dev', '/dev',
                     '--tmpfs', '/tmp', '--', '/bin/sh', '-exc',
                     'test -r /proc/1/status; test -r /proc/$$/status; '
                     'test "$(awk \'/^Pid:/{print $2}\' /proc/1/status)" = 1; '
                     'test -c /dev/null; printf test >/dev/null; '
                     'test "$(readlink /proc/1/ns/pid)" = "$(readlink /proc/self/ns/pid)"; '
                     'echo MD-BWRAP-PID'], 'MD-BWRAP-PID'),
            'basic': (['--bind', '/', '/', '--', '/usr/bin/id'], 'uid=2000'),
            'readonly': (['--ro-bind', '/', '/', '--tmpfs', '/tmp', '--', '/bin/sh', '-ec',
                          'printf writable >/tmp/probe; test "$(cat /tmp/probe)" = writable; '
                          'test -r /usr/bin/id; echo MD-BWRAP-READONLY'], 'MD-BWRAP-READONLY'),
            'identity': (['--uid', '0', '--gid', '0', '--hostname', 'shroot-private',
                          '--ro-bind', '/', '/', '--tmpfs', '/tmp', '--', '/bin/sh', '-ec',
                          'test "$(id -u)" = 0; test "$(id -g)" = 0; '
                          'test "$(uname -n)" = shroot-private; '
                          'if touch /forbidden-write; then exit 19; fi; '
                          'printf private >/tmp/probe; echo MD-BWRAP-IDENTITY'], 'MD-BWRAP-IDENTITY'),
            'nested': (['--hostname', 'outer-scope', '--ro-bind', '/', '/', '--tmpfs', '/tmp',
                        '--', '/bin/sh', '-ec',
                        'test "$(uname -n)" = outer-scope; printf outer >/tmp/outer; '
                        '/usr/bin/bwrap --unshare-user --unshare-uts --unshare-ipc '
                        '--hostname inner-scope --ro-bind / / --tmpfs /tmp -- /bin/sh -ec '
                        + shlex.quote('test "$(uname -n)" = inner-scope; test ! -e /tmp/outer; '
                                      'printf inner >/tmp/inner; test "$(cat /tmp/inner)" = inner')
                        + '; test "$(uname -n)" = outer-scope; test "$(cat /tmp/outer)" = outer; '
                          'test ! -e /tmp/inner; echo MD-BWRAP-NESTED'], 'MD-BWRAP-NESTED'),
        }
        for name, (arguments, marker) in cases.items():
            if args.case not in ('all', name):
                continue
            result = command(run + trace + ['/usr/bin/bwrap', '--unshare-user', '--unshare-uts',
                                           '--unshare-ipc'] + arguments, marker, logged=True)
            assert 'ptrace_syscall_info.op ==' not in result['output'], result['log']
        report['passed'] = True
    finally:
        client.call('console.close', {'sessionId': session})
        output = args.build / ('namespace-apps-' + tag + '.json')
        output.write_text(json.dumps(report, indent=2) + '\n')
        print('Report:', output, flush=True)


if __name__ == '__main__':
    main()

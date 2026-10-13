#!/usr/bin/env python3
"""Stock Podman/crun in a disposable prepared Linux store under shell UID.

The default exercises bridge networking and native overlay. Alternative storage
and network modes isolate failures; they do not certify the default workflow.
No seccomp/privilege bypass is passed to Podman or its container runtime.
"""
import argparse
import collections
import json
import os
from pathlib import Path
import resource
import subprocess
import sys


def guest(options):
    os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    report = {'options': options, 'commands': [], 'passed': False}
    base = Path(options['directory'])
    base.mkdir(parents=True, exist_ok=True)
    prefix = ['podman', '--log-level', 'debug', '--root', options['cache'],
              '--runroot', options['cache'] + '-run', '--storage-driver', options['storage']]
    limits = ['--cgroups', options['cgroups']]
    report['inheritedLimits'] = {}
    for name, kind in (('nofile', resource.RLIMIT_NOFILE), ('nproc', resource.RLIMIT_NPROC)):
        soft, hard = resource.getrlimit(kind)
        report['inheritedLimits'][name] = {'soft': soft, 'hard': hard}
        if options['hostLimits']:
            limits += ['--ulimit', f'{name}={soft}:{hard}']
    if options['unlimitedPids']:
        limits += ['--pids-limit', '-1']
    name = 'md-podman-probe'
    created = False

    def run(argv, timeout=90, required=True):
        print('RUN ' + repr(argv), flush=True)
        try:
            # EVENT_WAIT: exact child exit. The deadline fails the command.
            result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, timeout=timeout)
            item = {'argv': argv, 'exitCode': result.returncode, 'output': result.stdout}
        except subprocess.TimeoutExpired as error:
            item = {'argv': argv, 'timeout': True,
                    'output': (error.stdout or b'').decode(errors='replace')}
        report['commands'].append(item)
        print(item['output'], end='', flush=True)
        if required:
            assert item.get('exitCode') == 0, item
        return item

    try:
        run(['mount', '-t', 'sysfs', 'sysfs', '/sys'])
        run(['mount', '-t', 'cgroup2', 'none', '/sys/fs/cgroup'])
        run(prefix + ['info', '--format', 'json'])
        run(prefix + ['pull', options['image']], timeout=180)
        created = True
        command = prefix + ['run', '--rm', '--name', name, '--log-driver', 'k8s-file',
                            '--network', options['network'], *limits, options['image'],
                            '/bin/sh', '-ec', 'id; echo PODMAN_CONTAINER_OK']
        if options['trace']:
            command = ['strace', '-f', '-s', '180', '-e', 'trace=%file,%process,%network,%desc,prctl,seccomp,mount_setattr,prlimit64',
                       '-o', str(base / 'trace.log'), *command]
        result = run(command)
        assert 'PODMAN_CONTAINER_OK' in result['output'].splitlines(), result
        if options['network'] != 'none':
            result = run(prefix + ['run', '--rm', '--name', name, '--log-driver', 'k8s-file',
                          '--network', options['network'], *limits, options['image'], '/bin/sh', '-ec',
                          'wget -T 15 -qO /tmp/page http://example.com; test -s /tmp/page; echo PODMAN_INTERNET_OK'])
            assert 'PODMAN_INTERNET_OK' in result['output'].splitlines(), result
        report['passed'] = True
    except Exception as error:
        report['failure'] = repr(error)
    finally:
        if created:
            cleanup = run(prefix + ['rm', '-f', '--ignore', name], required=False)
            report['passed'] &= cleanup.get('exitCode') == 0
        trace = base / 'trace.log'
        if trace.exists():
            with trace.open(errors='replace') as source:
                report['traceTail'] = list(collections.deque(source, maxlen=120))
        print('PODMAN_REPORT ' + json.dumps(report), flush=True)


def main():
    from test_oci_services import Suite
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    parser.add_argument('--storage', choices=('overlay', 'vfs'), default='overlay')
    parser.add_argument('--network', choices=('bridge', 'host', 'none'), default='bridge')
    parser.add_argument('--cgroups', choices=('enabled', 'disabled'), default='enabled',
                        help='Explicit diagnostic mode; disabled does not certify cgroup support')
    parser.add_argument('--image', default='docker.io/library/alpine:3.23')
    parser.add_argument('--cache', default='', help='Owned disposable Podman image cache')
    parser.add_argument('--trace', action='store_true')
    parser.add_argument('--host-limits', action='store_true', help='Set nofile/nproc explicitly to inherited shell limits')
    parser.add_argument('--unlimited-pids', action='store_true', help='Explicitly disable the optional pids-controller limit')
    args = parser.parse_args()
    suite = Suite(Path('build/podman-results'), args.build)
    target = '/tmp/md-podman-probe-' + suite.report['id']
    runner = [suite.runner, '--store', args.store, '--user', '0:0', '--network', 'routed']
    created = False
    try:
        suite.transport.upload(suite.client, Path(__file__), suite.base + '/probe.py')
        suite.command(runner + ['--', '/bin/mkdir', target]); created = True
        options = {'directory': '/tmp/md-podman-' + suite.report['id'],
                   'cache': args.cache or '/tmp/md-podman-cache-' + suite.report['id'],
                   'storage': args.storage, 'network': args.network, 'image': args.image,
                   'cgroups': args.cgroups,
                   'trace': args.trace, 'hostLimits': args.host_limits, 'unlimitedPids': args.unlimited_pids}
        output = suite.command(runner + ['--bind-ro', suite.base, target, '--deadline-seconds', '300', '--',
                                        '/usr/bin/python3', target + '/probe.py', '--guest', json.dumps(options)], timeout=320)
        reports = [line.removeprefix('PODMAN_REPORT ') for line in output.splitlines() if line.startswith('PODMAN_REPORT ')]
        assert len(reports) == 1, output[-2000:]
        report = json.loads(reports[0]); suite.report['podman'] = report
        assert report['passed'], report.get('failure', 'container cleanup failed')
        suite.report['passed'] = True
    finally:
        try:
            if created:
                suite.command(runner + ['--', '/bin/rmdir', target])
        finally:
            suite.finish()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--guest':
        guest(json.loads(sys.argv[2]))
    else:
        main()

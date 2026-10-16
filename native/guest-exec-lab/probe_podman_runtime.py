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
import selectors
import signal
import subprocess
import sys


def guest(options):
    os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    report = {'options': options, 'commands': [], 'passed': False}
    base = Path(options['directory'])
    base.mkdir(parents=True, exist_ok=True)
    prefix = ['podman', '--log-level', 'info', '--root', options['cache'],
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
        if options['trace'] and argv[:len(prefix)] == prefix and argv[len(prefix):len(prefix)+1] in (['rm'], ['exec']):
            argv = ['strace', '-f', '-tt', '-T', '-s', '4096', '-e', 'trace=%network,%signal,%file,read,close,poll,ppoll,epoll_wait,epoll_pwait,pidfd_open,pidfd_send_signal',
                    '-o', str(base / f'trace-{len(report["commands"]):03d}.log'), *argv]
        try:
            # EVENT_WAIT: exact child exit. The deadline fails the command.
            result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, timeout=timeout)
            item = {'argv': argv, 'exitCode': result.returncode, 'output': result.stdout}
        except subprocess.TimeoutExpired as error:
            item = {'argv': argv, 'timeout': True,
                    'output': (error.stdout or b'').decode(errors='replace')}
        report['commands'].append(item)
        (base / 'progress.json').write_text(json.dumps(report))
        print(item['output'], end='', flush=True)
        if required:
            assert item.get('exitCode') == 0, item
        return item

    def trace_dns():
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit():
                continue
            try:
                args = (entry / 'cmdline').read_bytes().split(b'\0')
            except OSError:
                continue
            if b'/usr/libexec/podman/aardvark-dns' not in args:
                continue
            process = subprocess.Popen(['strace', '-f', '-tt', '-T', '-s', '2048', '-e',
                       'trace=%network,close,poll,ppoll,epoll_wait,epoll_pwait',
                       '-o', str(base / 'trace-dns.log'), '-p', entry.name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stderr, selectors.EVENT_READ)
                    # EVENT_WAIT: tracer attachment diagnostic, not a settling delay.
                    assert selector.select(10), 'DNS tracer did not attach'
                    line = process.stderr.readline()
                    assert b'attached' in line, line
                return process
            except BaseException:
                process.terminate()
                process.communicate(timeout=10)
                raise
        raise AssertionError('DNS service not found')

    def exercise_ports():
        from docker_network_fixture import observe, wait_service
        network = 'md-podman-ports'
        names = ('md-podman-first', 'md-podman-second')
        ports = []
        image = options['portsImage']
        if run(prefix + ['image', 'exists', image], required=False).get('exitCode') != 0:
            run(prefix + ['pull', image], timeout=180)
        if run(prefix + ['network', 'exists', network], required=False).get('exitCode') == 0:
            run(prefix + ['network', 'rm', '-f', network])
        run(prefix + ['network', 'create', '--subnet', '10.92.0.0/24', network])
        tracer = None
        try:
            for name in names:
                port = observe(options['observer'], operation='allocate')['port']
                ports.append(port)
                observe(options['observer'], operation='handoff', port=port)
                run(prefix + ['run', '-d', '--name', name, '--log-driver', 'k8s-file', '--network', network, *limits,
                              '-p', f'127.0.0.1:{port}:8080/tcp', '-p', f'127.0.0.1:{port}:8080/udp',
                              '--mount', 'type=bind,src=' + str(Path(__file__).with_name('docker_network_fixture.py'))
                              + ',dst=/fixture.py,readonly', image, 'python3', '/fixture.py', name])
                wait_service(prefix + ['logs', '-f', name])
                if options['trace'] and tracer is None:
                    tracer = trace_dns()
                report.setdefault('portChecks', []).append(observe(options['observer'], operation='exchange', port=port, token=name, repeats=20))
            for source, target in (names, tuple(reversed(names))):
                run(prefix + ['exec', source, 'python3', '/fixture.py', '--client', target, '8080', target, '20'])
            report['namedPeerExchangePassed'] = True
            outbound = observe(options['observer'], operation='outbound')['url']
            for name in names:
                run(prefix + ['exec', name, 'python3', '/fixture.py', '--http', outbound])
            report['localOutboundPassed'] = True
            if tracer:
                tracer.send_signal(signal.SIGINT)
                # EVENT_WAIT: detach while the multithreaded resolver remains
                # alive; its eventual shutdown cannot hide a lost interrupt.
                _, errors = tracer.communicate(timeout=10)
                assert tracer.returncode in (0, -signal.SIGINT), errors.decode(errors='replace')
                report['traceDetachPassed'] = True
                for source, target in (names, tuple(reversed(names))):
                    run(prefix + ['exec', source, 'python3', '/fixture.py', '--client', target, '8080', target, '20'])
            conflict = run(prefix + ['run', '--rm', '--name', 'md-podman-conflict', '--network', network,
                                    *limits, '-p', f'127.0.0.1:{ports[0]}:8080', image, '/bin/true'], required=False)
            assert conflict.get('exitCode') != 0 and ('already allocated' in conflict['output']
                    or 'address already in use' in conflict['output'].lower()), conflict
            if options['internet']:
                report['internetResults'] = [run(prefix + ['exec', name, 'python3', '/fixture.py', '--internet'],
                                                   required=False) for name in names]
                report['internetPassed'] = all(item.get('exitCode') == 0 for item in report['internetResults'])
        except Exception as error:
            report['portFailure'] = repr(error)
            run(['nft', 'list', 'ruleset'], required=False)
            run(['cat', '/etc/resolv.conf'], required=False)
            raise
        finally:
            try:
                removed = run(prefix + ['rm', '-f', '--ignore', *names, 'md-podman-conflict'], required=False)
                network_removed = run(prefix + ['network', 'rm', network], required=False)
            finally:
                if tracer:
                    try:
                        # EVENT_WAIT: DNS service exit drains its tracer too.
                        tracer.communicate(timeout=10)
                    except subprocess.TimeoutExpired:
                        tracer.kill()
                        tracer.communicate(timeout=10)
                        report['traceShutdownFailure'] = 'Tracer survived network teardown'
            if 'portFailure' not in report:
                assert removed.get('exitCode') == 0 and network_removed.get('exitCode') == 0, 'Network cleanup failed'
                assert 'traceShutdownFailure' not in report, report['traceShutdownFailure']
        for port in ports:
            report['portChecks'].append(observe(options['observer'], operation='released', port=port))
        report['portPublicationPassed'] = True

    try:
        run(['mount', '-t', 'sysfs', 'sysfs', '/sys'])
        run(['mount', '-t', 'cgroup2', 'none', '/sys/fs/cgroup'])
        run(prefix + ['info', '--format', 'json'])
        if run(prefix + ['image', 'exists', options['image']], required=False).get('exitCode') != 0:
            run(prefix + ['pull', options['image']], timeout=180)
        created = True
        command = prefix + ['run', '--rm', '--name', name, '--log-driver', 'k8s-file',
                            '--network', options['network'], *limits, options['image'],
                            '/bin/sh', '-ec', 'id; echo PODMAN_CONTAINER_OK']
        result = run(command)
        assert 'PODMAN_CONTAINER_OK' in result['output'].splitlines(), result
        if options['observer']:
            exercise_ports()
        if options['network'] != 'none' and options['internet']:
            result = run(prefix + ['run', '--rm', '--name', name, '--log-driver', 'k8s-file',
                          '--network', options['network'], *limits, options['image'], '/bin/sh', '-ec',
                          'wget -T 15 -qO /tmp/page http://example.com; test -s /tmp/page; echo PODMAN_INTERNET_OK'])
            assert 'PODMAN_INTERNET_OK' in result['output'].splitlines(), result
        if options['observer'] and options['internet']:
            assert report.get('internetPassed'), 'External DNS/HTTP failed; local matrix is recorded separately'
        report['passed'] = True
    except Exception as error:
        report['failure'] = repr(error)
    finally:
        if created:
            cleanup = run(prefix + ['rm', '-f', '--ignore', name], required=False)
            report['passed'] &= cleanup.get('exitCode') == 0
        report['traceErrors'] = []
        for trace in sorted(base.glob('trace-*.log')):
            report['traceErrors'] += [trace.name + ': ' + line for line in trace.read_text(errors='replace').splitlines()
                                     if 'EOPNOTSUPP' in line or 'operation not supported' in line.lower()
                                     or '\\241\\377' in line or '\\352\\377' in line or 'error=-' in line]
            with trace.open(errors='replace') as source:
                report['traceTail'] = list(collections.deque(source, maxlen=120))
        print('PODMAN_REPORT ' + json.dumps(report), flush=True)
        (base / 'progress.json').write_text(json.dumps(report))


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
    parser.add_argument('--exercise-ports', action='store_true')
    parser.add_argument('--ports-image', default='docker.io/library/python:3.14-alpine')
    parser.add_argument('--internet', action='store_true', help='Also require external DNS and HTTP')
    parser.add_argument('--host-limits', action='store_true', help='Set nofile/nproc explicitly to inherited shell limits')
    parser.add_argument('--unlimited-pids', action='store_true', help='Explicitly disable the optional pids-controller limit')
    args = parser.parse_args()
    if args.exercise_ports and args.network != 'bridge':
        parser.error('--exercise-ports requires bridge')
    suite = Suite(Path('build/podman-results'), args.build)
    from docker_network_fixture import Observer
    observer = Observer() if args.exercise_ports else None
    target = '/tmp/md-podman-probe-' + suite.report['id']
    runner = [suite.runner, '--store', args.store, '--user', '0:0', '--network', 'routed']
    created = False
    try:
        suite.transport.upload(suite.client, Path(__file__), suite.base + '/probe.py')
        suite.transport.upload(suite.client, Path(__file__).with_name('docker_network_fixture.py'),
                               suite.base + '/docker_network_fixture.py')
        suite.command(runner + ['--', '/bin/mkdir', target]); created = True
        options = {'directory': '/tmp/md-podman-' + suite.report['id'],
                   'cache': args.cache or '/tmp/md-podman-cache-' + suite.report['id'],
                   'storage': args.storage, 'network': args.network, 'image': args.image,
                   'cgroups': args.cgroups,
                   'internet': args.internet, 'portsImage': args.ports_image,
                   'trace': args.trace, 'hostLimits': args.host_limits, 'unlimitedPids': args.unlimited_pids,
                   'observer': observer.address if observer else ''}
        deadline = 900 if observer else 300
        output = suite.command(runner + ['--bind-ro', suite.base, target, '--deadline-seconds', str(deadline), '--',
                                        '/usr/bin/python3', target + '/probe.py', '--guest', json.dumps(options)], timeout=deadline+20)
        reports = [line.removeprefix('PODMAN_REPORT ') for line in output.splitlines() if line.startswith('PODMAN_REPORT ')]
        assert len(reports) == 1, output[-2000:]
        report = json.loads(reports[0]); suite.report['podman'] = report
        assert report['passed'], report.get('failure', 'container cleanup failed')
        suite.report['passed'] = True
    finally:
        if observer:
            observer.close()
            suite.report['externalPortChecks'] = observer.records
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

#!/usr/bin/env python3
"""Probe stock Docker Engine in a prepared disposable Debian Shroot store.

This records missing capabilities, not a passing Docker compatibility test.
The reduced-network profiles diagnose startup only; they do not validate -p.
Install docker.io and docker-cli in the store before running this probe.
"""
import argparse
import collections
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading


ROOTLESS_PROFILES = ('rootless', 'rootless-no-firewall', 'rootless-no-network')
PROFILES = ('default', 'no-network', *ROOTLESS_PROFILES)


def guest(profile, image, trace=False, cgroup='none', cgroupns='private', trace_runtime=False,
          no_new_keyring=False, trace_filesystem=False, create_count=0):
    os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    preparation = []
    def mount(*args):
        command = ['mount', *args]
        if trace:
            command = ['strace', '-f', '-s', '200', '-e',
                       'trace=mount,fsopen,fsconfig,fsmount,move_mount,mount_setattr', *command]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        preparation.append({'command': command,
                            'exitCode': result.returncode, 'output': result.stdout})
        if result.returncode:
            raise RuntimeError(preparation[-1])
    if cgroup != 'none':
        root = Path('/sys/fs/cgroup')
        root.mkdir(parents=True, exist_ok=True)
        if cgroup == 'v2':
            mount('-t', 'cgroup2', 'none', str(root))
        else:
            mount('-t', 'tmpfs', 'none', str(root))
            (root / 'devices').mkdir()
            mount('-t', 'cgroup', '-o', 'devices', 'none', str(root / 'devices'))
    base = Path(tempfile.mkdtemp(prefix='md-docker-'))
    endpoint = 'unix://' + str(base / 'docker.sock')
    argv = ['dockerd', '--debug', '--host', endpoint,
            '--pidfile', str(base / 'docker.pid'), '--data-root', str(base / 'data'),
            '--exec-root', str(base / 'run')]
    if profile in ROOTLESS_PROFILES:
        argv += ['--rootless', '--group', '0']
    if profile in ('no-network', 'rootless-no-firewall', 'rootless-no-network'):
        argv += ['--iptables=false', '--ip6tables=false', '--ip-forward=false',
                 '--ip-masq=false']
    if profile in ('no-network', 'rootless-no-network'):
        argv += ['--bridge=none', '--storage-driver=vfs']
    if trace_runtime or no_new_keyring:
        wrapper = base / 'runc-trace'
        wrapper.write_text('#!/usr/bin/python3\nimport os, sys\n'
                           'args = sys.argv[1:]\n'
                           + ('for i, arg in enumerate(args):\n'
                              '    if arg in ("create", "run"):\n'
                              '        args.insert(i + 1, "--no-new-keyring")\n'
                              '        break\n' if no_new_keyring else '')
                           + 'command = ["/usr/sbin/runc", *args]\n'
                           + ('command = ["/usr/bin/strace", "-D", "-f", "-s", "256", "-e", '
                              '"trace=%process,%file,%signal,%network,prctl,capget,capset,read,write,keyctl", "-o", '
                              + repr(str(base / 'runc-')) + ' + str(os.getpid()) + ".log", *command]\n'
                              if trace_runtime else '')
                           + 'os.execv(command[0], command)\n')
        wrapper.chmod(0o700)
        argv += ['--add-runtime=mdtrace=' + str(wrapper), '--default-runtime=mdtrace']
    if trace_filesystem:
        argv = ['strace', '-D', '-f', '-s', '256', '-e',
                'trace=%file,getdents64,lseek', '-o', str(base / 'filesystem.log'), *argv]
    elif trace:
        argv = ['strace', '-f', '-yy', '-s', '256', '-e', 'trace=fchown,fchownat', *argv]
    report = {'profile': profile, 'cgroup': cgroup, 'cgroupns': cgroupns, 'preparation': preparation,
              'newKeyringDisabled': no_new_keyring,
              'command': argv, 'directory': str(base),
              'apiReady': False, 'commands': [], 'portPublicationTested': False}
    records = queue.Queue()
    first, tail, important = [], collections.deque(maxlen=30), collections.deque(maxlen=60)
    log_count = 0
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, errors='replace')

    def drain():
        nonlocal log_count
        try:
            for line in process.stdout:
                log_count += 1
                if len(first) < 220:
                    first.append(line)
                else:
                    tail.append(line)
                if ('level=error' in line or 'failed to ' in line or '= -1 ' in line) and 'Error accepting connection' not in line:
                    important.append(line)
                if 'API listen on' in line:
                    records.put('ready')
        finally:
            records.put('eof')

    reader = threading.Thread(target=drain)
    reader.start()

    def client(*args):
        command = ['docker', '--host', endpoint, *args]
        try:
            # EVENT_WAIT: client completion; timeout fails this command.
            result = subprocess.run(command, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, timeout=90)
            item = {'command': command, 'exitCode': result.returncode,
                    'output': result.stdout[-20000:]}
        except subprocess.TimeoutExpired as error:
            item = {'command': command, 'timeout': True,
                    'output': (error.stdout or b'').decode(errors='replace')[-20000:]}
        report['commands'].append(item)
        return item.get('exitCode') == 0

    try:
        # EVENT_WAIT: daemon API log or output EOF; timeout is not readiness.
        event = records.get(timeout=45)
        if event == 'ready':
            report['apiReady'] = client('version', '--format', '{{json .Server}}')
            client('info', '--format', 'driver={{.Driver}} cgroup={{.CgroupDriver}} '
                   'memoryLimit={{.MemoryLimit}}')
            if report['apiReady'] and client('pull', image):
                for number in range(create_count):
                    name = 'md-copy-' + str(number)
                    if not client('create', '--name', name, '--network', 'none', '--cgroupns',
                                  cgroupns, image, '/bin/true'):
                        break
                    if not client('rm', name):
                        break
                for network in ('host', 'none'):
                    client('run', '--rm', '--network', network, '--cgroupns', cgroupns, image,
                           '/bin/sh', '-c', 'echo DOCKER_CONTAINER_EXECUTED; id')
        else:
            report['startupEnded'] = True
    except queue.Empty:
        report['startupTimeout'] = True
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            # EVENT_WAIT: Docker shutdown; escalation is scoped to this daemon.
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
            report['forcedShutdown'] = True
        reader.join(timeout=10)
        report['daemonExitCode'] = process.returncode
        report['logLines'] = log_count
        report['log'] = ''.join(first + list(tail))
        report['errors'] = list(important)
        report['readerDrained'] = not reader.is_alive()
        if trace_runtime:
            report['runtimeTraces'] = {}
            for path in sorted(base.glob('runc-*.log')):
                lines = path.read_text(errors='replace').splitlines()
                report['runtimeTraces'][path.name] = {
                    'lines': len(lines), 'tail': lines[-200:],
                    'errors': [line for line in lines if '= -1 ' in line][-100:]}
        if trace_filesystem:
            count, tail, conflicts = 0, collections.deque(maxlen=100), collections.deque(maxlen=60)
            recent, cleanup = collections.deque(maxlen=160), collections.deque(maxlen=6)
            following = 0
            with (base / 'filesystem.log').open(errors='replace') as stream:
                for line in stream:
                    count += 1
                    line = line.rstrip()
                    tail.append(line)
                    recent.append(line)
                    if following:
                        cleanup[-1]['lines'].append(line)
                        following -= 1
                    if 'EEXIST' in line:
                        conflicts.append(line)
                    if 'ENOTEMPTY' in line and not following:
                        cleanup.append({'at': count, 'lines': list(recent)})
                        following = 80
            report['filesystemTrace'] = {'lines': count, 'tail': list(tail), 'conflicts': list(conflicts),
                                         'cleanupFailures': list(cleanup)}
        print(json.dumps(report), flush=True)
        if reader.is_alive():
            os._exit(2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    parser.add_argument('--profile', choices=PROFILES, default='rootless-no-network')
    parser.add_argument('--image', default='busybox:1.37.0')
    tracing = parser.add_mutually_exclusive_group()
    tracing.add_argument('--trace', action='store_true')
    tracing.add_argument('--trace-runtime', action='store_true')
    tracing.add_argument('--trace-filesystem', action='store_true',
                        help='Record daemon file syscalls in the disposable guest directory')
    parser.add_argument('--create-count', type=int, default=0, choices=range(21),
                        help='Exercise repeated VFS layer creation/removal before starting containers')
    parser.add_argument('--no-new-keyring', action='store_true',
                        help='Diagnostic variant: runc inherits the session keyring instead of creating one')
    parser.add_argument('--cgroup', choices=('none', 'v2', 'devices'), default='none')
    parser.add_argument('--cgroupns', choices=('private', 'host'), default='private')
    args = parser.parse_args()
    from test_oci_services import Suite
    suite = Suite(args.build, args.build)
    suite.report.update(store=args.store, probe=True, profile=args.profile, cgroup=args.cgroup)
    target = '/tmp/md-docker-probe-' + suite.report['id']
    prefix = [suite.runner, '--store', args.store, '--user', '0:0']
    try:
        suite.transport.upload(suite.client, Path(__file__), suite.base + '/probe.py')
        suite.command(prefix + ['--', '/bin/mkdir', target])
        runner = prefix + ['--bind-ro', suite.base, target, '--deadline-seconds', '420', '--']
        suite.report['packages'] = suite.command(runner + ['/usr/bin/dpkg-query', '-W',
                                                          'docker.io', 'docker-cli', 'containerd', 'runc'])
        if args.profile in ROOTLESS_PROFILES:
            runner += ['/usr/bin/unshare', '--user', '--map-users=0:0:65536',
                       '--map-groups=0:0:65536', '--mount']
            # Mounting cgroups in a user namespace requires a cgroup namespace
            # owned by that user namespace, independently of Docker's setting.
            if args.cgroup != 'none':
                runner += ['--cgroup']
        output = suite.command(runner + ['/usr/bin/python3', target + '/probe.py', '--guest',
                                        args.profile, args.image, str(int(args.trace)), args.cgroup,
                                        args.cgroupns, str(int(args.trace_runtime)), str(int(args.no_new_keyring)),
                                        str(int(args.trace_filesystem)), str(args.create_count)], quiet=True, timeout=450)
        suite.report['probeResult'] = json.loads(output)
        print(json.dumps({key: value for key, value in suite.report['probeResult'].items()
                          if key != 'log'}, indent=2), flush=True)
    finally:
        try:
            suite.command(prefix + ['--', '/bin/rmdir', target])
        finally:
            suite.finish()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--guest':
        guest(sys.argv[2], sys.argv[3], bool(int(sys.argv[4])), sys.argv[5], sys.argv[6],
              bool(int(sys.argv[7])), bool(int(sys.argv[8])), bool(int(sys.argv[9])), int(sys.argv[10]))
    else:
        main()

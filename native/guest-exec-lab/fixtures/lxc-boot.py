#!/usr/bin/env python3
"""Boot an already prepared systemd rootfs under stock LXC common policy."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    name = 'md-lxc-' + uuid.uuid4().hex[:10]
    bridge = 'mdlxc' + uuid.uuid4().hex[:8]
    parent = Path('/var/lib/md-fixture-lxc')
    directory = parent / name
    root = directory / 'rootfs'
    root.mkdir(parents=True)
    report = dict(name=name, bridge=bridge, commands=[], passed=False)
    started = False
    connected = False

    def run(*argv, timeout=120, required=True):
        print('RUN', argv, flush=True)
        result = subprocess.run(list(map(str, argv)), capture_output=True, text=True, timeout=timeout)
        report['commands'].append(dict(argv=list(map(str, argv)), code=result.returncode,
                                      stdout=result.stdout, stderr=result.stderr))
        print(result.stdout + result.stderr, end='', flush=True)
        if required:
            assert result.returncode == 0, report['commands'][-1]
        return result

    def lxc(program, *argv, **kwargs):
        return run(program, '-n', name, '-P', parent, *argv, **kwargs)

    try:
        report['version'] = run('lxc-start', '--version').stdout
        run('tar', '-xpf', args.archive, '-C', root, timeout=300)
        run('ip', 'link', 'add', bridge, 'type', 'bridge')
        connected = True
        run('ip', 'link', 'set', bridge, 'up')
        (directory / 'config').write_text(
            'lxc.include = /usr/share/lxc/config/common.conf\n'
            'lxc.rootfs.path = dir:' + str(root) + '\n'
            'lxc.uts.name = ' + name + '\n'
            'lxc.net.0.type = veth\n'
            'lxc.net.0.link = ' + bridge + '\n'
            'lxc.net.0.flags = up\n'
            'lxc.net.0.name = eth0\n')
        report['config'] = (directory / 'config').read_text()
        log = args.report.with_suffix('.trace')
        started = True
        lxc('lxc-start', '-d', '-o', log, '-l', 'TRACE')
        lxc('lxc-wait', '-s', 'RUNNING', '-t', '60')
        result = lxc('lxc-attach', '--', '/bin/sh', '-ec',
                     'test "$(cat /proc/1/comm)" = systemd; '
                     'test "$(id -u)" = 0; cat /proc/self/status; '
                     'systemctl is-system-running --wait; echo LXC_BOOT_OK')
        assert 'LXC_BOOT_OK' in result.stdout and 'Seccomp:\t2' in result.stdout, result.stdout
        lxc('lxc-stop', '-t', '60', timeout=90)
        lxc('lxc-wait', '-s', 'STOPPED', '-t', '30')
        started = False
        report['passed'] = True
    finally:
        if started:
            lxc('lxc-stop', '-k', timeout=60, required=False)
        state = lxc('lxc-info', '-sH', required=False)
        stopped = state.returncode == 0 and state.stdout.strip() == 'STOPPED'
        if stopped:
            shutil.rmtree(directory)
        else:
            report['retainedRoot'] = str(directory)
        if connected:
            cleanup = run('ip', 'link', 'delete', bridge, required=False)
            report['bridgeCleanup'] = cleanup.returncode == 0
        report['stopped'] = stopped
        report['passed'] &= stopped and (not connected or report.get('bridgeCleanup', False))
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print('LXC_REPORT', args.report, 'passed=' + str(report['passed']), flush=True)


if __name__ == '__main__':
    main()

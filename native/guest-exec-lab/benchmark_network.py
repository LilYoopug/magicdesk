#!/usr/bin/env python3
"""Same static Linux executable: native shell, Shroot host/routed/filter/NAT.

Transport timing excludes warmup. Application CPU includes both echo processes;
a native wait4 wrapper records the invocation, including Shroot owners and nft setup.
Do not treat lifecycle CPU as transport-only CPU or compare runs under load.
"""
import argparse
import json
from pathlib import Path
import shlex
import statistics
import subprocess

from docker_network_fixture import Observer
from test_oci_services import Suite
from benchmark_cpu import observe_suite_cpu


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    parser.add_argument('--sysroot', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=5)
    args = parser.parse_args()
    root = args.sysroot.resolve()
    lib = root / 'usr/lib/aarch64-linux-gnu'
    gcc = root / 'usr/lib/gcc/aarch64-linux-gnu/14'
    binary = args.build / 'md-network-benchmark'
    subprocess.run(['clang', '--target=aarch64-linux-gnu', '--sysroot=' + str(root),
        '-isystem', str(root / 'usr/include/aarch64-linux-gnu'), '-fuse-ld=lld',
        '-std=c17', '-O2', '-Wall', '-Wextra', '-Werror', '-nostdlib', '-static', '-fno-pie',
        str(lib / 'crt1.o'), str(lib / 'crti.o'), str(gcc / 'crtbeginT.o'),
        str(Path(__file__).with_suffix('.c')), '-L' + str(lib), '-L' + str(gcc),
        '-Wl,--start-group', '-lc', '-lgcc', '-lgcc_eh', '-Wl,--end-group',
        str(gcc / 'crtend.o'), str(lib / 'crtn.o'), '-o', str(binary)], check=True)
    suite = Suite(Path('build/network-benchmark'), args.build)
    observer = Observer()
    prefix = [suite.runner, '--store', args.store, '--user', '0:0']
    target = '/tmp/md-network-benchmark-' + suite.report['id']
    samples = {mode: [] for mode in ('native', 'host', 'routed', 'filtered', 'nat')}
    created = False
    try:
        suite.transport.upload(suite.client, binary, suite.base + '/bench')
        suite.command(['chmod', '700', suite.base + '/bench'])
        suite.command(prefix + ['--', '/bin/mkdir', target])
        created = True
        # Rotate order to distribute thermal/drift effects across profiles.
        modes = list(samples)
        for iteration in range(args.rounds):
            for mode in modes[iteration % len(modes):] + modes[:iteration % len(modes)]:
                port = observer.allocate_port()
                front = observer.allocate_port()
                for sock in observer.reservations:
                    sock.close()
                observer.reservations.clear()
                rules = ''
                if mode in ('filtered', 'nat'):
                    rules = 'add table ip bench\nadd chain ip bench output { type filter hook output priority 0; policy accept; }\n'
                    rules += 'add rule ip bench output ct state invalid drop\n'
                if mode == 'nat':
                    rules += 'add chain ip bench translate { type nat hook output priority -100; policy accept; }\n'
                    for protocol in ('tcp', 'udp'):
                        rules += f'add rule ip bench translate {protocol} dport {front} dnat to 127.0.0.1:{port}\n'
                command = [suite.base + '/bench', str(port), str(front if mode == 'nat' else port)]
                if mode != 'native':
                    command[0] = target + '/bench'
                    script = ('printf %s ' + shlex.quote(rules) + ' | nft -f -\n' if rules else '')
                    script += 'exec ' + shlex.join(command)
                    command = prefix + ['--network', 'host' if mode == 'host' else 'routed',
                        '--bind-ro', suite.base, target, '--deadline-seconds', '90', '--', '/bin/sh', '-ec', script]
                with observe_suite_cpu(suite) as cpu_conditions:
                    output = suite.command([suite.base + '/bench', '--time', *command], timeout=110)
                result = json.loads(next(line.removeprefix('NETWORK_BENCH ') for line in output.splitlines()
                                         if line.startswith('NETWORK_BENCH ')))
                cpu = next(line.split()[1:] for line in output.splitlines() if line.startswith('NETWORK_CPU '))
                result['lifecycleCpuSeconds'] = sum(map(float, cpu))
                result['cpu'] = cpu_conditions
                samples[mode].append(result)
        suite.report['samples'] = samples
        suite.report['medians'] = {mode: {
            'tcpSeconds': statistics.median(row['tcp']['seconds'] for row in rows),
            'udpSeconds': statistics.median(row['udp']['seconds'] for row in rows),
            'lifecycleCpuSeconds': statistics.median(row['lifecycleCpuSeconds'] for row in rows),
            'applicationCpuSeconds': statistics.median(row['tcp']['applicationCpuSeconds'] +
                                                      row['udp']['applicationCpuSeconds'] for row in rows)
        } for mode, rows in samples.items()}
        print(json.dumps(suite.report['medians'], indent=2))
        suite.report['passed'] = True
    finally:
        observer.close()
        try:
            if created:
                suite.command(prefix + ['--', '/bin/rmdir', target])
        finally:
            suite.finish()


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Isolated real-musl correctness and paired native/kernel/cooperative timing."""
import argparse
import hashlib
import json
import re
import statistics
from pathlib import Path
from test_oci_services import Suite
import proot_fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('musl', type=Path)
    parser.add_argument('--rounds', type=int, default=5)
    parser.add_argument('--cpu-mask', default='3')
    parser.add_argument('--checks-only', action='store_true')
    parser.add_argument('--directory-mode', choices=('logical', 'imported'), default='logical')
    parser.add_argument('--workloads', nargs='+', choices=('metadata', 'metadata-absolute', 'metadata-dirfd',
                        'files', 'files-create', 'opens', 'opens-cloexec', 'opens-write', 'opens-create', 'opens-truncate', 'native'),
                        default=('metadata', 'metadata-absolute', 'metadata-dirfd', 'files', 'native'))
    parser.add_argument('--profile', action='store_true')
    parser.add_argument('--sample-statistics', action='store_true', help='Instrument every timed guest sample; do not mix with uninstrumented timings')
    parser.add_argument('--scale', type=int, default=1, help='Multiply workload iterations')
    parser.add_argument('--reference-build', type=Path, help='Interleave entry-enabled samples from another runtime build')
    parser.add_argument('--proot-prefix', type=Path, help='Stage installed PRoot for the same shell UID control')
    parser.add_argument('--condition', default='unspecified', help='Recorded measurement conditions, e.g. charging')
    args = parser.parse_args()
    if not 1 <= args.rounds <= 30 or not 1 <= args.scale <= 64 or not 0 < int(args.cpu_mask, 16) < 1 << 64:
        parser.error('invalid rounds, scale or CPU mask')
    suite = Suite(Path('build/cooperative-musl-results'), args.build)
    suite.report['conditions'] = dict(label=args.condition, cpuMask=args.cpu_mask,
                                     sampleStatistics=args.sample_statistics, scale=args.scale)
    try:
        root = suite.base + '/rootfs'
        native = suite.base + '/native'
        suite.command(['mkdir', '-p', root + '/bin', root + '/lib', native])
        if args.directory_mode == 'imported':
            suite.command(['mkdir', root + '/bench'])
        files = [(args.build / 'libmagicdesk_guest_service.so', suite.base + '/service'),
                 (args.musl / 'sysroot/lib/libc.so', root + '/lib/ld-musl-aarch64.so.1')]
        files += [(args.musl / ('probe-' + kind), root + '/bin/' + kind) for kind in ('static', 'dynamic')]
        suite.report['libcFixtureHashes'] = {}
        for source, target in files:
            with source.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            suite.transport.upload(suite.client, source, target)
            assert suite.command(['sha256sum', target], quiet=True).split()[0] == digest
            suite.report['libcFixtureHashes'][str(source)] = digest
            suite.command(['chmod', '700', target])
        for kind in ('static', 'dynamic'):
            command = [root + '/bin/' + kind, native, 'abi']
            if kind == 'dynamic':
                command.insert(0, root + '/lib/ld-musl-aarch64.so.1')
            output = suite.command(command)
            assert 'PASS musl ABI: absent provider' in output
        suite.command([suite.base + '/service', '--import', root, suite.base + '/store'])
        guest = [suite.runner, '--store', suite.base + '/store', '--user', '0:0', '--']
        reference = None
        if args.reference_build:
            directory = suite.base + '/reference'
            suite.command(['mkdir', directory])
            suite.report['referenceNativeHashes'] = suite.stage_runtime(args.reference_build, directory)
            suite.report['referenceBuild'] = str(args.reference_build)
            reference = directory + '/libmagicdesk_guest_run.so'
        if args.directory_mode == 'logical':
            suite.command([*guest, '/bin/static', '/bench', 'prepare'])
        suite.report['directoryKind'] = args.directory_mode
        def launch(mode):
            return [reference if mode == 'reference' else guest[0], *guest[1:-1],
                    '--env', 'SHROOT_COOPERATIVE=' + ('0' if mode == 'kernel' else '1')]

        guest_modes = ['kernel', 'entry'] + (['reference'] if reference else [])
        for kind in ('static', 'dynamic'):
            for mode in guest_modes:
                output = suite.command([*launch(mode), '--statistics', '--', '/bin/' + kind, '/bench', 'check'])
                assert 'PASS musl: real libc metadata, threads, cancellation, signal longjmp, fork/exec and seccomp' in output
                assert 'PASS musl FD:' in output and 'PASS musl paths:' in output
                assert 'PASS musl cancellation:' in output
                counters = re.search(r'cooperativeCompleted=(\d+)', output)
                assert counters, 'missing entry statistics'
                completed = int(counters[1])
                assert completed == 0 if mode == 'kernel' else completed >= 4000, 'wrong libc route'
                descriptors = re.search(r'cooperativeDescriptors=(\d+)', output)
                assert descriptors and (int(descriptors[1]) == 0 if mode == 'kernel' else int(descriptors[1]) >= 128)
                if mode == 'entry':
                    plans = re.search(r'nativeOpen=(\d+) nativeClose=(\d+) nativeFlags=(\d+)', output)
                    assert plans and all(int(n) > 0 for n in plans.groups()), 'native FD plans were not exercised'
        proot = None
        if args.proot_prefix:
            invocation = proot_fixture.stage(suite, args.proot_prefix)
            suite.command(['mkdir', '-p', root + '/bench', root + '/proc', root + '/dev'])
            # Both controls use the same underlying directory and exact static binary.
            native = root + '/bench'
            prefix = ['--kill-on-exit', '-0', '-r', root, '-b', '/proc', '-b', '/dev', '-w', '/bench']
            diagnostic = suite.command(invocation + ['-v', '1', *prefix, '/bin/static', '/bench', 'opens', '1'], quiet=True)
            assert 'ptrace acceleration (seccomp mode 2,' in diagnostic
            suite.report['proot']['seccompDiagnostic'] = diagnostic
            proot = invocation + prefix + ['/bin/static', '/bench']
        samples = []
        suite.report['samples'] = samples
        modes = ['native', *(['proot'] if proot else []), *guest_modes]
        counts = dict(metadata=32768, **{'metadata-absolute': 32768, 'metadata-dirfd': 32768, 'opens-cloexec': 4096,
                      'opens-write': 4096, 'opens-create': 4096, 'opens-truncate': 4096, 'files-create': 2048},
                      files=2048, opens=4096, native=65536)
        for workload in (() if args.checks_only else args.workloads):
            count = counts[workload] * args.scale
            for round_number in range(args.rounds):
                for mode in modes[round_number % len(modes):] + modes[:round_number % len(modes)]:
                    if mode == 'native':
                        command = [root + '/bin/static', native, workload, str(count)]
                    elif mode == 'proot':
                        command = [*proot, workload, str(count)]
                    else:
                        command = [*launch(mode), *(['--statistics'] if args.sample_statistics else []),
                                   '--', '/bin/static', '/bench', workload, str(count)]
                    output = suite.command(['taskset', args.cpu_mask, *command], quiet=True)
                    record = next(json.loads(line) for line in output.splitlines() if line.startswith('{"workload"'))
                    record.update(mode=mode, round=round_number)
                    if args.sample_statistics:
                        record['statistics'] = [line for line in output.splitlines() if line.startswith('MD_')]
                    samples.append(record)
                    print(json.dumps({k: v for k, v in record.items() if k != 'statistics'}), flush=True)
            if args.profile:
                for mode in guest_modes:
                    suite.command(['taskset', args.cpu_mask, *launch(mode), '--statistics', '--',
                                   '/bin/static', '/bench', workload, str(count)])
        suite.report['mediansMs'] = {
            workload: {mode: statistics.median(r['nanoseconds'] for r in samples
                                               if r['mode'] == mode and r['workload'] == workload) / 1e6
                       for mode in modes}
            for workload in sorted({r['workload'] for r in samples})}
        suite.report['pairedRatios'] = {}
        for workload in suite.report['mediansMs']:
            rounds = [{r['mode']: r['nanoseconds'] for r in samples
                       if r['workload'] == workload and r['round'] == number}
                      for number in range(args.rounds)]
            suite.report['pairedRatios'][workload] = {
                control: statistics.median(r['entry'] / r[control] for r in rounds)
                for control in ('native', *(['proot'] if proot else []), 'kernel', *(['reference'] if reference else []))}
        print(json.dumps(suite.report['mediansMs'], indent=2))
        print('Entry paired ratios:', json.dumps(suite.report['pairedRatios']))
        for source, _ in files:
            with source.open('rb') as stream:
                assert hashlib.file_digest(stream, 'sha256').hexdigest() == suite.report['libcFixtureHashes'][str(source)], \
                    'fixture changed during runtime checks'
        suite.report['libcFixturesUnchanged'] = True
        suite.report['passed'] = True
        suite.command(['rm', '-rf', suite.base])
    finally:
        suite.finish()


if __name__ == '__main__':
    main()

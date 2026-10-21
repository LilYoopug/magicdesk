#!/usr/bin/env python3
"""SVC-only entry and concurrent code publication, without peer patch stops."""
import argparse
import hashlib
import json
import re
from pathlib import Path
from test_oci_services import Suite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('--native-only', action='store_true')
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--benchmarks', action='store_true')
    parser.add_argument('--signal-proof', action='store_true')
    parser.add_argument('--workload', choices=('stat', 'opens', 'mutations'), default='stat')
    parser.add_argument('--cpu-mask', help='Optional taskset mask for benchmarks only')
    parser.add_argument('--case', choices=('all', 'lifetime', 'mapping', 'protection', 'entry', 'mirror', 'mirror-fork', 'mirror-filter', 'mirror-live', 'mirror-denied', 'cold-syscall', 'cold-filter', 'cold-trap', 'cold-restart'), default='all')
    args = parser.parse_args()
    assert 1 <= args.rounds <= 20
    assert not args.cpu_mask or args.benchmarks and 0 < int(args.cpu_mask, 16) < 1 << 64
    assert args.benchmarks or args.workload == 'stat'
    assert args.case not in ('cold-trap', 'cold-restart') or args.signal_proof
    suite = Suite(Path('build/svc-live-results'), None if args.native_only else args.build)
    suite.report['runs'] = []
    try:
        root = suite.base + '/root'
        suite.command(['mkdir', '-p', root + '/bin', root + '/tmp'])
        binary = args.build / 'libmagicdesk_guest_test_svc_live.so'
        suite.report['fixtureHash'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        suite.transport.upload(suite.client, binary, root + '/bin/live')
        suite.command(['chmod', '700', root + '/bin/live'])
        commands = [('native', [root + '/bin/live', root + '/tmp'])]
        if not args.native_only:
            service = args.build / 'libmagicdesk_guest_service.so'
            suite.transport.upload(suite.client, service, suite.base + '/service')
            suite.command(['chmod', '700', suite.base + '/service'])
            suite.command([suite.base + '/service', '--import', root, suite.base + '/store', '--preserve-ownership'])
            commands.append(('guest', [suite.runner, '--env', 'SHROOT_MACHINE_ENTRY=0', '--statistics', '--store', suite.base + '/store', '--user', '0:0',
                                       *(['--env', 'MD_SVC_SIGNAL_PROOF=1'] if args.signal_proof else []),
                                       '--', '/bin/live', '/tmp']))
        for round_number in range(args.rounds):
            for owner, command in commands:
                modes = ['bench-base', 'bench-callback', 'bench-direct', 'bench-owned', 'bench-mirror', 'bench-signals'] if args.benchmarks else [
                    'check', 'collision', 'filter', 'filter-signals', 'live', 'overflow', 'lifetime', 'protection', 'mapping', 'entry', 'mirror', 'mirror-fork', 'mirror-filter', 'mirror-live', 'mirror-denied', 'cold-syscall', 'cold-filter']
                if args.signal_proof and not args.benchmarks:
                    modes.extend(('cold-trap', 'cold-restart'))
                if args.case != 'all':
                    assert not args.benchmarks
                    modes = [args.case]
                if args.benchmarks and round_number % 2:
                    modes.reverse()
                for mode in modes:
                    prefix = ['taskset', args.cpu_mask] if args.cpu_mask else []
                    output = suite.command([*prefix, *command, mode, args.workload], timeout=180, quiet=True)
                    for line in output.splitlines():
                        if line.startswith(('SVC_', 'FILTER_STATE', 'MD_QUIESCENCE')):
                            print(line, flush=True)
                    sample, = [json.loads(line[len('SVC_LIVE '):]) for line in output.splitlines()
                               if line.startswith('SVC_LIVE ')]
                    assert sample['provider'] == (owner == 'guest')
                    assert sample['workload'] == args.workload
                    assert sample['peerStops'] == 0
                    assert sample['completed'] if owner == 'guest' else sample['nativeCompleted']
                    if owner == 'guest':
                        quiescence, = re.findall(r'MD_QUIESCENCE interrupts=(\d+) memoryRepairs=(\d+)', output)
                        sample.update(quiesceInterrupts=int(quiescence[0]), memoryRepairs=int(quiescence[1]))
                        if mode in ('lifetime', 'mapping', 'live', 'entry', 'mirror', 'mirror-fork', 'mirror-filter', 'mirror-live', 'mirror-denied', 'cold-syscall', 'cold-filter', 'cold-trap', 'cold-restart'):
                            assert sample['quiesceInterrupts'] == 0 and sample['memoryRepairs'] == 0
                    if mode in ('check', 'collision', 'filter', 'filter-signals', 'mirror-filter'):
                        assert sample['retired'] == 1 and sample['misses'] == 1
                    elif mode in ('live', 'mirror-live'):
                        assert sample['peerCalls'] > 0 and sample['misses'] == 0
                        assert sample['publications'] == 30001 and sample['retired'] == 0
                    elif mode == 'overflow':
                        assert sample['peerCalls'] > 0
                        if owner == 'guest':
                            assert sample['retired'] == 1 and sample['misses'] > 0
                    elif mode in ('lifetime', 'mapping', 'mirror', 'mirror-fork'):
                        assert sample['misses'] == 0 and sample['retired'] == 0 and sample['peerCalls'] > 0
                    elif mode in ('cold-syscall', 'cold-filter', 'cold-trap', 'cold-restart'):
                        assert sample['misses'] == 0 and sample['retired'] == 0
                        completed = sample['completed'] if owner == 'guest' else sample['nativeCompleted']
                        assert completed == (2 if mode == 'cold-syscall' else 1)
                        if mode == 'cold-trap' and owner == 'guest':
                            signals, = [json.loads(line[len('SVC_SIGNALS '):]) for line in output.splitlines()
                                        if line.startswith('SVC_SIGNALS {')]
                            assert signals['kernelAliases'] == 1
                        if mode == 'cold-restart' and owner == 'guest':
                            signals, = [json.loads(line[len('SVC_SIGNALS '):]) for line in output.splitlines()
                                        if line.startswith('SVC_SIGNALS {')]
                            assert signals['kernelEntries'] >= 3
                    elif mode.startswith('bench-'):
                        assert sample['retired'] == 0 and sample['misses'] == 0
                        completed = sample['completed'] if owner == 'guest' else sample['nativeCompleted']
                        iterations, calls = {'stat': (32768, 1), 'opens': (4096, 2), 'mutations': (1024, 4)}[args.workload]
                        assert sample['iterations'] == iterations and sample['callsPerIteration'] == calls
                        assert completed == (1 if mode == 'bench-base' else 1 + (iterations + 128) * calls)
                    sample.update(owner=owner, round=round_number, cpuMask=args.cpu_mask)
                    suite.report['runs'].append(sample)
                if not args.benchmarks:
                    if args.case in ('all', 'lifetime'):
                        suite.command([*command, 'lifetime-unsafe'], timeout=180, expected=139)
                    if args.case in ('all', 'mapping'):
                        suite.command([*command, 'mapping-unsafe'], timeout=180, expected=92)
                    if args.case in ('all', 'entry'):
                        suite.command([*command, 'entry-unsafe'], timeout=180, expected=139)
                    if args.case in ('all', 'mirror-fork'):
                        suite.command([*command, 'mirror-fork-shared'], timeout=180, expected=94)
                    if args.case in ('all', 'cold-syscall'):
                        suite.command([*command, 'cold-blocked-unsafe'], timeout=180, expected=133)
                    if args.case in ('all', 'cold-filter'):
                        suite.command([*command, 'cold-filter-unsafe'], timeout=180, expected=159)
                    if args.signal_proof and owner == 'guest' and args.case in ('all', 'cold-trap'):
                        suite.command([*command, 'cold-trap-unsafe'], timeout=180, expected=97)
                    if args.signal_proof and owner == 'guest' and args.case in ('all', 'cold-restart'):
                        suite.command([*command, 'cold-restart-unsafe'], timeout=180, expected=97)
                    if args.signal_proof and args.case in ('all', 'cold-restart'):
                        suite.command([*command, 'cold-restart-unprojected'], timeout=180, expected=159)
        suite.report['passed'] = True
        suite.command(['rm', '-rf', suite.base])
    finally:
        suite.finish()


if __name__ == '__main__':
    main()

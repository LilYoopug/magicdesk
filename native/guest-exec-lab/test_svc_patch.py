#!/usr/bin/env python3
"""Separate code-patch transparency, entry cost, and actual acceleration coverage."""
import argparse
import hashlib
import json
import re
import statistics
from pathlib import Path
from test_oci_services import Suite
from audit_svc_payload import audit


def records(output, prefix):
    return [json.loads(line[len(prefix):]) for line in output.splitlines() if line.startswith(prefix)]


def census(suite, program, mode, root, native):
    output = suite.command([root + '/bin/tracer', mode, root + '/bin/' + program, native],
                           quiet=True, timeout=180)
    markers = {'raw': 'PASS raw assembly:', 'go-stress': 'PASS Go stress:',
               'fault': 'PASS SVC fault:', 'mapping': 'PASS SVC mapping:'}
    assert markers[program] in output
    totals, = records(output, 'SVC_TOTAL ')
    sites = records(output, 'SVC_SITE ')
    assert totals['exit'] == 0 and not totals['overflow'] and not totals['unreadable']
    assert not totals['probeFailures'], 'hardware witness unavailable; do not claim executed-prefix coverage'
    assert all(not s['patched'] or s['witnessed'] for s in sites)
    if program == 'fault' and mode != 'observe':
        fault, = records(output, 'SVC_FAULT ')
        fault_site, = [s for s in sites if s['pc'] == fault['pc']]
        assert fault_site['patched'] and fault_site['kind'] == 3 and fault['faults'] == 1
        if mode == 'count': assert fault_site['stubVisits'] > 1
    if mode == 'count':
        assert sum(s['stubVisits'] for s in sites) > (1000 if program != 'fault' else 0)
        if program == 'raw':
            hot = sorted([s for s in sites if s['calls'] == 2000], key=lambda s: int(s['pc'], 16))
            assert len(hot) == 7 and all(s['patched'] and s['stubVisits'] for s in hot[:6])
            assert abs(hot[5]['patchedSiteCalls'] - 2*hot[5]['stubVisits']) <= 1, 'incoming edge not counted'
            assert not hot[6]['patched'] and not hot[6]['witnessed'], 'adjacent literal was treated as code'
        if program == 'mapping':
            assert sum(s['retired'] for s in sites) >= 3, 'code replacement not rediscovered'
    suite.report['census'].append(dict(program=program, mode=mode, totals=totals, sites=sites,
                                      syscalls=records(output, 'SVC_NR ')))
    print(program, mode, 'calls', totals['calls'], 'patched sites', sum(s['patchedSiteCalls'] for s in sites),
          'actual visits', sum(s['stubVisits'] for s in sites),
          'zero TLS', sum(s['zeroTls'] for s in sites), flush=True)


def edge_run(suite, command, provider, proof, sandbox, round_number):
    if sandbox: command = [*command, 'sandbox']
    output = suite.command(command, quiet=True, timeout=180)
    totals, = records(output, 'SVC_TOTAL ')
    evidence, = records(output, 'SVC_EDGE_STATS ')
    assert 'PASS Go stress:' in output and totals['exit'] == 0
    assert evidence['detached'] and evidence['provider'] == provider and not evidence['unknown']
    assert (evidence['completed'] > 1000) if provider else (evidence['completed'] == 0)
    assert not totals['probeFailures']
    signals = records(output, 'SVC_SIGNALS ')
    if proof and provider:
        assert len(signals) == 1 and signals[0]['deferred'] == signals[0]['delivered']
        assert signals[0]['deferred'] > 0
    if sandbox:
        assert 'PASS Go sandbox:' in output
        if provider: assert evidence['revoked'] == 1
    suite.report['edgeRuns'].append(dict(round=round_number, sandbox=sandbox, provider=provider,
                                        totals=totals, evidence=evidence, signals=signals))
    print('Go call edge', round_number, 'sandbox' if sandbox else 'plain', evidence, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('go', type=Path)
    parser.add_argument('--rounds', type=int, default=5)
    parser.add_argument('--checks-only', action='store_true')
    parser.add_argument('--benchmarks-only', action='store_true')
    parser.add_argument('--entry-only', action='store_true', help='skip the independent ptrace census')
    parser.add_argument('--nested-tracer', action='store_true', help='exercise guest ptrace, not a second host tracer')
    parser.add_argument('--edge-only', action='store_true', help='stock Go with witnessed call-edge entry, then debugger detach')
    parser.add_argument('--signal-proof', action='store_true', help='enable the separately compiled supervisor signal-window experiment')
    parser.add_argument('--cpu-mask', default='3')
    parser.add_argument('--condition', default='unspecified')
    parser.add_argument('--integrated', action='store_true', help='existing contracts through the ordinary supervisor, without a discovery tracer')
    args = parser.parse_args()
    assert 1 <= args.rounds <= 20
    assert not (args.checks_only and args.benchmarks_only)
    suite = Suite(Path('build/svc-patch-results'), args.build)
    suite.report['samples'] = []
    suite.report['census'] = []
    suite.report['condition'] = args.condition
    suite.report['cpuMask'] = args.cpu_mask
    suite.report['checksOnly'] = args.checks_only
    suite.report['benchmarksOnly'] = args.benchmarks_only
    suite.report['fixtureHashes'] = {}
    suite.report['payloadAudit'] = audit(args.build)
    try:
        suite.report['kernel'] = suite.command(['uname', '-a'], quiet=True).strip()
        root = suite.base + '/root'
        native = suite.base + '/native'
        suite.command(['mkdir', '-p', root + '/bin', root + '/tmp', native])
        for name, target in [('test_svc_patch', suite.base + '/planner'),
                             ('trace_svc_patch', root + '/bin/tracer'),
                             ('test_svc_raw', root + '/bin/raw'),
                             ('test_svc_fault', root + '/bin/fault'),
                             ('test_svc_mapping', root + '/bin/mapping'),
                             ('test_process_image', root + '/bin/process-image'),
                             ('test_svc_gate', root + '/bin/gate'),
                             ('service', suite.base + '/service')]:
            binary = args.build / ('libmagicdesk_guest_' + name + '.so')
            suite.report['fixtureHashes'][name] = hashlib.sha256(binary.read_bytes()).hexdigest()
            suite.transport.upload(suite.client, binary, target)
            assert suite.command(['sha256sum', target], quiet=True).split()[0] == suite.report['fixtureHashes'][name]
            suite.command(['chmod', '700', target])
        suite.transport.upload(suite.client, args.go, root + '/bin/go-stress')
        suite.report['fixtureHashes']['go-stress'] = hashlib.sha256(args.go.read_bytes()).hexdigest()
        assert suite.command(['sha256sum', root + '/bin/go-stress'], quiet=True).split()[0] == suite.report['fixtureHashes']['go-stress']
        suite.command(['chmod', '700', root + '/bin/go-stress'])
        if not args.benchmarks_only and not args.edge_only and not args.integrated:
            suite.command([suite.base + '/planner'])
            suite.command([root + '/bin/gate', native, 'check'])
            suite.command([root + '/bin/gate', native, 'integer-check'])
            suite.command([root + '/bin/gate', native, 'borrowed-check'])
            suite.command([root + '/bin/gate', native, 'pair-check'])
            suite.command([root + '/bin/gate', native, 'edge-check'])
            suite.command([root + '/bin/gate', native, 'single-check'])
            for mode in ('stack-base', 'stack-patch', 'stack-borrowed', 'stack-pair', 'stack-edge'):
                suite.command([root + '/bin/gate', native, mode])
            if not args.entry_only:
                suite.command([root + '/bin/go-stress', native], timeout=60)
                for program in ('raw', 'fault', 'mapping', 'go-stress'):
                    for mode in ('observe', 'forward', 'count'):
                        census(suite, program, mode, root, native)
        suite.command([suite.base + '/service', '--import', root, suite.base + '/store', '--preserve-ownership'])
        guest = [suite.runner, '--store', suite.base + '/store', '--user', '0:0']
        if args.integrated:
            suite.command([suite.base + '/planner'])
            rejected = suite.command([*guest, '--env', 'SHROOT_MACHINE_ENTRY=invalid',
                                      '--', '/bin/raw'], quiet=True, expected=126)
            assert 'SHROOT_MACHINE_ENTRY must be 0 or 1' in rejected
            base_output = suite.command([*guest, '--env', 'SHROOT_MACHINE_ENTRY=0',
                                         '--statistics', '--', '/bin/raw', '/tmp'], quiet=True)
            assert 'PASS raw assembly:' in base_output
            assert not records(base_output, 'SVC_RUNTIME_STATS ')
            assert re.search(r'cooperativeCompleted=0\b', base_output), base_output
            suite.report['runtimeRuns'] = []
            native_filter = suite.command([root + '/bin/mapping', 'filter-race'], quiet=True, timeout=180)
            assert 'PASS SVC filter race:' in native_filter
            for command in ([root + '/bin/mapping'], [*guest, '--env', 'SHROOT_MACHINE_ENTRY=0', '--', '/bin/mapping']):
                output = suite.command(command, quiet=True, timeout=60)
                assert 'PASS SVC mapping: ELF protection' in output
            filter_output = suite.command([*guest, '--statistics',
                                           '--deadline-seconds', '150', '--', '/bin/mapping', 'filter-race'],
                                          quiet=True, timeout=180)
            assert 'PASS SVC filter race:' in filter_output
            fences, drains = map(int, re.search(r'MD_ENTRY_FENCE transitions=(\d+) drains=(\d+)', filter_output).groups())
            assert fences == 24 and drains > 0, filter_output
            suite.report['filterFence'] = dict(installs=fences, drains=drains)
            suite.report['filterRace'] = records(filter_output, 'SVC_RUNTIME_STATS ')
            assert any(item['completed'] > 128 and item['revoked'] for item in suite.report['filterRace'])
            print('Integrated filter race PASS', flush=True)
            for command in ([root + '/bin/mapping'], [*guest, '--env', 'SHROOT_MACHINE_ENTRY=0', '--'],
                            [*guest, '--statistics', '--']):
                if command[-1] == '--':
                    command += ['/bin/mapping']
                output = suite.command([*command, 'protected-race'], quiet=True, timeout=180)
                assert 'PASS SVC protected race:' in output
                if '--statistics' in command:
                    fences, drains = map(int, re.search(
                        r'MD_ENTRY_FENCE transitions=(\d+) drains=(\d+)', output).groups())
                    assert fences == 24 and drains > 0, output
                    suite.report['protectedFence'] = dict(transitions=fences, drains=drains)
                    evidence = records(output, 'SVC_RUNTIME_STATS ')
                    assert any(item['completed'] > 128 and item['revoked'] for item in evidence)
            print('Integrated protected race PASS', flush=True)
            for command in ([root + '/bin/process-image'], [*guest, '--env', 'SHROOT_MACHINE_ENTRY=0', '--', '/bin/process-image'],
                            [*guest, '--statistics', '--', '/bin/process-image']):
                for mode in (['protected'] if len(command)==1 else ['protected', 'protected-other-user']):
                    output = suite.command([*command, mode], quiet=True, timeout=60)
                    assert 'PASS protected process image:' in output
            print('Protected cmdline/auxv native, Base and lazy PASS', flush=True)
            runs = [('raw', False), ('mapping', False)]
            runs += [('go-stress', sandbox) for _ in range(args.rounds) for sandbox in (False, True)]
            for program, sandbox in runs:
                output = suite.command([*guest, '--statistics',
                                        '--deadline-seconds', '150', '--', '/bin/' + program, '/tmp',
                                        *(['sandbox'] if sandbox else [])], quiet=True, timeout=180)
                marker = {'raw': 'PASS raw assembly:', 'mapping': 'PASS SVC mapping:',
                          'go-stress': 'PASS Go stress:'}[program]
                assert marker in output
                if sandbox: assert 'PASS Go sandbox:' in output
                evidence = records(output, 'SVC_RUNTIME_STATS ')
                assert evidence and not any(item['unknown'] for item in evidence), output
                if program == 'go-stress':
                    assert any(item['completed'] > 1000 for item in evidence), output
                if program == 'mapping':
                    assert any(item['completed'] >= 64 for item in evidence), output
                    repairs = re.search(r'memoryRepairs=(\d+)', output)
                    assert repairs, output
                    suite.report['elfProtectionRepairs'] = int(repairs[1])
                suite.report['runtimeRuns'].append(dict(program=program, sandbox=sandbox, evidence=evidence))
                print('Integrated', program, 'sandbox=' + str(sandbox), 'PASS', flush=True)
            suite.report['passed'] = True
            suite.command(['rm', '-rf', suite.base])
            return
        # The experimental tracer owns patching; do not enable a second owner.
        guest += ['--env', 'SHROOT_MACHINE_ENTRY=0']
        if args.signal_proof:
            guest += ['--env', 'MD_SVC_SIGNAL_PROOF=1']
        if args.edge_only:
            suite.report['edgeRuns'] = []
            commands = ((False, [root + '/bin/tracer', 'edge', root + '/bin/go-stress', native]),
                        (True, [*guest, '--', '/bin/tracer', 'edge', '/bin/go-stress', '/tmp']))
            for round_number in range(args.rounds):
                for provider, command in commands:
                    edge_run(suite, command, provider, args.signal_proof,
                             args.signal_proof and round_number % 2 == 1, round_number)
        if args.nested_tracer:
            suite.command([*guest, '--', '/bin/gate', '/tmp', 'base', 'stat', '1'])
            output = suite.command([*guest, '--', '/bin/tracer', 'forward', '/bin/go-stress', '/tmp'],
                                   quiet=True, timeout=180)
            totals, = records(output, 'SVC_TOTAL ')
            assert not totals['exit'] and 'PASS Go stress:' in output
            suite.report['nestedTracer'] = totals
        if not args.benchmarks_only and not args.edge_only:
            output = suite.command([*guest, '--statistics', '--', '/bin/gate', '/tmp', 'check'])
            assert 'PASS SVC gate:' in output
            suite.command([*guest, '--', '/bin/gate', '/tmp', 'integer-check'])
            suite.command([*guest, '--', '/bin/gate', '/tmp', 'borrowed-check'])
            suite.command([*guest, '--', '/bin/gate', '/tmp', 'pair-check'])
            suite.command([*guest, '--', '/bin/gate', '/tmp', 'edge-check'])
            suite.command([*guest, '--', '/bin/gate', '/tmp', 'single-check'])
            suite.command([*guest, '--', '/bin/gate', '/tmp', 'stack-borrowed'])
            suite.command([*guest, '--', '/bin/gate', '/tmp', 'stack-pair'])
            suite.command([*guest, '--', '/bin/gate', '/tmp', 'stack-edge'])
            # The stock Go control verifies Shroot Base independently; do not count
            # its forwarding-only run above as cooperative acceleration.
            suite.command([*guest, '--', '/bin/go-stress', '/tmp'], timeout=120)
        modes = ('native', 'native-patch', 'base', 'source', 'patch', 'integer', 'borrowed', 'pair', 'edge')
        workloads = [] if args.checks_only or args.edge_only else [('stat', 32768, False), ('opens', 4096, False),
                                                ('mutations', 1024, False), ('stat', 4096, True)]
        for workload, count, sandbox in workloads:
            for round_number in range(args.rounds):
                rotation = round_number // 2 % len(modes)
                order = modes[rotation:] + modes[:rotation]
                if round_number % 2: order = order[::-1]
                for mode in order:
                    if mode.startswith('native'):
                        command = [root + '/bin/gate', native, 'patch' if mode == 'native-patch' else 'base']
                    else:
                        command = [*guest, '--', '/bin/gate', '/tmp', mode]
                    output = suite.command(['taskset', args.cpu_mask, *command, workload, str(count),
                                            'sandbox' if sandbox else 'plain'], quiet=True)
                    sample, = records(output, 'SVC_BENCH ')
                    assert sample['provider'] == (not mode.startswith('native'))
                    if sandbox: assert not sample['completed']
                    elif mode in ('source', 'patch', 'integer', 'borrowed', 'pair', 'edge'): assert sample['completed'] >= count + 128
                    else: assert not sample['completed']
                    sample.update(control=mode, round=round_number)
                    suite.report['samples'].append(sample)
                    print(workload, 'sandbox' if sandbox else 'plain', mode, round_number, round(sample['ns']/1e6, 3), 'ms', flush=True)
        summaries = {}
        for workload, count, sandbox in workloads:
            series = {mode: [s['ns'] for s in suite.report['samples']
                             if s['workload'] == workload and s['control'] == mode and s['sandbox'] == sandbox] for mode in modes}
            summaries[workload + ('-sandbox' if sandbox else '')] = dict(iterations=count,
                mediansMs={mode: statistics.median(values)/1e6 for mode, values in series.items()},
                patchToSourceMedianPaired=statistics.median(a/b for a, b in zip(series['patch'], series['source'])),
                borrowedToSourceMedianPaired=statistics.median(a/b for a, b in zip(series['borrowed'], series['source'])),
                pairToSourceMedianPaired=statistics.median(a/b for a, b in zip(series['pair'], series['source'])),
                edgeToSourceMedianPaired=statistics.median(a/b for a, b in zip(series['edge'], series['source'])),
                integerToSourceMedianPaired=statistics.median(a/b for a, b in zip(series['integer'], series['source'])))
        suite.report['summary'] = summaries
        print(json.dumps(summaries, indent=2), flush=True)
        suite.report['passed'] = True
        suite.command(['rm', '-rf', suite.base])
    finally:
        suite.finish()


if __name__ == '__main__':
    main()

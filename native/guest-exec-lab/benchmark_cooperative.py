#!/usr/bin/env python3
"""Compare captured cooperative requests with the production syscall path."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics

from test_oci_services import Suite
import proot_fixture


def records(output, prefix):
    return [json.loads(line[len(prefix):]) for line in output.splitlines()
            if line.startswith(prefix)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('--output', type=Path, default=Path('build/cooperative-entry'))
    parser.add_argument('--iterations', type=int, default=1024)
    parser.add_argument('--rounds', type=int, default=5)
    parser.add_argument('--profile', action='store_true', help='separate instrumented engine invocation')
    parser.add_argument('--reference', type=Path, help='previous fixture for interleaved engine comparison')
    parser.add_argument('--runtime-reference', type=Path,
                        help='previous native build for interleaved production Base/entry comparison')
    parser.add_argument('--proot-prefix', type=Path, help='stage installed Termux PRoot and its dependencies for the same shell UID control')
    parser.add_argument('--contracts', action='store_true', help='run inode, native leaf, credentials and mount contracts')
    parser.add_argument('--spin-ns', type=int, default=10000, help='bounded handoff budget, 0..100000 ns')
    parser.add_argument('--helper-spin-ns', type=int, help='optional independent pipeline-helper budget, 0..100000 ns')
    affinity = parser.add_mutually_exclusive_group()
    affinity.add_argument('--cpu', type=int, help='optional single-core control; affinity belongs only to fixture children')
    affinity.add_argument('--cpu-mask', type=lambda value: int(value, 16), help='hex mask for a same-cluster multi-core control')
    parser.add_argument('--modes', nargs='+', help='optional subset of measured modes, still rotated between rounds')
    parser.add_argument('--logical-root', action='store_true', help='give the test root guest 0:0/0755 metadata; default retains legacy physical root permissions')
    parser.add_argument('--workload', choices=('files', 'opens', 'directories', 'metadata'), default='files')
    args = parser.parse_args()
    if not 1 <= args.iterations <= 1000000 or not 1 <= args.rounds <= 100:
        parser.error('iterations must be 1..1000000; rounds must be 1..100')
    if not 0 <= args.spin_ns <= 100000:
        parser.error('spin-ns must be 0..100000')
    if args.helper_spin_ns is not None and not 0 <= args.helper_spin_ns <= 100000:
        parser.error('helper-spin-ns must be 0..100000')
    if args.cpu is not None and not 0 <= args.cpu < 64:
        parser.error('cpu must be 0..63')
    if args.cpu_mask is not None and not 0 < args.cpu_mask < 1 << 64:
        parser.error('cpu-mask must be a nonzero 64-bit hexadecimal mask')
    mask = (1 << args.cpu) if args.cpu is not None else args.cpu_mask
    allowed = {'native', 'shroot', 'shroot-entry', 'cooperative', 'cooperative-bounded', 'cooperative-adaptive', 'cooperative-leased', 'cooperative-leased-recheck', 'cooperative-shared-files', 'cooperative-shared-tracked', 'cooperative-fd-executor', 'cooperative-fd-executor-parked', 'cooperative-fd-sidecar', 'cooperative-fd-sidecar-parked', 'engine'}
    if args.workload == 'metadata':
        allowed.add('engine-read-lease')
    allowed.add('shroot-machine')
    allowed.update({'cooperative-fd-pipeline', 'cooperative-fd-reopen', 'cooperative-fd-pidfd', 'cooperative-fd-local-close', 'cooperative-fd-plan', 'cooperative-guest-plan'})
    allowed.update({'cooperative-guest-pin', 'cooperative-guest-queued', 'cooperative-guest-window'})
    if args.reference:
        allowed.update({'engine-reference', 'bounded-reference', 'adaptive-reference'})
    if args.runtime_reference:
        allowed.update({'shroot-reference', 'shroot-entry-reference'})
    proot_assets = proot_fixture.ASSETS
    if args.proot_prefix:
        for name in proot_assets:
            if not (args.proot_prefix / name).is_file():
                parser.error('missing PRoot asset: ' + str(args.proot_prefix / name))
        allowed.add('proot')
    if args.modes and (len(set(args.modes)) != len(args.modes) or set(args.modes) - allowed):
        parser.error('modes must be distinct available modes: ' + ', '.join(sorted(allowed)))
    suite = Suite(args.output, args.build)
    try:
        filename = 'libmagicdesk_guest_benchmark_cooperative.so'
        binary = args.build / filename
        with binary.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        executable = suite.base + '/' + filename
        suite.transport.upload(suite.client, binary, executable)
        assert suite.command(['sha256sum', executable], quiet=True).split()[0] == digest
        suite.command(['chmod', '700', executable])
        suite.report['nativeHashes'][filename] = digest
        suite.report['kernel'] = suite.command(['uname', '-a'], quiet=True).strip()
        suite.report['scope'] = {
            'operations': (['openat(O_CREAT|O_EXCL)', 'write(4096)', 'close', 'renameat2', 'unlinkat']
                           if args.workload == 'files' else ['openat(O_RDONLY|O_CLOEXEC)', 'close'] if args.workload == 'opens'
                           else ['newfstatat'] if args.workload == 'metadata' else
                           ['mkdirat', 'renameat2', 'unlinkat(AT_REMOVEDIR)', 'newfstatat']),
            'workload': args.workload,
            'transport': {
                'shroot-entry': 'production auxv entry, authenticated task, original guest pointers, shared worker',
                'shroot': 'production kernel syscall entry',
                'shroot-machine': 'production supervisor, stock instructions, lazy SVC entry; no source-built libc',
                'cooperative-*': 'lab captured absolute paths; shared mmap and futex; one fixed actor',
                'cooperative-shared-files': 'lab CLONE_FILES, separate address spaces; direct FD ownership transfer; no production FD provenance/lifecycle',
                'cooperative-shared-tracked': 'lab CLONE_FILES with production mount anchors, FD origins and table turns; worker executes close; no production lifecycle',
                'cooperative-fd-executor': 'lab private engine table plus CLONE_FILES delivery/close relay; slot custody only, not production origin publication/lifecycle',
                'cooperative-fd-executor-parked': 'same relay; client immediately parks during an upstream engine operation',
                'cooperative-fd-sidecar': 'lab private engine with real origins/turns/custody; guest calls engine directly; sidecar only installs/closes descriptors; guest recvmsg denied by seccomp',
                'cooperative-fd-sidecar-parked': 'same sidecar; guest parks only for open/close completion',
                'cooperative-fd-pipeline': 'lab helper thread unshares file table and shares it with a separate-VM guest; real metadata completed by helper before direct guest reply; private anchor destruction remains on engine',
                'cooperative-fd-reopen': 'same pipeline; ordinary files reopen the pinned engine source through /proc/self/fd instead of per-open SCM_RIGHTS; narrow flags, not a generic FD transfer',
                'cooperative-fd-pidfd': 'same pipeline; same-process pidfd_getfd copies the pinned engine source into the helper/client table, not from a protected guest process',
                'cooperative-fd-local-close': 'same pidfd pipeline; guest closes directly through its table-sharing helper with real origin retirement; bounded queue returns private anchor destruction to engine',
                'cooperative-fd-plan': 'lab-only backing-open interposer retains real path/access checks but prepares an O_PATH pin for existing regular readonly opens; helper opens data in the client table; creation retains the pidfd control',
                'cooperative-guest-plan': 'same readonly plan, executed by the guest itself; async result receipt commits real FD origins before the next tracked operation; fixed cooperative actor, not general filter admission',
                'cooperative-guest-pin': 'same guest plan with one O_PATH pin owned by the real origin, borrowed by the plan until completion',
                'cooperative-guest-queued': 'single-pin guest plan; native guest close and bounded ordered completion queue drained before subsequent requests; fixed actor only, no concurrent FD users',
                'cooperative-guest-window': 'same queued completion; existing bounded metadata read window also covers readonly open, released before park or mutation',
            },
            'workerCpu': 'whole invocation, including correctness checks and warmup',
            'callerCpu': 'measured loop only; excludes the separate owner/supervisor',
            'labSpinNanoseconds': args.spin_ns,
            'pipelineHelperSpinNanoseconds': args.helper_spin_ns,
            'entrySpinPolicy': 'bounded 25000 ns; four misses select 128 immediate parks',
            'namespace': 'Shroot and lab modes share the store and empty attachment set; test executable installed in /fixture/benchmark; native and optional PRoot share a separate physical data directory',
            'cpu': args.cpu,
            'cpuMask': None if mask is None else format(mask, 'x'),
            'readLeaseExperiment': bool(args.modes and 'engine-read-lease' in args.modes),
            'boundedReadWindowExperiment': True,
            'rootPermissions': 'guest-0:0-0755' if args.logical_root else 'physical',
        }
        native = suite.base + '/native'
        store = suite.base + '/store'
        suite.command([executable, 'prepare', store])
        if args.logical_root:
            suite.command([executable, 'guest-root', store])
        suite.command([executable, 'native-prepare', native])
        suite.command([executable, 'test', store])
        if args.modes and set(args.modes) & {'cooperative-fd-pidfd', 'cooperative-fd-local-close', 'cooperative-fd-plan', 'cooperative-guest-plan', 'cooperative-guest-pin', 'cooperative-guest-queued', 'cooperative-guest-window'}:
            suite.command([executable, 'test-pidfd', store])
        proot_command = None
        if args.proot_prefix:
            invocation = proot_fixture.stage(suite, args.proot_prefix)
            root = suite.base + '/proot-root'
            suite.command(['mkdir', '-p', root + '/fixture', root + '/proc', root + '/dev'])
            suite.command(['cp', executable, root + '/fixture/benchmark'])
            assert suite.command(['sha256sum', root + '/fixture/benchmark'], quiet=True).split()[0] == digest
            # Native and PRoot use the same physical directory. Shroot uses its
            # native-leaf representation on the same host filesystem.
            suite.command(['mv', native, root + '/bench'])
            native = root + '/bench'
            guest = ['--kill-on-exit', '-0', '-r', root, '-b', '/proc', '-b', '/dev',
                     '-w', '/bench', '/fixture/benchmark', 'syscalls', '/bench']
            diagnostic = suite.command(invocation + ['-v', '1'] + guest + ['1', 'opens'], quiet=True)
            assert 'ptrace acceleration (seccomp mode 2,' in diagnostic, diagnostic
            suite.report['proot'].update({
                'seccompDiagnostic': diagnostic,
                'root': root, 'binds': ['/proc', '/dev'],
                'environment': 'clean; no PROOT_NO_SECCOMP or preload',
            })
            suite.report['scope']['transport']['proot'] = 'installed Termux PRoot staged under shell UID 2000; seccomp enabled; same static fixture and native data directory'
            proot_command = invocation + guest
        if args.contracts:
            for name in ('inodes', 'native_leaf', 'credentials', 'mounts'):
                fixture = args.build / ('libmagicdesk_guest_test_' + name + '.so')
                target = suite.base + '/' + fixture.name
                suite.transport.upload(suite.client, fixture, target)
                suite.command(['chmod', '700', target])
                suite.command(['timeout', '120', target, suite.base + '/contract-' + name])
        commands = {
            'native': [executable, 'syscalls', native],
            'shroot': [suite.runner, '--store', store, '--user', '0:0',
                       '--deadline-seconds', '120',
                       '--', '/fixture/benchmark', 'syscalls', '/bench'],
            'shroot-entry': [suite.runner, '--store', store, '--user', '0:0',
                            '--deadline-seconds', '120',
                            '--', '/fixture/benchmark', 'syscalls-entry', '/bench'],
            'shroot-machine': [suite.runner, '--env', 'SHROOT_MACHINE_ENTRY=1',
                               '--store', store, '--user', '0:0', '--deadline-seconds', '120',
                               '--', '/fixture/benchmark', 'syscalls', '/bench'],
            'cooperative': [executable, 'cooperative', store],
            'cooperative-bounded': ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns),
                                    executable, 'cooperative-bounded', store],
            'cooperative-adaptive': ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns),
                                    executable, 'cooperative-adaptive', store],
            'cooperative-shared-files': ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns),
                                         executable, 'cooperative-shared-files', store],
            'cooperative-shared-tracked': ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns),
                                           executable, 'cooperative-shared-tracked', store],
            'cooperative-fd-executor': ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns),
                                       executable, 'cooperative-fd-executor', store],
            'cooperative-fd-executor-parked': ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns),
                                              executable, 'cooperative-fd-executor-parked', store],
            'cooperative-fd-sidecar': ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns),
                                      executable, 'cooperative-fd-sidecar', store],
            'cooperative-fd-sidecar-parked': ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns),
                                             executable, 'cooperative-fd-sidecar-parked', store],
            'cooperative-fd-pipeline': ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns),
                                       executable, 'cooperative-fd-pipeline', store],
            'cooperative-fd-reopen': ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns),
                                     executable, 'cooperative-fd-reopen', store],
            'cooperative-fd-pidfd': ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns),
                                    executable, 'cooperative-fd-pidfd', store],
            'cooperative-fd-local-close': ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns),
                                          executable, 'cooperative-fd-local-close', store],
            'cooperative-fd-plan': ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns),
                                   executable, 'cooperative-fd-plan', store],
            'cooperative-guest-plan': ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns),
                                      executable, 'cooperative-guest-plan', store],
            'cooperative-guest-pin': ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns),
                                     executable, 'cooperative-guest-pin', store],
            'cooperative-guest-queued': ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns),
                                        executable, 'cooperative-guest-queued', store],
            'cooperative-guest-window': ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns),
                                        executable, 'cooperative-guest-window', store],
            'cooperative-leased': ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns),
                                    executable, 'cooperative-leased', store],
            'engine': [executable, 'engine', store],
        }
        if proot_command:
            commands['proot'] = proot_command
        if args.runtime_reference:
            directory = suite.base + '/runtime-reference'
            suite.command(['mkdir', directory])
            suite.report['runtimeReference'] = {
                'build': str(args.runtime_reference),
                'hashes': suite.stage_runtime(args.runtime_reference, directory),
            }
            for mode in ('shroot', 'shroot-entry'):
                commands[mode + '-reference'] = [directory + '/libmagicdesk_guest_run.so',
                                                  *commands[mode][1:]]
        if not args.modes or 'cooperative-fd-pidfd' not in args.modes:
            commands.pop('cooperative-fd-pidfd')
        if not args.modes or 'cooperative-fd-local-close' not in args.modes:
            commands.pop('cooperative-fd-local-close')
        if not args.modes or 'cooperative-fd-plan' not in args.modes:
            commands.pop('cooperative-fd-plan')
        if not args.modes or 'cooperative-guest-plan' not in args.modes:
            commands.pop('cooperative-guest-plan')
        for mode in ('cooperative-guest-pin', 'cooperative-guest-queued', 'cooperative-guest-window'):
            if not args.modes or mode not in args.modes:
                commands.pop(mode)
        if args.helper_spin_ns is not None:
            for mode in ('cooperative-fd-pipeline', 'cooperative-fd-reopen', 'cooperative-fd-pidfd', 'cooperative-fd-local-close', 'cooperative-fd-plan', 'cooperative-guest-plan', 'cooperative-guest-pin', 'cooperative-guest-queued', 'cooperative-guest-window'):
                if mode in commands:
                    commands[mode].insert(1, 'MD_LAB_HELPER_SPIN_NS=' + str(args.helper_spin_ns))
        if args.modes and 'engine-read-lease' in args.modes:
            commands['engine-read-lease'] = [executable, 'engine-read-lease', store]
        if args.modes and 'cooperative-leased-recheck' in args.modes:
            commands['cooperative-leased-recheck'] = ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns),
                                                    executable, 'cooperative-leased-recheck', store]
        if args.reference:
            target = suite.base + '/reference'
            suite.transport.upload(suite.client, args.reference, target)
            suite.command(['chmod', '700', target])
            commands['engine-reference'] = [target, 'engine', store]
            commands['bounded-reference'] = ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns), target, 'cooperative-bounded', store]
            commands['adaptive-reference'] = ['env', 'MD_LAB_SPIN_NS=' + str(args.spin_ns), target, 'cooperative-adaptive', store]
            suite.report['referenceHash'] = suite.command(['sha256sum', target], quiet=True).split()[0]
        suite.report['samples'] = samples = []
        modes = args.modes or list(commands)
        if 'shroot-machine' in modes:
            # Keep instrumentation out of timed runs, but require actual engine
            # completions rather than inferring acceleration from elapsed time.
            command = commands['shroot-machine']
            output = suite.command([command[0], '--statistics', *command[1:], '16', args.workload], quiet=True)
            evidence = records(output, 'SVC_RUNTIME_STATS ')
            assert evidence and all(item['unknown'] == 0 for item in evidence), output
            assert sum(item['completed'] for item in evidence) >= 16, output
            suite.report['machineEntryEvidence'] = evidence
        for round_number in range(args.rounds):
            offset = round_number % len(modes)
            for mode in modes[offset:] + modes[:offset]:
                affinity = [] if mask is None else ['taskset', format(mask, 'x')]
                output = suite.command(affinity + commands[mode] + [str(args.iterations), args.workload])
                measured = records(output, 'COOPERATIVE_BENCH ')
                calls = args.iterations * {'metadata': 1, 'directories': 4, 'files': 5, 'opens': 2}[args.workload]
                assert len(measured) == 1 and measured[0]['calls'] == calls, output
                assert measured[0]['workload'] == args.workload, output
                sample = {**measured[0], 'mode': mode, 'round': round_number,
                          'worker': records(output, 'COOPERATIVE_WORKER ')}
                if args.workload == 'opens' and mode in ('cooperative-fd-plan', 'cooperative-guest-plan', 'cooperative-guest-pin', 'cooperative-guest-queued', 'cooperative-guest-window'):
                    counter = 'preparedOpens' if mode == 'cooperative-fd-plan' else 'directPlans'
                    assert sum(worker.get(counter, 0) for worker in sample['worker']) >= args.iterations, output
                if mode in ('cooperative-guest-queued', 'cooperative-guest-window') and args.workload in ('opens', 'files'):
                    assert sum(worker.get('queuedCloses', 0) for worker in sample['worker']) >= args.iterations, output
                samples.append(sample)
        medians = {mode: statistics.median(s['seconds'] for s in samples if s['mode'] == mode)
                   for mode in modes}
        ratios = {
            'baseOverRuntimeReference': ('shroot', 'shroot-reference'),
            'entryOverRuntimeReference': ('shroot-entry', 'shroot-entry-reference'),
            'entryOverNative': ('shroot-entry', 'native'),
            'entrySpeedupVsShroot': ('shroot', 'shroot-entry'),
            'machineOverNative': ('shroot-machine', 'native'),
            'machineOverEntry': ('shroot-machine', 'shroot-entry'),
            'machineSpeedupVsShroot': ('shroot', 'shroot-machine'),
            'machineSpeedupVsProot': ('proot', 'shroot-machine'),
            'cooperativeSpeedupVsShroot': ('shroot', 'cooperative'),
            'cooperativeOverNative': ('cooperative', 'native'),
            'engineOverNative': ('engine', 'native'),
            'boundedOverNative': ('cooperative-bounded', 'native'),
            'adaptiveOverNative': ('cooperative-adaptive', 'native'),
            'leasedOverNative': ('cooperative-leased', 'native'),
            'leasedSpeedupVsAdaptive': ('cooperative-adaptive', 'cooperative-leased'),
            'boundedSpeedupVsShroot': ('shroot', 'cooperative-bounded'),
            'boundedSpeedupVsCooperative': ('cooperative', 'cooperative-bounded'),
            'adaptiveSpeedupVsShroot': ('shroot', 'cooperative-adaptive'),
            'sharedFilesSpeedupVsShroot': ('shroot', 'cooperative-shared-files'),
            'sharedFilesSpeedupVsEntry': ('shroot-entry', 'cooperative-shared-files'),
            'sharedFilesSpeedupVsSCM': ('cooperative-adaptive', 'cooperative-shared-files'),
            'trackedFilesSpeedupVsShroot': ('shroot', 'cooperative-shared-tracked'),
            'trackedFilesSpeedupVsEntry': ('shroot-entry', 'cooperative-shared-tracked'),
            'executorSpeedupVsShroot': ('shroot', 'cooperative-fd-executor'),
            'executorSpeedupVsEntry': ('shroot-entry', 'cooperative-fd-executor'),
            'executorOverSCM': ('cooperative-fd-executor', 'cooperative-adaptive'),
            'parkedExecutorSpeedupVsShroot': ('shroot', 'cooperative-fd-executor-parked'),
            'parkedExecutorSpeedupVsExecutor': ('cooperative-fd-executor', 'cooperative-fd-executor-parked'),
            'prootOverNative': ('proot', 'native'),
            'shrootOverProot': ('shroot', 'proot'),
            'trackedFilesSpeedupVsProot': ('proot', 'cooperative-shared-tracked'),
            'sidecarSpeedupVsShroot': ('shroot', 'cooperative-fd-sidecar'),
            'sidecarSpeedupVsProot': ('proot', 'cooperative-fd-sidecar'),
            'sidecarOverSharedTracked': ('cooperative-fd-sidecar', 'cooperative-shared-tracked'),
            'parkedSidecarSpeedupVsSidecar': ('cooperative-fd-sidecar', 'cooperative-fd-sidecar-parked'),
            'pipelineSpeedupVsShroot': ('shroot', 'cooperative-fd-pipeline'),
            'pipelineSpeedupVsProot': ('proot', 'cooperative-fd-pipeline'),
            'pipelineSpeedupVsSidecar': ('cooperative-fd-sidecar', 'cooperative-fd-pipeline'),
            'pipelineOverSharedTracked': ('cooperative-fd-pipeline', 'cooperative-shared-tracked'),
            'reopenSpeedupVsPipeline': ('cooperative-fd-pipeline', 'cooperative-fd-reopen'),
            'reopenSpeedupVsProot': ('proot', 'cooperative-fd-reopen'),
            'pidfdSpeedupVsPipeline': ('cooperative-fd-pipeline', 'cooperative-fd-pidfd'),
            'pidfdSpeedupVsProot': ('proot', 'cooperative-fd-pidfd'),
            'localCloseSpeedupVsPidfd': ('cooperative-fd-pidfd', 'cooperative-fd-local-close'),
            'localCloseSpeedupVsShroot': ('shroot', 'cooperative-fd-local-close'),
            'localCloseSpeedupVsProot': ('proot', 'cooperative-fd-local-close'),
            'planSpeedupVsLocalClose': ('cooperative-fd-local-close', 'cooperative-fd-plan'),
            'planSpeedupVsShroot': ('shroot', 'cooperative-fd-plan'),
            'planSpeedupVsProot': ('proot', 'cooperative-fd-plan'),
            'guestPlanSpeedupVsLocalClose': ('cooperative-fd-local-close', 'cooperative-guest-plan'),
            'guestPlanSpeedupVsHelperPlan': ('cooperative-fd-plan', 'cooperative-guest-plan'),
            'guestPlanSpeedupVsShroot': ('shroot', 'cooperative-guest-plan'),
            'guestPlanSpeedupVsProot': ('proot', 'cooperative-guest-plan'),
            'singlePinSpeedupVsPlan': ('cooperative-guest-plan', 'cooperative-guest-pin'),
            'queuedSpeedupVsPlan': ('cooperative-guest-plan', 'cooperative-guest-queued'),
            'queuedSpeedupVsSinglePin': ('cooperative-guest-pin', 'cooperative-guest-queued'),
            'queuedSpeedupVsProot': ('proot', 'cooperative-guest-queued'),
            'queuedSpeedupVsShroot': ('shroot', 'cooperative-guest-queued'),
            'windowSpeedupVsQueued': ('cooperative-guest-queued', 'cooperative-guest-window'),
            'windowSpeedupVsPlan': ('cooperative-guest-plan', 'cooperative-guest-window'),
            'windowSpeedupVsProot': ('proot', 'cooperative-guest-window'),
            'windowSpeedupVsShroot': ('shroot', 'cooperative-guest-window'),
        }
        suite.report['summary'] = {'medianSeconds': medians, **{
            name: medians[a] / medians[b] for name, (a, b) in ratios.items() if a in medians and b in medians}}
        paired = {}
        for name, (a, b) in ratios.items():
            if a not in medians or b not in medians:
                continue
            values = []
            for round_number in range(args.rounds):
                times = {s['mode']: s['seconds'] for s in samples if s['round'] == round_number}
                values.append(times[a] / times[b])
            paired[name] = {'median': statistics.median(values), 'min': min(values), 'max': max(values)}
        suite.report['summary']['pairedRoundRatios'] = paired
        print(json.dumps(suite.report['summary'], indent=2), flush=True)
        if args.profile:
            affinity = [] if mask is None else ['taskset', format(mask, 'x')]
            output = suite.command(affinity + [executable, 'engine-profile', store, str(args.iterations), args.workload])
            suite.report['profile'] = records(output, 'COOPERATIVE_PROFILE ')
        suite.report['passed'] = True
    finally:
        try:
            # Only this invocation's unique disposable directory is removed.
            suite.command(['rm', '-rf', suite.base])
        finally:
            suite.finish()


if __name__ == '__main__':
    main()

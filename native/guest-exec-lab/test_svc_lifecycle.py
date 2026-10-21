#!/usr/bin/env python3
"""Real published entries, retired before destructive VM operations."""
import argparse
import json
from pathlib import Path
from test_oci_services import Suite
from audit_svc_payload import audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('--mode', action='append')
    parser.add_argument('--diagnostics', action='store_true')
    args = parser.parse_args()
    suite = Suite(Path('build/svc-lifecycle-results'), args.build)
    suite.report['lifecycle'] = []
    suite.report['payloadAudit'] = audit(args.build)
    try:
        signal = suite.base + '/signal'
        suite.transport.upload(suite.client, args.build / 'libmagicdesk_guest_test_svc_signal.so', signal)
        suite.command(['chmod', '700', signal])
        assert 'PASS SVC prefix fault:' in suite.command(['timeout', '20', signal])
        root = suite.base + '/root'
        suite.command(['mkdir', '-p', root + '/bin', root + '/tmp'])
        for name, target in [('trace_svc_patch', root + '/bin/tracer'),
                             ('test_svc_lifecycle', root + '/bin/lifecycle'),
                             ('service', suite.base + '/service')]:
            suite.transport.upload(suite.client, args.build / ('libmagicdesk_guest_' + name + '.so'), target)
            suite.command(['chmod', '700', target])
        suite.command([suite.base + '/service', '--import', root, suite.base + '/store', '--preserve-ownership'])
        for mode in args.mode or ('protect', 'remap', 'unmap', 'replace', 'discard', 'fork', 'clone-vm', 'vfork',
                                 'exec', 'thread-exec', 'drain', 'drain-death', 'drain-ipc',
                                 'debugger', 'pid-namespace', 'writable', 'shared'):
            output = suite.command([suite.runner, *(['--diagnostics'] if args.diagnostics else []),
                                    '--store', suite.base + '/store', '--user', '0:0',
                                    '--env', 'SHROOT_MACHINE_ENTRY=0', '--env', 'MD_SVC_SIGNAL_PROOF=1', '--',
                                    '/bin/tracer', 'edge', '/bin/lifecycle', '/tmp', mode], timeout=90, quiet=True)
            assert 'PASS SVC lifecycle:' in output
            totals = [json.loads(s[len('SVC_EDGE_STATS '):]) for s in output.splitlines() if s.startswith('SVC_EDGE_STATS ')]
            declined = mode in ('writable', 'shared')
            assert len(totals) == 1 and not totals[0]['unknown']
            assert totals[0]['completed'] == 0 if declined else totals[0]['completed'] > 900
            if mode not in ('exec', 'thread-exec') and not declined:
                assert 'SVC_RETIRE ' in output
            if mode in ('drain', 'drain-death', 'drain-ipc'):
                retirements = [json.loads(s[len('SVC_RETIRE '):]) for s in output.splitlines() if s.startswith('SVC_RETIRE ')]
                assert any(r['draining'] > 0 for r in retirements)
            suite.report['lifecycle'].append(dict(mode=mode, evidence=totals[0]))
            print('PASS lifecycle', mode, totals[0]['completed'], flush=True)
        suite.report['passed'] = True
        suite.command(['rm', '-rf', suite.base])
    finally:
        suite.finish()


if __name__ == '__main__':
    main()

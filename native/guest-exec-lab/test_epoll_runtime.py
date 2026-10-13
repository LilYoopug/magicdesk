#!/usr/bin/env python3
"""Mixed native/control epoll through the production shell runtime."""
import argparse
from pathlib import Path
from test_oci_services import Suite

MODES = ('mixed', 'filtered', 'shared', 'shared-filtered', 'close-filtered', 'retire-filtered')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--store', required=True)
    parser.add_argument('--repetitions', type=int, default=1)
    parser.add_argument('--mode', choices=MODES,
                        action='append', help='Select focused cases; default runs all modes')
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error('--repetitions must be positive')
    suite = Suite(args.build, args.build)
    target = '/md-epoll-' + suite.report['id']
    prefix = [suite.runner, '--store', args.store, '--user', '0:0']
    created = False
    try:
        suite.transport.upload(suite.client, args.build / 'libmagicdesk_guest_readiness_guest.so', suite.base + '/readiness')
        suite.command(['chmod', '700', suite.base + '/readiness'])
        suite.command(prefix + ['--', '/bin/mkdir', target])
        created = True
        for _ in range(args.repetitions):
            for mode in args.mode or MODES:
                denied = mode == 'retire-filtered'
                output = suite.command(prefix + ['--diagnostics', '--bind', suite.base, target, '--deadline-seconds', '20',
                                                 '--', target + '/readiness', '--' + mode], timeout=35,
                                       expected=125 if denied else 0)
                if denied:
                    assert 'Shroot: cannot retire temporary FD ' in output
                    assert 'Operation not permitted' in output
                    assert 'launch deadline expired' not in output
                else:
                    assert 'PASS mixed epoll' in output
        suite.report['passed'] = True
    finally:
        try:
            if created:
                suite.command(prefix + ['--', '/bin/rmdir', target])
        finally:
            suite.finish()


if __name__ == '__main__':
    main()

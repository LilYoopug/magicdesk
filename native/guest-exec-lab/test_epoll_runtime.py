#!/usr/bin/env python3
"""Mixed native/control epoll through the production shell runtime."""
import argparse
from pathlib import Path
from test_oci_services import Suite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--store', required=True)
    args = parser.parse_args()
    suite = Suite(args.build, args.build)
    target = '/md-epoll-' + suite.report['id']
    prefix = [suite.runner, '--store', args.store, '--user', '0:0']
    created = False
    try:
        suite.transport.upload(suite.client, args.build / 'libmagicdesk_guest_readiness_guest.so', suite.base + '/readiness')
        suite.command(['chmod', '700', suite.base + '/readiness'])
        suite.command(prefix + ['--', '/bin/mkdir', target])
        created = True
        for mode in ('--mixed', '--filtered'):
            output = suite.command(prefix + ['--diagnostics', '--bind', suite.base, target, '--deadline-seconds', '20',
                                             '--', target + '/readiness', mode], timeout=35)
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

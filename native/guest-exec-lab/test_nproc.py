#!/usr/bin/env python3
"""Real UID task limits, including protected guest memory and zombie lifetime."""
import argparse
from pathlib import Path
from test_oci_services import Suite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    args = parser.parse_args()
    suite = Suite(args.build, args.build)
    target = '/tmp/md-nproc-' + suite.report['id']
    prefix = [suite.runner, '--store', args.store, '--user', '0:0']
    try:
        for name in ('test_process_limits', 'nproc_guest'):
            suite.transport.upload(suite.client, args.build / ('libmagicdesk_guest_' + name + '.so'),
                                   suite.base + '/' + name)
            suite.command(['chmod', '755', suite.base + '/' + name])
        suite.command([suite.base + '/test_process_limits'])
        suite.command(prefix + ['--', '/bin/mkdir', target])
        suite.command(prefix + ['--bind-ro', suite.base, target, '--deadline-seconds', '80',
                                '--', target + '/nproc_guest'], timeout=100)
        suite.command(prefix + ['--bind-ro', suite.base, target, '--deadline-seconds', '80',
                                '--', '/usr/bin/unshare', '-mpf', '--mount-proc', target + '/nproc_guest'], timeout=100)
        suite.report['passed'] = True
    finally:
        try:
            suite.command(prefix + ['--', '/bin/rmdir', target])
        finally:
            suite.finish()


if __name__ == '__main__':
    main()

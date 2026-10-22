#!/usr/bin/env python3
"""Guest process/FD limits, protected memory, inheritance and exhaustion."""
import argparse
from pathlib import Path
from test_oci_services import Suite, add_machine_entry_argument


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    add_machine_entry_argument(parser)
    args = parser.parse_args()
    suite = Suite(args.build, args.build, machine_entry=args.machine_entry)
    target = '/tmp/md-nproc-' + suite.report['id']
    prefix = [suite.runner, '--store', args.store, '--user', '0:0', *suite.entry_options]
    created = False
    try:
        for name in ('test_process_limits', 'nproc_guest', 'nofile_guest'):
            suite.transport.upload(suite.client, args.build / ('libmagicdesk_guest_' + name + '.so'),
                                   suite.base + '/' + name)
            suite.command(['chmod', '755', suite.base + '/' + name])
        suite.command([suite.base + '/test_process_limits'])
        suite.command(prefix + ['--', '/bin/mkdir', target])
        created = True
        for name in ('nproc_guest', 'nofile_guest'):
            for namespace in ([], ['/usr/bin/unshare', '-mpf', '--mount-proc']):
                suite.command(prefix + ['--bind-ro', suite.base, target, '--deadline-seconds', '80',
                                        '--'] + namespace + [target + '/' + name], timeout=100)
        suite.report['passed'] = True
    finally:
        try:
            if created:
                suite.command(prefix + ['--', '/bin/rmdir', target])
        finally:
            suite.finish()


if __name__ == '__main__':
    main()

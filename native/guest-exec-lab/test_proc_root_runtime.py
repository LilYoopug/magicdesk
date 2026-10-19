#!/usr/bin/env python3
"""Foreign process roots in a stock Python userspace under the shell runtime."""
import argparse
from pathlib import Path
from test_oci_services import Suite, Server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    parser.add_argument('--libc-registry', help='Use the production accelerated libc selection')
    args = parser.parse_args()
    suite = Suite(args.build, args.build)
    target = '/tmp/md-proc-root-' + suite.report['id']
    base = [suite.runner, '--store', args.store, '--user', '0:0']
    if args.libc_registry:
        base += ['--libc-registry', args.libc_registry]
        suite.report['libcRegistry'] = args.libc_registry
    try:
        suite.transport.upload(suite.client, Path(__file__).with_name('test_proc_root_guest.py'), suite.base + '/probe.py')
        suite.transport.upload(suite.client, Path(__file__).with_name('test_fd_selector_guest.py'), suite.base + '/selectors.py')
        suite.command(base + ['--', '/bin/mkdir', target])
        suite.command(base + ['--bind-ro', suite.base, target, '--deadline-seconds', '60', '--',
                              '/usr/bin/python3', target + '/selectors.py'])
        for wrapper in ([], ['/usr/bin/unshare', '--pid', '--fork', '--mount-proc']):
            process = Server(suite, base + ['--bind-ro', suite.base, target, '--deadline-seconds', '90',
                                           '--'] + wrapper + ['/usr/bin/python3', target + '/probe.py'])
            try:
                process.ready('PASS foreign proc root:')
                process.completed()
            finally:
                process.close()
        suite.report['passed'] = True
    finally:
        try:
            suite.command(base + ['--', '/bin/rmdir', target])
        finally:
            suite.finish()


if __name__ == '__main__':
    main()

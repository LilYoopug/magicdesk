#!/usr/bin/env python3
"""Distribution Glycin with Bubblewrap and its original seccomp policy, UID 2000."""
import argparse
from pathlib import Path

from test_oci_services import Suite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    parser.add_argument('--trace', action='store_true')
    args = parser.parse_args()
    suite = Suite(args.build, args.build)
    suite.report['store'] = args.store
    try:
        source = Path(__file__).with_name('test_glycin_loader.py')
        suite.transport.upload(suite.client, source, suite.base + '/loader.py')
        target = '/tmp/md-glycin-' + suite.report['id']
        base = [suite.runner, '--store', args.store, '--user', '2000:2000']
        suite.command(base + ['--', '/bin/mkdir', target])
        prefix = base + ['--bind-ro', suite.base, target, '--deadline-seconds', '60', '--']
        suite.report['packages'] = suite.command(prefix + ['/usr/bin/dpkg-query', '-W', 'loupe', 'glycin-loaders', 'libglycin-1-0', 'bubblewrap'])
        trace = ['/usr/bin/strace', '-f', '-s', '160'] if args.trace else []
        result = suite.command(prefix + trace + ['/usr/bin/env', 'RUST_LOG=glycin=debug', 'HOME=/tmp',
                                                'python3', target + '/loader.py'], timeout=80)
        assert 'PASS Glycin BWRAP decoded 2x1 RGB pixels' in result
        assert 'running without sandbox' not in result
        suite.report['passed'] = True
    finally:
        try:
            if 'target' in locals():
                suite.command(base + ['--', '/bin/rmdir', target])
        finally:
            suite.finish()
    return 0 if suite.report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

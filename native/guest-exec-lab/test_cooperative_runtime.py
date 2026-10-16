#!/usr/bin/env python3
"""Opt-in direct entry through the production bootstrap and syscall engine."""
import argparse
import re
from pathlib import Path
from test_oci_services import Suite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('--entry-only', action='store_true')
    parser.add_argument('--diagnostics', action='store_true')
    args = parser.parse_args()
    suite = Suite(Path('build/cooperative-runtime'), args.build)
    try:
        root = suite.base + '/rootfs'
        suite.command(['mkdir', '-p', root + '/bin', root + '/tmp'])
        for name, destination in (('service', suite.base + '/service'),
                                  ('cooperative_guest', root + '/bin/probe'),
                                  ('test_vdso', suite.base + '/vdso'),
                                  ('test_cooperative_native', suite.base + '/native-journal'),
                                  ('test_inodes', suite.base + '/inodes'),
                                  ('test_interception_buffers', suite.base + '/buffers'),
                                  ('fs_dispatch', suite.base + '/dispatch')):
            suite.transport.upload(suite.client, args.build / ('libmagicdesk_guest_' + name + '.so'), destination)
            suite.command(['chmod', '700', destination])
        if not args.entry_only:
            suite.command(['timeout', '45', suite.base + '/native-journal'])
            suite.command(['timeout', '60', suite.base + '/inodes', suite.base + '/inode-store'])
            suite.command(['timeout', '10', suite.base + '/vdso'])
            suite.command(['timeout', '90', suite.base + '/buffers'])
            suite.command(['timeout', '120', suite.base + '/dispatch', suite.base + '/dispatch-store'], quiet=True)
            output = suite.command(['timeout', '90', suite.base + '/dispatch', '--broker-directory',
                                    suite.base + '/broker-store'], quiet=True)
            assert 'PASS notification result: exact cancelled-token replacement' in output
        suite.command([suite.base + '/service', '--import', root, suite.base + '/store'])
        output = suite.command(['timeout', '90', suite.runner, *(['--diagnostics'] if args.diagnostics else []), '--statistics', '--store', suite.base + '/store',
                               '--user', '0:0', '--', '/bin/probe'])
        assert 'PASS cooperative entry: metadata' in output
        assert 'PASS cooperative ABI: runtime-owned offers' in output
        assert 'PASS native FD plans: 192 live opens' in output
        assert 'PASS native FD watches: exactly one open and one close event' in output
        assert 'PASS native writable plans:' in output
        assert 'PASS native create admission:' in output
        assert 'PASS native open exhaustion:' in output
        for key, minimum in (('nativeOpen', 1000), ('nativeClose', 990), ('nativeFlags', 576), ('nativeDeferred', 1)):
            count = re.search(rf'{key}=(\d+)', output)
            assert count and int(count[1]) >= minimum, f'{key} did not exercise native FD plans'
        descriptors = re.search(r'cooperativeDescriptors=(\d+)', output)
        assert descriptors and int(descriptors[1]) >= 128, 'FD checks did not exercise cooperative admission'
        suite.report['passed'] = True
        suite.command(['rm', '-rf', suite.base])
    finally:
        suite.finish()


if __name__ == '__main__':
    main()

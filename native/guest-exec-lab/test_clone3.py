#!/usr/bin/env python3
"""Clone ABI contracts on the real shell and in a recipe-installed userspace."""
import argparse
import json
from pathlib import Path

from test_oci_services import Suite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--name', required=True)
    args = parser.parse_args()
    suite = Suite(args.build, args.build)
    try:
        info = json.loads(suite.command(['shroot', 'inspect', args.name], quiet=True))
        suite.report['environment'] = info
        binary = 'libmagicdesk_guest_clone3_guest.so'
        suite.transport.upload(suite.client, args.build / binary, suite.base + '/' + binary)
        suite.command(['chmod', '755', suite.base + '/' + binary])
        suite.command([suite.base + '/' + binary, '--native'])
        suite.command(suite.guest(info['store'], '--user', '0:0', '--',
                                  '/bin/mkdir', '-p', '/opt/md-clone-fixture'))
        for mode in (0, 1):
            result = suite.command(suite.guest(info['store'], '--user', '0:0',
                '--env', 'SHROOT_MACHINE_ENTRY=' + str(mode),
                '--bind-ro', suite.base, '/opt/md-clone-fixture', '--deadline-seconds', '90', '--',
                '/opt/md-clone-fixture/' + binary), timeout=120)
            assert 'PASS clone3' in result
        suite.report['passed'] = True
    finally:
        suite.finish()


if __name__ == '__main__':
    main()

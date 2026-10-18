#!/usr/bin/env python3
"""Run stock FUSE clients in a private runtime, retaining per-command receipts."""
import argparse
from pathlib import Path

from test_oci_services import Suite


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--store', required=True)
    parser.add_argument('--case', choices=('rofiles', 'portal', 'squashfs'), required=True)
    parser.add_argument('--output', type=Path, default=Path('build/fuse-results'))
    parser.add_argument('--portal-user', default='1000:1000')
    parser.add_argument('--portal-home', default='/home/steamos')
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()
    suite = Suite(args.output, args.build)
    try:
        fixtures = Path(__file__).resolve().parent / 'fixtures'
        name = 'flatpak-document-portal.sh' if args.case == 'portal' else f'fuse-{args.case}.py'
        suite.transport.upload(suite.client, fixtures / name, suite.base + '/fixture')
        if args.case == 'portal':
            command = [suite.runner, '--store', args.store, '--bind-ro', suite.base, '/mnt',
                       '--user', args.portal_user, '--admit-elf', '/usr/bin/fusermount3',
                       '--env', 'HOME=' + args.portal_home, '--env', 'PATH=/usr/bin:/bin',
                       *(['--env', 'G_MESSAGES_DEBUG=xdg-desktop-portal'] if args.debug else []),
                       '--', '/bin/sh', '-ec',
                       'XDG_RUNTIME_DIR=$(mktemp -d /tmp/md-fuse-portal.XXXXXXXX); '
                       'export XDG_RUNTIME_DIR; '
                       'trap \'fusermount3 -u -z "$XDG_RUNTIME_DIR/doc" 2>/dev/null || :; '
                       'rm -rf "$XDG_RUNTIME_DIR"\' EXIT; '
                       'dbus-run-session -- /bin/sh /mnt/fixture']
        else:
            command = suite.run(args.store, '--bind-ro', suite.base, '/mnt',
                                '--user', '0:0', '--entrypoint', '/usr/bin/python3', '--', '/mnt/fixture')
        suite.command(command, timeout=180)
        suite.report.update(case=args.case, passed=True)
    finally:
        suite.finish()


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Run stock FUSE clients in a private runtime, retaining per-command receipts."""
import argparse
from pathlib import Path

from test_oci_services import Suite


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--store', required=True)
    parser.add_argument('--case', choices=('rofiles', 'portal', 'squashfs', 'close'), required=True)
    parser.add_argument('--output', type=Path, default=Path('build/fuse-results'))
    parser.add_argument('--portal-user', default='1000:1000')
    parser.add_argument('--portal-home', default='/home/steamos')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--libc-registry', help='Use and verify a prepared accelerated libc registry')
    args = parser.parse_args()
    suite = Suite(args.output, args.build)
    try:
        fixtures = Path(__file__).resolve().parent / 'fixtures'
        name = ('flatpak-document-portal.sh' if args.case == 'portal' else
                'fuse-close.c' if args.case == 'close' else f'fuse-{args.case}.py')
        suite.transport.upload(suite.client, fixtures / name, suite.base + '/fixture')
        registry = ['--libc-registry', args.libc_registry] if args.libc_registry else []
        if registry:
            suite.report['libcRegistry'] = args.libc_registry
            suite.command([suite.runner, '--store', args.store, *registry, '--',
                '/usr/bin/python3', '-c', '''import ctypes
libc = ctypes.CDLL(None)
libc.getauxval.argtypes = [ctypes.c_ulong]
libc.getauxval.restype = ctypes.c_void_p
entry = libc.getauxval(0x4d440001)
assert entry and ctypes.cast(entry, ctypes.POINTER(ctypes.c_uint32))[0] == libc.shroot_libc_entry_abi()
print('PASS FUSE fixture accelerated libc selection')
'''])
        if args.case == 'close':
            command = suite.run(args.store, *registry, '--bind-ro', suite.base, '/mnt',
                '--user', '0:0', '--entrypoint', '/bin/sh', '--', '-ec',
                'work=$(mktemp -d /tmp/md-fuse-close-build.XXXXXXXX); '
                'trap \'rm -rf "$work"\' EXIT; '
                'cc -x c -Wall -Wextra -Werror -O2 -pthread /mnt/fixture -o "$work/close"; '
                '"$work/close"; "$work/close" --filtered')
        elif args.case == 'portal':
            command = [suite.runner, '--store', args.store, '--bind-ro', suite.base, '/mnt',
                       *registry,
                       '--user', args.portal_user,
                       '--env', 'HOME=' + args.portal_home, '--env', 'PATH=/usr/bin:/bin',
                       *(['--env', 'G_MESSAGES_DEBUG=xdg-desktop-portal'] if args.debug else []),
                       '--', '/bin/sh', '-ec',
                       'XDG_RUNTIME_DIR=$(mktemp -d /tmp/md-fuse-portal.XXXXXXXX); '
                       'export XDG_RUNTIME_DIR; '
                       'trap \'fusermount3 -u -z "$XDG_RUNTIME_DIR/doc" 2>/dev/null || :; '
                       'rm -rf "$XDG_RUNTIME_DIR"\' EXIT; '
                       'dbus-run-session -- /bin/sh /mnt/fixture']
        else:
            command = suite.run(args.store, *registry, '--bind-ro', suite.base, '/mnt',
                                '--user', '0:0', '--entrypoint', '/usr/bin/python3', '--', '/mnt/fixture')
        suite.command(command, timeout=180)
        suite.report.update(case=args.case, passed=True)
    finally:
        suite.finish()


if __name__ == '__main__':
    main()

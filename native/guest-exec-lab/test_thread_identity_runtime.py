#!/usr/bin/env python3
"""Check libc thread identity during PID-namespace birth publication."""
import argparse
from pathlib import Path
from test_oci_services import Suite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    parser.add_argument('fixture', type=Path)
    parser.add_argument('--debuggers', action='store_true', help='Also exercise installed strace and GDB')
    parser.add_argument('--libc-registry')
    args = parser.parse_args()
    suite = Suite(args.build, args.build)
    target = '/tmp/md-thread-' + suite.report['id']
    base = [suite.runner, '--store', args.store, '--user', '0:0']
    if args.libc_registry:
        base += ['--libc-registry', args.libc_registry]
    try:
        suite.transport.upload(suite.client, args.fixture, suite.base + '/thread')
        suite.command(['chmod', '700', suite.base + '/thread'])
        suite.command(base + ['--', '/bin/mkdir', target])
        if args.libc_registry:
            root = Path(__file__).resolve().parents[2]
            for source in ('native/guest-exec-lab/test_libc_selection_guest.c',
                           'native/shroot/src/cooperative_entry.h'):
                suite.transport.upload(suite.client, root / source, suite.base + '/' + Path(source).name)
            suite.command(base + ['--bind', suite.base, target, '--', '/usr/bin/cc',
                '-O2', '-I' + target, target + '/test_libc_selection_guest.c', '-ldl', '-o', target + '/libc-probe'])
            suite.command(base + ['--bind-ro', suite.base, target, '--', target + '/libc-probe', 'shroot'])
        for wrapper in ([], ['/usr/bin/unshare', '--pid', '--fork', '--mount-proc']):
            suite.command(base + ['--bind-ro', suite.base, target, '--deadline-seconds', '20', '--']
                          + wrapper + [target + '/thread'], timeout=30)
            output = suite.command(base + ['--bind-ro', suite.base, target, '--deadline-seconds', '20', '--']
                                   + wrapper + [target + '/thread', '--pid-futex'], timeout=30)
            assert 'PASS PI futex admission' in output, output
        if args.debuggers:
            namespace = ['/usr/bin/unshare', '--pid', '--fork', '--mount-proc']
            trace = ['/usr/bin/strace', '-f', '-qq', '-o', '/dev/null']
            # Trace from the parent namespace as well: the tracer and signal
            # recipient must not share the same siginfo PID translation.
            for wrapper in (trace, trace + namespace):
                output = suite.command(base + ['--bind-ro', suite.base, target, '--deadline-seconds', '60', '--']
                                       + wrapper + [target + '/thread'], timeout=70)
                assert 'PASS thread identity:' in output, output
            for debugger in (['/usr/bin/strace', '-f', '-qq', '-o', '/dev/null'],
                             ['/usr/bin/gdb', '-nx', '-batch',
                              '-ex', 'set debuginfod enabled off', '-ex', 'set disable-randomization off',
                              '-ex', 'run', '--args']):
                output = suite.command(base + ['--bind-ro', suite.base, target, '--deadline-seconds', '60', '--']
                                       + namespace + debugger + [target + '/thread'], timeout=70)
                assert 'PASS thread identity:' in output, output
                if args.libc_registry:
                    output = suite.command(base + ['--bind-ro', suite.base, target, '--deadline-seconds', '60', '--']
                                           + namespace + debugger + [target + '/libc-probe', 'base'], timeout=70)
                    assert 'PASS libc selection: base' in output, output
        suite.report['passed'] = True
    finally:
        try:
            suite.command(base + ['--', '/bin/rmdir', target])
        finally:
            suite.finish()


if __name__ == '__main__':
    main()

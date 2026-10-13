#!/usr/bin/env python3
"""Device creation authority and retained native-device bind mounts under shell."""
import argparse
from contextlib import ExitStack
import ctypes
import errno
import os
from pathlib import Path
import stat
import sys
import tempfile


def guest():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long

    def call(nr, *args):
        values = [ctypes.c_char_p(str(a).encode()) if isinstance(a, (str, Path))
                  else ctypes.c_long(a) for a in args]
        result = libc.syscall(ctypes.c_long(nr), *values)
        if result < 0:
            raise OSError(ctypes.get_errno(), str((nr, args)))
        return result

    def denied(action, code):
        try:
            action()
            raise AssertionError('unexpected success')
        except OSError as error:
            assert error.errno == code, error

    with tempfile.TemporaryDirectory(prefix='md-devices-') as directory, ExitStack() as cleanup:
        root = Path(directory)
        # CAP_MKNOD authorizes guest metadata, never Android device creation.
        assert call(167, 23, 27, 0, 0, 0) == 1
        for kind, device in ((stat.S_IFCHR, os.makedev(1, 3)),
                             (stat.S_IFBLK, os.makedev(7, 0))):
            path = root / 'logical'
            os.mknod(path, kind | 0o600, device)
            node = path.stat()
            assert stat.S_IFMT(node.st_mode) == kind and node.st_rdev == device
            path.unlink()
        print('PASS logical device creation preserves kind and rdev', flush=True)

        for name in ('full', 'null', 'zero', 'random', 'urandom', 'tty'):
            source, target = Path('/dev') / name, root / name
            native = source.stat()
            assert stat.S_ISCHR(native.st_mode)
            read_denied = False
            if name == 'full':
                try:
                    check = os.open(source, os.O_RDWR | os.O_NOCTTY)
                except PermissionError:
                    print('NATIVE_DENIED /dev/full: Android shell cannot open the source', flush=True)
                    read_denied = True
                else:
                    os.close(check)
            target.touch()
            descriptor = os.open(target, os.O_PATH)
            try:
                # The same proc-FD destination used by ordinary container runtimes.
                call(40, source, '/proc/self/fd/' + str(descriptor), 0, 4096, 0)
            finally:
                os.close(descriptor)
            cleanup.callback(libc.syscall, ctypes.c_long(39), ctypes.c_char_p(str(target).encode()), ctypes.c_long(2))
            bound = target.stat()
            assert stat.S_ISCHR(bound.st_mode) and bound.st_rdev == native.st_rdev
            print('PASS bind', name, flush=True)
            if read_denied:
                denied(lambda: os.open(target, os.O_RDWR | os.O_NOCTTY), errno.EACCES)
                print('PASS bound device retains native data-access denial', flush=True)
                continue
            if name == 'tty':
                continue  # This non-PTY automation launch has no controlling terminal.
            fd = os.open(target, os.O_RDWR | os.O_NOCTTY)
            try:
                assert os.fstat(fd).st_rdev == native.st_rdev
                if name == 'null':
                    assert os.write(fd, b'discard') == 7 and os.read(fd, 8) == b''
                elif name in ('zero', 'full'):
                    assert os.read(fd, 8) == b'\0' * 8
                    if name == 'full':
                        denied(lambda: os.write(fd, b'x'), errno.ENOSPC)
                else:
                    assert len(os.read(fd, 8)) == 8
            finally:
                os.close(fd)
        print('PASS native device binds, proc-FD destinations, rdev and real device IO', flush=True)

        target = root / 'null'
        retained = os.open(target, os.O_RDWR)
        try:
            call(40, 0, target, 0, 4096 | 32 | 4, 0)  # bind remount,nodev
            denied(lambda: os.open(target, os.O_RDWR), errno.EACCES)
            fd = os.open(target, os.O_PATH)
            os.close(fd)
            call(39, target, 2)
            assert stat.S_ISREG(target.stat().st_mode)
            assert os.write(retained, b'x') == 1 and os.read(retained, 1) == b''
        finally:
            os.close(retained)
        print('PASS nodev admission and open device lifetime after detach', flush=True)

        regular, fifo = root / 'regular', root / 'fifo'
        os.mknod(regular, stat.S_IFREG | 0o600)
        os.mknod(fifo, stat.S_IFIFO | 0o600)
        assert stat.S_ISREG(regular.stat().st_mode) and stat.S_ISFIFO(fifo.stat().st_mode)
        root.chmod(0o777)
        child = os.fork()
        if child == 0:
            try:
                os.setuid(123)
                denied(lambda: os.mknod(root / 'unprivileged', stat.S_IFCHR | 0o600, os.makedev(1, 3)), errno.EPERM)
                os._exit(0)
            except BaseException:
                import traceback
                traceback.print_exc()
                os._exit(1)
        # EVENT_WAIT: child exit; the supervised deadline bounds a stalled child.
        assert os.waitpid(child, 0)[1] == 0
        print('PASS ordinary file/FIFO creation and non-root device denial', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    args = parser.parse_args()
    from test_oci_services import Suite
    suite = Suite(args.build, args.build)
    target = '/tmp/md-devices-' + suite.report['id']
    prefix = [suite.runner, '--store', args.store, '--user', '0:0']
    try:
        suite.transport.upload(suite.client, Path(__file__), suite.base + '/test.py')
        suite.command(prefix + ['--', '/bin/mkdir', target])
        suite.command(prefix + ['--bind-ro', suite.base, target, '--deadline-seconds', '90', '--',
                                '/usr/bin/unshare', '--mount', '/usr/bin/python3', target + '/test.py', '--guest'],
                      timeout=110)
        suite.report['passed'] = True
    finally:
        try:
            suite.command(prefix + ['--', '/bin/rmdir', target])
        finally:
            suite.finish()


if __name__ == '__main__':
    if sys.argv[1:] == ['--guest']:
        guest()
    else:
        main()

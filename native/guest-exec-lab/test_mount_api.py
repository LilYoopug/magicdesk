#!/usr/bin/env python3
"""Descriptor mount API and stock util-linux consumers, through actual shell."""
import argparse
import array
import ctypes
import errno
import fcntl
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor


def guest():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long

    def call(nr, *args, error=None):
        converted = [ctypes.c_char_p(arg.encode()) if isinstance(arg, str)
                     else ctypes.c_long(arg) for arg in args]
        result = libc.syscall(ctypes.c_long(nr), *converted)
        code = ctypes.get_errno() if result < 0 else 0
        assert code == (error or 0), (nr, args, result, code, error)
        return result

    def config(fd, key, value=None):
        return call(431, fd, 0 if value is None else 1, key, 0 if value is None else value, 0)

    def create(kind='tmpfs', **options):
        fd = call(430, kind, 1)
        for key, value in options.items():
            config(fd, key, value)
        call(431, fd, 6, 0, 0, 0)
        return fd

    def attributes(path='', fd=-100, flags=0, set_bits=0, clear_bits=0, propagation=0,
                   userns=0, tail=None, error=None):
        words = [set_bits, clear_bits, propagation, userns]
        if tail is not None:
            words.append(tail)
        value = (ctypes.c_uint64 * len(words))(*words)
        return call(442, fd, str(path), flags, ctypes.addressof(value), ctypes.sizeof(value), error=error)

    def write_denied(path):
        try:
            Path(path).write_text('not allowed')
            raise AssertionError('readonly mount accepted a write')
        except OSError as error:
            assert error.errno == errno.EROFS, error

    # The launch enters a child user/mount namespace but retains its parent's
    # cgroup namespace. fsopen must not acquire the authority of a later unshare.
    old_context = call(430, 'cgroup2', 1)
    call(97, 0x02000000)  # AArch64 unshare(CLONE_NEWCGROUP).
    call(431, old_context, 6, 0, 0, 0, error=errno.EPERM)
    os.close(old_context)
    print('PASS cgroup fscontext retains namespace authority', flush=True)

    with tempfile.TemporaryDirectory(prefix='md-fsopen-') as directory:
        root = Path(directory)
        call(430, 'unknown', 0, error=errno.ENODEV)
        call(430, 'tmpfs', 2, error=errno.EINVAL)
        call(431, 123456, 6, 0, 0, 0, error=errno.EBADF)
        with open('/dev/null', 'rb') as ordinary:
            call(431, ordinary.fileno(), 6, 0, 0, 0, error=errno.EINVAL)
        fd = call(430, 'tmpfs', 0)
        assert not fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        for action, expected in [(lambda: os.read(fd, 10), errno.ENODATA),
                                 (lambda: os.lseek(fd, 0, os.SEEK_SET), errno.ESPIPE),
                                 (lambda: os.pread(fd, 10, 0), errno.ESPIPE)]:
            try:
                action()
                raise AssertionError('fscontext IO unexpectedly succeeded')
            except OSError as error:
                assert error.errno == expected, error
        call(432, fd, 1, 0, error=errno.EINVAL)
        call(431, fd, 0, 'unsupported', 0, 0, error=errno.EOPNOTSUPP)
        call(431, fd, 0, 'size', 0, 0, error=errno.EINVAL)
        config(fd, 'mode', '0700')
        config(fd, 'size', '1')
        config(fd, 'nr_blocks', '1')
        config(fd, 'nr_inodes', '1')
        duplicate = os.dup(fd)
        os.close(fd)
        call(431, duplicate, 6, 0, 0, 0)
        call(431, duplicate, 6, 0, 0, 0, error=errno.EBUSY)
        call(432, duplicate, 1, 0x30, error=errno.EINVAL)
        mount = call(432, duplicate, 1, 0x20)  # MOUNT_ATTR_STRICTATIME is a backing hint.
        assert fcntl.fcntl(mount, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        assert fcntl.fcntl(mount, fcntl.F_GETFL) & os.O_PATH
        os.close(duplicate)
        assert os.fstat(mount).st_mode & 0o777 == 0o700
        nested = os.open('before-attach', os.O_CREAT | os.O_RDWR, 0o600, dir_fd=mount)
        os.write(nested, b'kept')
        os.ftruncate(nested, 16384)
        assert os.pwrite(nested, b'beyond', 8192) == 6
        os.ftruncate(nested, 4)
        os.close(nested)
        assert not (root / 'before-attach').exists()
        call(429, mount, '', -100, str(root), 4)
        assert (root / 'before-attach').read_bytes() == b'kept'
        (root / 'moved').mkdir()
        call(429, mount, '', -100, str(root / 'moved'), 4, error=errno.EINVAL)
        call(39, str(root), 2)
        assert not (root / 'before-attach').exists()
        call(429, mount, '', -100, str(root), 4, error=errno.EINVAL)
        os.close(mount)
        print('PASS fscontext state, dup, detached IO, attach and unmount', flush=True)

        # Real SCM_RIGHTS transfers retain authority, not the carrier inode.
        left, right = socket.socketpair()
        context = create(mode='0751')
        left.sendmsg([b'x'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [context]))])
        os.close(context)
        _, ancillary, _, _ = right.recvmsg(1, socket.CMSG_SPACE(4))
        received = array.array('i')
        received.frombytes(ancillary[0][2])
        mount = call(432, received[0], 0, 1)
        os.close(received[0])
        assert not fcntl.fcntl(mount, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        call(429, mount, '', -100, str(root), 4)
        os.close(mount)
        try:
            (root / 'readonly').write_text('not allowed')
            raise AssertionError('readonly mount accepted a write')
        except OSError as error:
            assert error.errno == errno.EROFS, error
        call(39, str(root), 2)
        left.close()
        right.close()
        print('PASS SCM_RIGHTS filesystem context and readonly policy', flush=True)

        context = create(mode='0750')
        child = os.fork()
        if child == 0:
            mount = call(432, context, 1, 0)
            call(429, mount, '', -100, str(root), 4)
            os.close(mount)
            os._exit(0)
        # EVENT_WAIT: child completion; outer supervised deadline fails a hang.
        assert os.waitpid(child, 0)[1] == 0
        os.close(context)
        assert root.stat().st_mode & 0o777 == 0o750
        call(39, str(root), 2)
        print('PASS inherited fscontext and shared mount publication', flush=True)

        # Zero attributes skip path lookup, but malformed structures never do.
        zero = (ctypes.c_uint64 * 4)()
        call(442, -1, 0, 0, ctypes.addressof(zero), 32)
        call(442, -100, str(root), 0, 0, 31, error=errno.EINVAL)
        call(442, -100, str(root), 0, 0, os.sysconf('SC_PAGE_SIZE') + 1, error=errno.E2BIG)
        call(442, -100, str(root), 0, 1, 32, error=errno.EFAULT)
        call(442, -100, str(root), 1, ctypes.addressof(zero), 32, error=errno.EINVAL)
        attributes(root, tail=1, error=errno.E2BIG)
        attributes(root, set_bits=1 << 63, error=errno.EINVAL)
        attributes(root, set_bits=0x20, error=errno.EINVAL)
        attributes(root, clear_bits=0x10, error=errno.EINVAL)
        attributes(root, set_bits=0x30, clear_bits=0x70, error=errno.EINVAL)
        attributes(root, set_bits=0x100000, error=errno.EOPNOTSUPP)  # IDMAP
        attributes(root, set_bits=0x200000, error=errno.EOPNOTSUPP)  # NOSYMFOLLOW
        attributes(root, propagation=(1 << 18) | (1 << 19), error=errno.EINVAL)
        attributes(root, propagation=1 << 20, error=errno.EOPNOTSUPP)  # SHARED
        context = create()
        mount = call(432, context, 1, 0)
        os.close(context)
        attributes(fd=mount, set_bits=1, error=errno.ENOENT)
        attributes(fd=mount, flags=0x1000, set_bits=1, tail=0)
        try:
            os.open('blocked', os.O_CREAT | os.O_WRONLY, 0o600, dir_fd=mount)
            raise AssertionError('detached readonly mount accepted a write')
        except OSError as error:
            assert error.errno == errno.EROFS, error
        attributes(fd=mount, flags=0x1000, clear_bits=1)
        call(429, mount, '', -100, str(root), 4)
        (root / 'child').mkdir()
        (root / 'ordinary').mkdir()
        attributes(root / 'ordinary', set_bits=1, error=errno.EINVAL)
        context = create()
        child_mount = call(432, context, 1, 0)
        os.close(context)
        call(429, child_mount, '', -100, str(root / 'child'), 4)
        os.close(child_mount)
        (root / 'child' / 'value').write_text('child')
        (root / 'value').write_text('root')
        alias = root / 'link'
        alias.symlink_to(root / 'child', target_is_directory=True)
        attributes(alias, flags=0x100, set_bits=1, error=errno.EINVAL)  # NOFOLLOW
        attributes(alias, set_bits=1)
        write_denied(root / 'child' / 'blocked')
        attributes(root, set_bits=2)  # NOSUID on parent only.
        assert os.statvfs(root).f_flag & os.ST_NOSUID
        assert not os.statvfs(root / 'child').f_flag & os.ST_NOSUID
        attributes(root, clear_bits=2)

        child = os.fork()
        if child == 0:
            try:
                assert libc.prctl(4, 0, 0, 0, 0) == 0  # PR_SET_DUMPABLE
                attributes(root, set_bits=8)
                assert os.statvfs(root).f_flag & os.ST_NOEXEC
                attributes(root, clear_bits=8)
                os.setresuid(1, 1, 1)
                call(442, -1, 0, 0, ctypes.addressof(zero), 32, error=errno.EPERM)
                os._exit(0)
            except BaseException:
                import traceback
                traceback.print_exc()
                os._exit(1)
        # EVENT_WAIT: protected caller and authority check; outer deadline fails a hang.
        assert os.waitpid(child, 0)[1] == 0

        child = os.fork()
        if child == 0:
            try:
                call(97, 0x10000000 | 0x20000)  # NEWUSER | NEWNS, locks inherited policy.
                Path('/proc/self/uid_map').write_text('0 0 1\n')
                Path('/proc/self/setgroups').write_text('deny\n')
                Path('/proc/self/gid_map').write_text('0 0 1\n')
                attributes(root, flags=0x8000, set_bits=2, clear_bits=1, error=errno.EPERM)
                assert not os.statvfs(root).f_flag & os.ST_NOSUID
                assert not os.statvfs(root / 'child').f_flag & os.ST_NOSUID
                assert os.statvfs(root / 'child').f_flag & os.ST_RDONLY
                (root / 'parent-still-writable').write_text('kept')
                os._exit(0)
            except BaseException:
                import traceback
                traceback.print_exc()
                os._exit(1)
        # EVENT_WAIT: namespace child completion; outer deadline fails a hang.
        assert os.waitpid(child, 0)[1] == 0
        attributes(root, flags=0x8000, set_bits=1 | 2 | 4 | 8)
        write_denied(root / 'blocked')
        write_denied(root / 'child' / 'blocked')
        for path in (root, root / 'child'):
            assert os.statvfs(path).f_flag & 15 == 15
        attributes(root, flags=0x8000, set_bits=0x20, clear_bits=15 | 0x70, propagation=1 << 18)
        (root / 'value').write_text('writable')
        (root / 'child' / 'value').write_text('writable')
        # Retained descriptors observe the same policy after attachment.
        attributes(fd=mount, flags=0x1000, set_bits=1, clear_bits=1)
        write_denied(root / 'blocked')
        attributes(fd=mount, flags=0x1000, clear_bits=1)
        call(39, str(root), 2)
        attributes(fd=mount, flags=0x1000, set_bits=1, error=errno.EINVAL)
        os.close(mount)
        print('PASS mount_setattr: ABI, detached FD, recursive policy, locked rollback and retained origins', flush=True)

        # openat2 shares the versioned-structure reader, not mount semantics.
        how = (ctypes.c_uint64 * 4)(os.O_PATH, 0, 0, 0)
        opened = call(437, -100, str(root), ctypes.addressof(how), ctypes.sizeof(how))
        os.close(opened)
        how[3] = 1
        call(437, -100, str(root), ctypes.addressof(how), ctypes.sizeof(how), error=errno.E2BIG)
        call(437, -100, str(root), ctypes.addressof(how), 23, error=errno.EINVAL)
        call(437, -100, str(root), 1, 24, error=errno.EFAULT)
        print('PASS shared structure reader: openat2 zero extension and invalid buffers', flush=True)

        for kind, options in [('tmpfs', 'mode=0755,size=65536k,strictatime'), ('cgroup2', None), ('cgroup', 'devices'),
                              ('proc', None), ('devpts', 'newinstance,ptmxmode=0666,mode=0620')]:
            command = ['strace', '-e', 'trace=fsopen,fsconfig,fsmount,move_mount,mount_setattr',
                       'mount', '-t', kind]
            if options:
                command += ['-o', options]
            result = subprocess.run(command + ['none', str(root)], capture_output=True, text=True)
            print(result.stderr, end='', flush=True)
            assert result.returncode == 0, result
            assert 'fsopen(' in result.stderr and 'move_mount(' in result.stderr, result.stderr
            opened = os.open(root, os.O_PATH | os.O_DIRECTORY)
            try:
                link = '/proc/self/fd/' + str(opened)
                assert os.readlink(link) == str(root), (kind, os.readlink(link))
                with ThreadPoolExecutor(max_workers=1) as workers:
                    linked = workers.submit(os.readlink, link).result(timeout=10)
                assert linked == str(root), (kind, 'threaded proc fd', linked)
            finally:
                os.close(opened)
            if kind == 'cgroup':
                entries = Path('/proc/self/mountinfo').read_text().splitlines()
                entry = next(line for line in entries if line.split()[4] == str(root))
                assert 'devices' in entry.split(' - ')[1].split()[2].split(','), entry
            call(39, str(root), 2)
        print('PASS stock util-linux mount using new API', flush=True)

        for part in ('lower', 'upper', 'work', 'merged'):
            (root / part).mkdir()
        (root / 'lower' / 'value').write_text('lower')
        context = create('overlay', lowerdir=str(root / 'lower'), upperdir=str(root / 'upper'),
                         workdir=str(root / 'work'))
        mount = call(432, context, 1, 0)
        os.close(context)
        call(429, mount, '', -100, str(root / 'merged'), 4)
        os.close(mount)
        assert (root / 'merged' / 'value').read_text() == 'lower'
        (root / 'merged' / 'value').write_text('upper')
        assert (root / 'lower' / 'value').read_text() == 'lower'
        assert (root / 'upper' / 'value').read_text() == 'upper'
        call(39, str(root / 'merged'), 2)
        print('PASS overlay through the common filesystem provider', flush=True)

        before = len(os.listdir('/proc/self/fd'))
        for _ in range(96):
            context = create(mode='0700')
            mount = call(432, context, 1, 0)
            os.close(context)
            os.close(mount)
        assert len(os.listdir('/proc/self/fd')) == before
        print('PASS abandoned detached mounts: slot reuse and descriptor release', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    args = parser.parse_args()
    from test_oci_services import Suite
    suite = Suite(args.build, args.build)
    target = '/tmp/md-mount-api-' + suite.report['id']
    prefix = [suite.runner, '--store', args.store, '--user', '0:0']
    try:
        suite.transport.upload(suite.client, Path(__file__), suite.base + '/test.py')
        suite.command(prefix + ['--', '/bin/mkdir', target])
        command = prefix + ['--bind-ro', suite.base, target, '--deadline-seconds', '100', '--',
                            '/usr/bin/unshare', '--user', '--map-users=0:0:65536', '--map-groups=0:0:65536',
                            '--mount', '--pid', '--fork', '/usr/bin/python3', target + '/test.py', '--guest']
        suite.command(command, timeout=120)
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

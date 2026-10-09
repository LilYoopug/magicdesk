#!/usr/bin/env python3
"""Foreign proc-root lookup retains the selected namespace, not Android's root."""
import ctypes
import errno
import os
import shutil
import signal
import socket
import stat
import tempfile

libc = ctypes.CDLL(None, use_errno=True)


def native(call, *args):
    result = call(*args)
    if result < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return result


def rejects(code, call, *args, **kwargs):
    try:
        result = call(*args, **kwargs)
    except OSError as error:
        assert error.errno == code, error
    else:
        raise AssertionError(('expected errno', code, 'got', result))


def readat(fd, path):
    child = os.open(path, os.O_RDONLY, dir_fd=fd)
    try:
        return os.read(child, 100)
    finally:
        os.close(child)


def status_identity(process, uid, gid):
    with open(f'/proc/{process}/status') as stream:
        fields = dict(line.rstrip().split(':', 1) for line in stream)
    assert list(map(int, fields['Uid'].split())) == [uid] * 4, fields['Uid']
    assert list(map(int, fields['Gid'].split())) == [gid] * 4, fields['Gid']
    assert int(fields['TracerPid']) == 0, fields['TracerPid']


def fdinfo(fd, process='self'):
    with open(f'/proc/{process}/fdinfo/{fd}') as stream:
        return dict(line.rstrip().split(':', 1) for line in stream)


def descriptor_info():
    pidfd = os.pidfd_open(os.getpid())
    try:
        fields = fdinfo(pidfd)
        assert int(fields['Pid']) == os.getpid(), (fields, os.getpid())
        if os.getpid() == 1 or 'NSpid' in fields:
            assert int(fields['NSpid'].split()[0]) == os.getpid(), fields
        os.set_inheritable(pidfd, True)
        assert not (int(fdinfo(pidfd)['flags'], 8) & os.O_CLOEXEC)
        os.set_inheritable(pidfd, False)
        assert int(fdinfo(pidfd)['flags'], 8) & os.O_CLOEXEC
        with open(f'/proc/self/fdinfo/{pidfd}', 'rb', buffering=0) as stream:
            first = stream.read(4)
            duplicate = os.dup(stream.fileno())
            try:
                rest = os.read(duplicate, 4096)
                assert first + rest == os.pread(stream.fileno(), 4096, 0)
                os.close(pidfd)
                pidfd = -1
                stream.seek(0)
                rejects(errno.ENOENT, stream.read, 4096)
            finally:
                os.close(duplicate)
    finally:
        if pidfd >= 0:
            os.close(pidfd)
    with tempfile.TemporaryFile() as stream:
        stream.write(b'ordinary descriptor')
        stream.flush()
        assert int(fdinfo(stream.fileno())['pos']) == stream.tell()
        stream.seek(3)
        assert int(fdinfo(stream.fileno())['pos']) == 3
    a, b = socket.socketpair()
    try:
        try:
            pidfd = a.getsockopt(socket.SOL_SOCKET, 77)  # SO_PEERPIDFD, optional since 6.5
        except OSError as error:
            assert error.errno in (errno.ENOPROTOOPT, errno.EINVAL, errno.ENOSYS), error
        else:
            try:
                assert int(fdinfo(pidfd)['Pid']) == os.getpid()
            finally:
                os.close(pidfd)
    finally:
        a.close()
        b.close()


def signal_identity():
    ready, notify = os.pipe()
    child = os.fork()
    if not child:
        os.close(ready)
        os.setgid(1234)
        os.setuid(1234)
        os.write(notify, b'R')
        signal.pause()
        os._exit(1)
    os.close(notify)
    try:
        # EVENT_WAIT: child publishes its new credentials; harness owns timeout.
        assert os.read(ready, 1) == b'R'
        denied = os.fork()
        if not denied:
            try:
                os.setgid(2345)
                os.setuid(2345)
                rejects(errno.EPERM, os.kill, child, 0)
            except BaseException:
                os._exit(1)
            os._exit(0)
        assert os.waitpid(denied, 0)[1] == 0
        os.kill(child, signal.SIGTERM)
        assert os.waitpid(child, 0)[1] == signal.SIGTERM
    finally:
        os.close(ready)


def main():
    status_identity('self', 0, 0)
    if os.getpid() == 1:
        signal_identity()
    descriptor_info()
    protected_info = os.fork()
    if not protected_info:
        try:
            native(libc.prctl, 4, 0, 0, 0, 0)
            descriptor_info()
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(1)
        os._exit(0)
    assert os.waitpid(protected_info, 0)[1] == 0
    root = tempfile.mkdtemp(prefix='proc-root-')
    os.mkdir(root + '/mounted')
    with open(root + '/identity', 'wb') as stream:
        stream.write(b'guest root')
    ready, notify = os.pipe()
    release, done = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(ready)
            os.close(done)
            native(libc.unshare, 0x00020000)  # CLONE_NEWNS
            native(libc.mount, b'tmpfs', os.fsencode(root + '/mounted'), b'tmpfs', 0, b'mode=755')
            with open(root + '/mounted/private', 'wb') as stream:
                stream.write(b'private mount')
            os.chroot(root)
            os.chdir('/')
            os.write(notify, b'R')
            # EVENT_WAIT: parent owns inspection; the harness deadline cancels failure.
            assert os.read(release, 1) == b'Q'
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(1)
        os._exit(0)
    os.close(notify)
    os.close(release)
    fd = duplicate = -1
    try:
        assert os.read(ready, 1) == b'R'
        status_identity(pid, 0, 0)
        path = f'/proc/{pid}/root'
        assert stat.S_ISDIR(os.stat(path).st_mode)
        assert stat.S_ISLNK(os.lstat(path).st_mode)
        rejects(errno.ELOOP, os.open, path, os.O_RDONLY | os.O_NOFOLLOW)
        fd = os.open(path, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        duplicate = os.dup(fd)
        directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            assert sorted(os.listdir(directory)) == ['identity', 'mounted']
        finally:
            os.close(directory)
        rejects(errno.ENOENT, readat, fd, '.flatpak-info')
        assert readat(fd, 'identity') == b'guest root'
        assert readat(fd, 'mounted/private') == b'private mount'
        assert open(path + '/mounted/private', 'rb').read() == b'private mount'
        assert not os.path.exists(root + '/mounted/private')
        assert os.readlink(path) == root, (os.readlink(path), root)
        created = os.open('created', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
        os.close(created)
        assert os.path.isfile(root + '/created')
        # A process with different logical credentials must not borrow this root.
        denied = os.fork()
        if denied == 0:
            try:
                os.setgid(1234)
                os.setuid(1234)
                status_identity('self', 1234, 1234)
                status_identity(pid, 0, 0)
                rejects(errno.EACCES, os.open, path, os.O_PATH | os.O_DIRECTORY)
            except BaseException:
                os._exit(1)
            os._exit(0)
        assert os.waitpid(denied, 0)[1] == 0
        protected = os.fork()
        if protected == 0:
            try:
                native(libc.prctl, 4, 0, 0, 0, 0)  # PR_SET_DUMPABLE
                protected_fd = os.open(path, os.O_PATH | os.O_DIRECTORY)
                assert readat(protected_fd, 'mounted/private') == b'private mount'
                os.close(protected_fd)
            except BaseException:
                import traceback
                traceback.print_exc()
                os._exit(1)
            os._exit(0)
        assert os.waitpid(protected, 0)[1] == 0
        os.write(done, b'Q')
        assert os.waitpid(pid, 0)[1] == 0
        pid = None
        rejects(errno.ENOENT, os.open, path, os.O_RDONLY | os.O_DIRECTORY)
        assert readat(duplicate, 'mounted/private') == b'private mount'
        print('PASS foreign proc root: namespace, chroot, suffix, retained FD, protected reader, exit and denied identity', flush=True)
    finally:
        if pid is not None:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
        for number in (fd, duplicate, ready, done):
            if number >= 0:
                os.close(number)
        shutil.rmtree(root)


if __name__ == '__main__':
    main()

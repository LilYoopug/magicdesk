"""Private API filesystems and a real console for userspace init tests."""

TRACE_SYSCALLS = ('%file,%process,ioctl,mount_setattr,open_tree,move_mount,fsopen,fsconfig,fsmount,'
                  'prctl,seccomp,epoll_create1,epoll_ctl,epoll_pwait,epoll_pwait2')

PREPARE = r'''set -eux
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export container=shroot SYSTEMD_LOG_TARGET=console SYSTEMD_LOG_LEVEL=info
export SYSTEMD_LOG_COLOR=0 SYSTEMD_PAGER=cat LANG=C.UTF-8
test "$$" = 1
mount -t tmpfs -o mode=755 tmpfs /run
mount -t sysfs -o ro sysfs /sys
mount -t cgroup2 none /sys/fs/cgroup
console=$(tty)
mkdir -p /run/md-host-dev
mount --bind /dev /run/md-host-dev
mount -t tmpfs -o mode=755 tmpfs /dev
mkdir -p /dev/pts /dev/shm
for device in null zero full random urandom tty; do
    touch /dev/$device
    mount --bind /run/md-host-dev/$device /dev/$device
done
touch /dev/console
mount --bind "/run/md-host-dev/${console#/dev/}" /dev/console
mount -t devpts -o newinstance,ptmxmode=0666,mode=0620 devpts /dev/pts
ln -s pts/ptmx /dev/ptmx
umount /run/md-host-dev
'''

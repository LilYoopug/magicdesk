"""Private API filesystems and a real console for userspace init tests."""

TRACE_SYSCALLS = ('%file,%process,%network,ioctl,mount_setattr,open_tree,move_mount,fsopen,fsconfig,fsmount,'
                  'prctl,seccomp,epoll_create1,epoll_ctl,epoll_pwait,epoll_pwait2')

PREPARE = r'''set -eux
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export container=shroot SYSTEMD_LOG_TARGET=console SYSTEMD_LOG_LEVEL=info
export SYSTEMD_LOG_COLOR=0 SYSTEMD_PAGER=cat LANG=C.UTF-8
test "$$" = 1
# Preserve the launch-owned input provider across the private /run mount.
udev_mount=
if mountpoint -q /run/udev; then
    udev_mount=$(mktemp -d /mnt/md-init-udev.XXXXXXXX)
    mount --move /run/udev "$udev_mount"
fi
mount -t tmpfs -o mode=755 tmpfs /run
if [ -n "$udev_mount" ]; then
    mkdir -p /run/udev
    mount --move "$udev_mount" /run/udev
    rmdir "$udev_mount"
fi
mount -t tmpfs -o mode=1777 tmpfs /tmp
mount -t tmpfs -o mode=1777 tmpfs /var/tmp
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

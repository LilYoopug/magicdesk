"""Private API filesystems and a real console for userspace init tests."""
import shlex

TRACE_SYSCALLS = ('%file,%process,%network,ioctl,mount_setattr,open_tree,move_mount,fsopen,fsconfig,fsmount,'
                  'prctl,seccomp,epoll_create1,epoll_ctl,epoll_pwait,epoll_pwait2')

OPENRC_PREPARE = r'''
# Select stock container services in private configuration mounts. Do not
# rewrite packaged init/service scripts or enable host hardware management.
cp /etc/rc.conf /run/rc.conf
printf '\nrc_sys="docker"\nrc_verbose=yes\nrc_nocolor=yes\n' >> /run/rc.conf
mount --bind /run/rc.conf /etc/rc.conf
cp -a /etc/conf.d /run/conf.d
printf '\nlog_dmesg=no\n' >> /run/conf.d/bootmisc
mount --bind /run/conf.d /etc/conf.d
mount -t tmpfs tmpfs /etc/runlevels
mkdir -p /etc/runlevels/sysinit /etc/runlevels/boot /etc/runlevels/default /etc/runlevels/shutdown
for service in procfs sysfs cgroups; do rc-update add "$service" sysinit; done
for service in bootmisc hostname; do rc-update add "$service" boot; done
for service in syslog crond local; do rc-update add "$service" default; done
mount -t tmpfs tmpfs /etc/local.d
mkdir -p /run/openrc
'''

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
mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs /dev/shm
for device in null zero full random urandom tty; do
    touch /dev/$device
    mount --bind /run/md-host-dev/$device /dev/$device
done
# Keep launch-provided FUSE and graphics devices in every init scenario.
# Never expose arbitrary Android devices through the private /dev mount.
for node in fuse kgsl-3d0 dma_heap dri; do
    if [ -d /run/md-host-dev/$node ]; then mkdir -p /dev/$node
    elif [ -e /run/md-host-dev/$node ]; then touch /dev/$node
    else continue
    fi
    mount --bind /run/md-host-dev/$node /dev/$node
done
touch /dev/console
mount --bind "/run/md-host-dev/${console#/dev/}" /dev/console
mount -t devpts -o newinstance,ptmxmode=0666,mode=0620 devpts /dev/pts
ln -s pts/ptmx /dev/ptmx
umount /run/md-host-dev
'''


def installed_boot(target, port, token, init, desktop_user=None):
    """One init/control owner; a desktop driver is an optional dependent service."""
    control_args = f'{target}/session-controller.py {target} {port} {token}'
    services = [('control', '/usr/bin/python3', control_args)]
    if desktop_user is not None:
        services.append(('desktop', '/bin/bash', f'{target}/driver.sh'))
    boot = PREPARE + '''
mount --make-rshared /
unset XDG_DATA_DIRS XDG_CONFIG_DIRS XDG_RUNTIME_DIR DBUS_SESSION_BUS_ADDRESS
'''
    user = shlex.quote(desktop_user) if desktop_user is not None else None
    driver = None
    if init == 'systemd':
        units = ' '.join('md-installed-' + name + '.service' for name, _, _ in services)
        boot += f'''mkdir -p /run/systemd/system
cat > /run/systemd/system/md-installed.target <<EOF
[Unit]
DefaultDependencies=no
Requires=dbus.socket {units}
After=dbus.socket {units}
EOF
'''
        for name, command, arguments in services:
            boot += f'''cat > /run/systemd/system/md-installed-{name}.service <<EOF
[Unit]
DefaultDependencies=no
Conflicts=shutdown.target
Before=shutdown.target
[Service]
Type=simple
ExecStart={command} {arguments}
StandardOutput=append:{target}/{name}.log
StandardError=inherit
EOF
'''
        boot += 'exec /usr/bin/setpriv --bounding-set=-sys_module /usr/lib/systemd/systemd --system --unit=md-installed.target --show-status=no --crash-shell=no --crash-reboot=no\n'
        if user is not None:
            driver = f'''#!/bin/bash
set -eux
uid=$(id -u {user})
systemctl start dbus.socket systemd-logind.service systemd-user-sessions.service
systemctl start user@$uid.service
exec systemd-run --unit=md-installed-desktop-session --wait --collect --uid={user} --property=PAMName=login /bin/bash {target}/session.sh
'''
    elif init == 'openrc':
        boot += OPENRC_PREPARE + '''
cp -a /etc/init.d /run/md-init.d
mount --bind /run/md-init.d /etc/init.d
rc-update add dbus default
'''
        for name, command, arguments in services:
            boot += f'''cat > /etc/init.d/md-installed-{name} <<'EOF'
#!/sbin/openrc-run
command={command}
command_args="{arguments}"
command_background=yes
pidfile=/run/md-installed-{name}.pid
output_log={target}/{name}.log
error_log={target}/{name}.log
depend() {{ need dbus; }}
EOF
chmod 755 /etc/init.d/md-installed-{name}
rc-update add md-installed-{name} default
'''
        boot += 'exec /sbin/openrc-init\n'
        if user is not None:
            driver = f'''#!/bin/bash
set -eux
uid=$(id -u {user})
gid=$(id -g {user})
install -d -m 700 -o "$uid" -g "$gid" /run/user/$uid
exec setpriv --reuid="$uid" --regid="$gid" --init-groups /bin/bash {target}/session.sh
'''
    else:
        raise ValueError('Unsupported init: ' + init)
    return boot, driver

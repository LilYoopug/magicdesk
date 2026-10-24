#!/usr/bin/env python3
"""Host checks for shared nested-system readiness and TCP/UDP fixtures."""
from pathlib import Path
import io
import errno
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error

from init_fixture import installed_boot, start_service, enable_runit_service, RUNIT_START
from installed_desktop import wait_controller
from test_os_boot import check_runit_boot
from test_nixos_boot import boot_script
from test_snap import PREPARE as SNAP_PREPARE

sys.path.insert(0, str(Path(__file__).with_name('fixtures')))
from network_exchange import exchange
from systemd_ready import wait_systemd


class BootHelpers(unittest.TestCase):
    def test_nixos_boot_keeps_activation_and_selected_network_policy(self):
        for dhcp in (False, True):
            with self.subTest(dhcp=dhcp):
                boot = boot_script('/nix/store/system', '/nix/store/python/bin/python3', '/mnt/fixture', dhcp)
                self.assertLess(boot.index('/nix/store/system/activate'), boot.index('exec /sbin/init'))
                self.assertIn('systemctl is-system-running --wait', boot)
                self.assertIn('PASS boot service IO and restart', boot)
                self.assertEqual('umount /run/netns/md-nixos-client' in boot, dhcp)
                self.assertEqual('systemctl restart dhcpcd.service' in boot, dhcp)
                subprocess.run(['sh', '-n'], input=boot, text=True, check=True)

    def test_snap_prepares_existing_base_mounts(self):
        self.assertIn('systemctl start dbus.socket snapd.mounts.target snapd.socket\n'
                      'systemctl start snapd.service\nsnap version\n', SNAP_PREPARE)
        subprocess.run(['sh', '-n'], input=SNAP_PREPARE, text=True, check=True)

    def test_observer_cannot_hide_failed_runit_stage(self):
        observer = '\nPASS runit stock PID1 boot and service lifecycle\n'
        check_runit_boot('Mounting filesystems [done]' + observer)
        for failed in ('[fail]', '[ fail ]', '\x1b[1;34m[\x1b[1;35mfail\x1b[1;34m]\x1b[m'):
            with self.subTest(failed=failed), self.assertRaises(AssertionError):
                check_runit_boot('Mounting filesystems ' + failed + observer)

    def test_init_services(self):
        for init in ('systemd', 'openrc', 'runit'):
            for user in (None, 'fixture'):
                with self.subTest(init=init, user=user):
                    boot, driver = installed_boot('/opt/fixture', 12345, 'test-token', init, user)
                    self.assertIn('session-controller.py /opt/fixture 12345 test-token', boot)
                    self.assertEqual('driver.sh' in boot, user is not None)
                    self.assertEqual(driver is not None, user is not None)
                    self.assertNotIn('weston', boot)
                    self.assertIn('mount --rbind /dev /run/md-host-dev', boot)
                    self.assertIn('umount -l /run/md-host-dev', boot)
                    for name, target in [('fd', '/proc/self/fd'), ('stdin', '/proc/self/fd/0'),
                                         ('stdout', '/proc/self/fd/1'), ('stderr', '/proc/self/fd/2')]:
                        self.assertIn(f'ln -s {target} /dev/{name}', boot)
                    if init == 'systemd' and user is not None:
                        self.assertIn('systemctl start dbus.service ', driver)
                        self.assertNotIn('systemctl start dbus.socket', driver)
                    if init == 'runit':
                        self.assertIn('mount --bind /run/md-runit/runsvdir /etc/runit/runsvdir', boot)
                        self.assertNotIn('mount --bind /run/md-runit /etc/runit\n', boot)
                    for script in (boot, driver):
                        if script is not None:
                            subprocess.run(['sh', '-n'], input=script, text=True, check=True)

    def test_service_uses_selected_init(self):
        for init, expected in [('systemd', 'systemctl start docker.service'),
                               ('openrc', 'rc-service docker start'),
                               ('runit', ' /etc/runit/runsvdir/default/docker')]:
            command = start_service(init, 'docker')
            self.assertIn(expected, command)
            subprocess.run(['sh', '-n'], input=command, text=True, check=True)
        with self.assertRaises(ValueError):
            start_service('unknown', 'docker')

    def test_runit_waits_for_fifo_reader(self):
        with patch('sys.argv', ['fixture', '/service/test']), \
                patch('os.open', side_effect=[FileNotFoundError(errno.ENOENT, 'missing'),
                                             OSError(errno.ENXIO, 'no reader'), 7]) as opened, \
                patch('os.close') as close, patch('os.execvp') as execute, \
                patch('threading.Event') as event:
            exec(RUNIT_START, {})
        self.assertEqual(opened.call_count, 3)
        self.assertEqual(event.return_value.wait.call_count, 2)
        close.assert_called_once_with(7)
        execute.assert_called_once_with('sv', ['sv', '-w', '30', 'start', '/service/test'])

    def test_runit_stock_service_layouts(self):
        for layout in ('etc/sv', 'etc/runit/sv'):
            with self.subTest(layout=layout), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / 'etc/runit/runsvdir/default/docker'
                target.parent.mkdir(parents=True)
                source = root / layout / 'docker'
                source.mkdir(parents=True)
                (source / 'run').write_text('#!/bin/sh\nexec dockerd\n')
                command = enable_runit_service('docker').replace('/etc/', directory + '/etc/')
                for _ in range(2):
                    subprocess.run(['sh', '-eu', '-c', command], check=True, timeout=5)
                self.assertEqual(target.resolve(), source)
                (source / 'run').unlink()
                self.assertNotEqual(0, subprocess.run(['sh', '-eu', '-c', command], timeout=5).returncode)

    def test_runit_timeout_is_not_started(self):
        with patch('sys.argv', ['fixture', '/service/test']), \
                patch('os.open', side_effect=FileNotFoundError(errno.ENOENT, 'missing')), \
                patch('time.monotonic', side_effect=[0, 31]), patch('os.execvp') as execute:
            with self.assertRaises(TimeoutError):
                exec(RUNIT_START, {})
        execute.assert_not_called()

    def test_controller_connection_then_ready(self):
        with patch('installed_desktop.urllib.request.urlopen', side_effect=[
                urllib.error.URLError(ConnectionRefusedError(errno.ECONNREFUSED, 'not listening')),
                io.BytesIO(b'{"uid": 0}')]) as connect, patch('installed_desktop.threading.Event') as event:
            wait_controller(dict(rootPort=12345, token='test-token'))
        self.assertEqual(connect.call_count, 2)
        self.assertEqual(connect.call_args.args[0].get_header('Authorization'), 'Bearer test-token')
        event.return_value.wait.assert_called_once()

    def test_controller_rejection_is_not_retried(self):
        error = urllib.error.HTTPError('http://127.0.0.1', 403, 'Forbidden', {}, None)
        with patch('installed_desktop.urllib.request.urlopen', side_effect=error) as connect:
            with self.assertRaises(urllib.error.HTTPError):
                wait_controller(dict(rootPort=12345, token='test-token'))
        connect.assert_called_once()

    def test_user_controller_requires_selected_identity(self):
        state = dict(rootPort=12345, userPort=12346, userUid=1001, token='test-token')
        with patch('installed_desktop.urllib.request.urlopen', return_value=io.BytesIO(b'{"uid": 1001}')) as connect:
            wait_controller(state, user=True)
        self.assertEqual(connect.call_args.args[0].full_url, 'http://127.0.0.1:12346')
        for uid in (0, 1000):
            with self.subTest(uid=uid), patch('installed_desktop.urllib.request.urlopen',
                    return_value=io.BytesIO(json.dumps(dict(uid=uid)).encode())) as connect:
                with self.assertRaises(AssertionError):
                    wait_controller(state, user=True)
            connect.assert_called_once()

    def test_controller_deadline_is_failure(self):
        with patch('installed_desktop.time.monotonic', side_effect=[0, 91]):
            with self.assertRaisesRegex(AssertionError, 'did not become ready'):
                wait_controller(dict(rootPort=12345, token='test-token'))

    def test_ready(self):
        probe = Mock(return_value=subprocess.CompletedProcess([], 0, 'running\n', ''))
        alive = Mock()
        wait_systemd(probe, alive)
        alive.assert_not_called()
        self.assertGreater(probe.call_args.args[0], 0)

    def test_connection_then_ready(self):
        probe = Mock(side_effect=[
            subprocess.CompletedProcess([], 1, '', 'Failed to connect: No such file or directory'),
            subprocess.CompletedProcess([], 0, 'running\n', '')])
        alive = Mock()
        with patch('systemd_ready.threading.Event') as event:
            wait_systemd(probe, alive)
        alive.assert_called_once()
        event.return_value.wait.assert_called_once()

    def test_degraded_is_not_retried(self):
        probe = Mock(return_value=subprocess.CompletedProcess([], 1, 'degraded\n', ''))
        with self.assertRaises(AssertionError):
            wait_systemd(probe, Mock())
        probe.assert_called_once()

    def test_deadline_is_failure(self):
        probe = Mock()
        with patch('systemd_ready.time.monotonic', side_effect=[0, 91]):
            with self.assertRaisesRegex(AssertionError, 'did not become ready'):
                wait_systemd(probe, Mock())
        probe.assert_not_called()

    def test_network(self):
        def service(_python, *argv):
            return subprocess.run([sys.executable, *argv], capture_output=True, text=True,
                                  check=True, timeout=10)
        self.assertEqual(exchange(service, '127.0.0.1'), dict(tcp=20, udp=20))


if __name__ == '__main__':
    unittest.main()

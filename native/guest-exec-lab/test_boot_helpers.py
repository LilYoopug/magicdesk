#!/usr/bin/env python3
"""Host checks for shared nested-system readiness and TCP/UDP fixtures."""
from pathlib import Path
import io
import errno
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch
import urllib.error

from init_fixture import installed_boot
from installed_desktop import wait_controller

sys.path.insert(0, str(Path(__file__).with_name('fixtures')))
from network_exchange import exchange
from systemd_ready import wait_systemd


class BootHelpers(unittest.TestCase):
    def test_init_services(self):
        for init in ('systemd', 'openrc'):
            for user in (None, 'fixture'):
                with self.subTest(init=init, user=user):
                    boot, driver = installed_boot('/opt/fixture', 12345, 'test-token', init, user)
                    self.assertIn('session-controller.py /opt/fixture 12345 test-token', boot)
                    self.assertEqual('driver.sh' in boot, user is not None)
                    self.assertEqual(driver is not None, user is not None)
                    self.assertNotIn('weston', boot)
                    for script in (boot, driver):
                        if script is not None:
                            subprocess.run(['sh', '-n'], input=script, text=True, check=True)

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

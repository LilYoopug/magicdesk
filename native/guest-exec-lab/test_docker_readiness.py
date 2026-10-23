"""A started service is not a ready Docker API; preserve the startup bound."""
import queue
import subprocess
import unittest
from unittest.mock import patch

from probe_docker_runtime import wait_daemon_api


class DockerReadinessTest(unittest.TestCase):
    @patch('probe_docker_runtime.threading.Event')
    @patch('probe_docker_runtime.subprocess.run')
    def test_retries_recorded_without_claiming_failed_workload_commands(self, run, event):
        run.side_effect = [subprocess.CompletedProcess([], 1, 'not listening'),
                           subprocess.CompletedProcess([], 0, '{"Version":"29"}')]
        report = {}
        self.assertEqual('ready', wait_daemon_api('unix:///var/run/docker.sock', report))
        self.assertEqual([1, 0], [attempt['exitCode'] for attempt in report['startupAttempts']])
        event.return_value.wait.assert_called_once()
        self.assertNotIn('commands', report)

    @patch('probe_docker_runtime.threading.Event')
    @patch('probe_docker_runtime.time.monotonic', side_effect=[0, 44, 45, 45])
    @patch('probe_docker_runtime.subprocess.run', side_effect=subprocess.TimeoutExpired('docker', 1))
    def test_client_timeout_cannot_extend_startup_deadline(self, run, clock, event):
        report = {}
        with self.assertRaises(queue.Empty):
            wait_daemon_api('unix:///var/run/docker.sock', report)
        self.assertEqual(1, run.call_args.kwargs['timeout'])
        self.assertEqual([{'timeout': True}], report['startupAttempts'])


if __name__ == '__main__':
    unittest.main()

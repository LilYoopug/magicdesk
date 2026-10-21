"""CPU evidence must not confuse point readings with task execution frequency."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


spec = importlib.util.spec_from_file_location('benchmark_cpu',
    Path(__file__).resolve().parents[2] / 'native/guest-exec-lab/benchmark_cpu.py')
cpu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cpu)


def snapshot(counters=(100, 200), maximum=2000, cpus='0 1'):
    fields = dict(related_cpus=cpus, scaling_cur_freq=1000, scaling_min_freq=1000,
                  scaling_max_freq=maximum, cpuinfo_max_freq=3000, scaling_governor='test')
    output = ''.join(f'policy0\t{key}\t{value}\n' for key, value in fields.items())
    if counters is None:
        return output + 'policy0\tstats/time_in_state\t-\n'
    return output + ''.join(f'policy0\tstats/time_in_state\t{frequency} {ticks}\n'
                            for frequency, ticks in zip((1000, 2000), counters))


def interval(before, after):
    return cpu.policy_intervals({'policies': cpu.parse_snapshot(before)},
                                {'policies': cpu.parse_snapshot(after)})['policy0']


class BenchmarkCpuTest(unittest.TestCase):
    def test_preserves_point_readings_limits_and_counters(self):
        data = cpu.parse_snapshot(snapshot())['policy0']
        self.assertEqual(1000, data['scaling_cur_freq'])
        self.assertEqual(2000, data['scaling_max_freq'])
        self.assertEqual(3000, data['cpuinfo_max_freq'])
        self.assertEqual({'1000': 100, '2000': 200}, data['stats/time_in_state'])
        self.assertEqual('0 1', data['related_cpus'])

    def test_residency_not_arithmetic_average_of_endpoint_frequencies(self):
        data = interval(snapshot(), snapshot((110, 230)))
        self.assertEqual('available', data['status'])
        self.assertEqual({'1000': 10, '2000': 30}, data['timeInStateDeltaTicks'])
        self.assertEqual(1750, data['residencyWeightedKhz'])
        self.assertFalse(data['endpointLimitsDiffer'])

    def test_limit_changes_are_retained(self):
        data = interval(snapshot(), snapshot((110, 230), maximum=3000))
        self.assertTrue(data['endpointLimitsDiffer'])

    def test_missing_counter_reset_and_short_intervals_have_no_estimated_frequency(self):
        for after, reason in ((snapshot(None), 'time_in_state unavailable'),
                              (snapshot((1, 2)), 'time_in_state counters reset'),
                              (snapshot(), 'no time_in_state counter advance'),
                              (snapshot((110, 230), cpus='0 1 2'),
                               'policy disappeared or CPU membership changed'),
                              ('', 'policy disappeared or CPU membership changed'),
                              (snapshot((110, 230)).replace('2000 230', '3000 230'),
                               'frequency table changed')):
            with self.subTest(reason=reason):
                data = interval(snapshot(), after)
                self.assertEqual('unavailable', data['status'])
                self.assertEqual(reason, data['reason'])
                self.assertNotIn('residencyWeightedKhz', data)

    def test_missing_fields_remain_unknown_not_zero(self):
        data = cpu.parse_snapshot('policy0\tscaling_cur_freq\t-\n')['policy0']
        self.assertIsNone(data['scaling_cur_freq'])
        self.assertEqual({}, cpu.parse_snapshot(''))

    def test_invalid_snapshot_is_explicitly_unavailable(self):
        for invalid in ('broken output', 'policy0\tscaling_cur_freq\t0\n',
                        'policy0\tstats/time_in_state\t1000 -1\n',
                        'policy0\tstats/time_in_state\t0 10\n',
                        'policy0\tstats/time_in_state\t1000 1\n' * 2):
            with self.subTest(invalid=invalid):
                data = cpu.snapshot(lambda command: invalid)
                self.assertEqual('unavailable', data['status'])
                self.assertIn('error', data)

    def test_capture_brackets_work_and_preserves_its_error(self):
        calls = []
        outputs = iter((snapshot(), snapshot((110, 230))))

        def run(command):
            self.assertEqual(cpu.SNAPSHOT_COMMAND, command)
            calls.append('snapshot')
            return next(outputs)

        with self.assertRaisesRegex(RuntimeError, 'benchmark failed'):
            with cpu.observe_cpu(run) as evidence:
                calls.append('benchmark')
                raise RuntimeError('benchmark failed')
        self.assertEqual(['snapshot', 'benchmark', 'snapshot'], calls)
        self.assertEqual(1750, evidence['policies']['policy0']['residencyWeightedKhz'])
        self.assertIn('not per-thread', evidence['scope'])
        self.assertLessEqual(evidence['before']['finishedUnixNs'], evidence['after']['startedUnixNs'])

    def test_observation_failure_does_not_mask_benchmark_failure(self):
        def denied(command):
            raise OSError('permission denied')

        with self.assertRaisesRegex(RuntimeError, 'benchmark failed'):
            with cpu.observe_cpu(denied) as evidence:
                raise RuntimeError('benchmark failed')
        self.assertEqual('permission denied', evidence['after']['error'])
        self.assertEqual({}, evidence['policies'])

    @unittest.skipUnless(shutil.which('sh'), 'POSIX shell required')
    def test_shell_collector_with_missing_optional_files(self):
        with tempfile.TemporaryDirectory() as root:
            policy = Path(root) / 'policy0'
            policy.mkdir()
            (policy / 'related_cpus').write_text('0 1\n')
            (policy / 'scaling_cur_freq').write_text('1500000\n')
            command = cpu.SNAPSHOT_COMMAND.replace('/sys/devices/system/cpu/cpufreq', root)
            # EVENT_WAIT: shell collector exit; timeout fails the test.
            result = subprocess.run(['sh', '-c', command], text=True, capture_output=True,
                                    timeout=5, check=True)
            self.assertEqual('', result.stderr)
            data = cpu.parse_snapshot(result.stdout)['policy0']
            self.assertEqual(1500000, data['scaling_cur_freq'])
            self.assertIsNone(data['scaling_max_freq'])
            self.assertIsNone(data['stats/time_in_state'])
            (policy / 'stats').mkdir()
            (policy / 'stats/time_in_state').write_text('1000000 7\n2000000 8\n')
            result = subprocess.run(['sh', '-c', command], text=True, capture_output=True,
                                    timeout=5, check=True)
            data = cpu.parse_snapshot(result.stdout)['policy0']
            self.assertEqual({'1000000': 7, '2000000': 8}, data['stats/time_in_state'])


if __name__ == '__main__':
    unittest.main()

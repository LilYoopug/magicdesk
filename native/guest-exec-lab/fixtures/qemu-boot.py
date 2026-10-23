#!/usr/bin/env python3
"""Boot the unprivileged kernel-contract initramfs with distribution QEMU TCG."""
import argparse
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kernel', type=Path)
    parser.add_argument('initrd', type=Path)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    report = dict(passed=False, networking=False, acceleration='tcg')
    try:
        report['version'] = subprocess.check_output(['qemu-system-aarch64', '--version'], text=True)
        command = ['qemu-system-aarch64', '-machine', 'virt', '-cpu', 'cortex-a72',
                   '-accel', 'tcg,thread=multi', '-smp', '2', '-m', '512',
                   '-nographic', '-monitor', 'none', '-nic', 'none', '-no-reboot',
                   '-kernel', str(args.kernel), '-initrd', str(args.initrd),
                   '-append', 'console=ttyAMA0 rdinit=/init magicdesk.kernel_fixture=1']
        report['command'] = command
        # EVENT_WAIT: actual VM poweroff; timeout kills QEMU and fails this run.
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=180)
        report.update(exitCode=result.returncode, serial=result.stdout)
        assert result.returncode == 0, result.stdout[-4000:]
        assert 'PASS kernel contract in VM status=0' in result.stdout, result.stdout[-4000:]
        report['passed'] = True
        print('PASS direct QEMU TCG kernel boot and poweroff', flush=True)
    finally:
        args.report.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()

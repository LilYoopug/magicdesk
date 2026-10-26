#!/usr/bin/env python3
"""Deterministic signals at every executed SVC-only gate instruction."""
import argparse
from pathlib import Path
from test_oci_services import Suite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    args = parser.parse_args()
    suite = Suite(Path('build/svc-direct-signals'), None)
    try:
        binary = suite.base + '/signals'
        suite.transport.upload(suite.client, args.build / 'libmagicdesk_guest_test_svc_direct_signal.so', binary)
        suite.command(['chmod', '700', binary])
        output = suite.command(['timeout', '250', binary], timeout=270)
        assert 'PASS SVC arbitrary boundary:' in output
        assert output.count('SVC_SIGNAL_PATH ') == 5
        output = suite.command(['timeout', '60', binary, '--mmap-guard'], timeout=70)
        assert 'PASS mmap argument guard:' in output
        for control in ('--unsafe-context', '--unsafe-checkpoint'):
            output = suite.command(['timeout', '20', binary, control], timeout=30)
            assert 'PASS negative signal control:' in output
        output = suite.command(['timeout', '30', binary, '--queued'], timeout=40)
        assert output.count('PASS queued RT:') == 8
        output = suite.command(['timeout', '20', binary, '--queued-unsafe'], timeout=30)
        assert 'PASS negative queued RT:' in output
        suite.report['passed'] = True
        suite.command(['rm', '-rf', suite.base])
    finally:
        suite.finish()


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Run prebuilt reviewed LTP tests in an installed distribution's own userspace."""
import argparse
from pathlib import Path
from boot_fixture import run_fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--session', type=Path, required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--user', default='mdtester')
    args = parser.parse_args()
    run_fixture(args.session, 'ltp', [args.source, args.user])


if __name__ == '__main__':
    main()

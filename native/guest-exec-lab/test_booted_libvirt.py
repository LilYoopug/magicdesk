#!/usr/bin/env python3
"""Run stock system libvirt or direct QEMU TCG in an installed Linux session."""
import argparse
from pathlib import Path
from boot_fixture import run_fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--session', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--initrd', type=Path, required=True)
    parser.add_argument('--direct', action='store_true', help='Run QEMU without libvirt')
    args = parser.parse_args()
    run_fixture(args.session, 'qemu' if args.direct else 'libvirt',
                [args.kernel, args.initrd], [args.kernel, args.initrd])


if __name__ == '__main__':
    main()

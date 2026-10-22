#!/usr/bin/env python3
"""Run the full machinectl fixture in a retained installed systemd environment.

The selected /var/lib/machines/MACHINE must already contain a bootable rootfs
with systemd, dbus, iproute2 and Python. No unit overrides or sandbox switches
are installed by this test.
"""
import argparse
from pathlib import Path
from boot_fixture import run_fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--session', type=Path, required=True)
    parser.add_argument('--machine', required=True)
    args = parser.parse_args()
    run_fixture(args.session, 'nspawn', [args.machine])


if __name__ == '__main__':
    main()

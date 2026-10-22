#!/usr/bin/env python3
"""Run stock LXC with a systemd/dbus/iproute2/Python rootfs archive."""
import argparse
from pathlib import Path
from boot_fixture import run_fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--session', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    args = parser.parse_args()
    run_fixture(args.session, 'lxc', [args.archive], [args.archive])


if __name__ == '__main__':
    main()

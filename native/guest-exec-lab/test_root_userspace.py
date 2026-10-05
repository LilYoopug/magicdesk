#!/usr/bin/env python3
"""Stock Debian/Alpine chroot, dynamic loader and reexec through Shroot."""
import argparse
from pathlib import Path

from test_oci_services import Suite


def script(kind):
    prepare = {
        "debian": '''
mkdir -p "$root/lib/aarch64-linux-gnu"
cp -L /bin/dash "$root/bin/sh"
cp -L /lib/ld-linux-aarch64.so.1 "$root/lib/"
cp -L /lib/aarch64-linux-gnu/libc.so.6 "$root/lib/aarch64-linux-gnu/"
''',
        "alpine": '''
cp -L /bin/busybox "$root/bin/busybox"
ln -s busybox "$root/bin/sh"
cp -L /lib/ld-musl-aarch64.so.1 "$root/lib/"
''',
    }[kind]
    return '''
set -eu
root=$(mktemp -d /tmp/md-root.XXXXXX)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/bin" "$root/lib" "$root/proc"
''' + prepare + '''
printf inside >"$root/value"
ln -s /value "$root/absolute"
chroot "$root" /bin/sh -ec '
    test "$(pwd)" = /
    test -f /absolute
    test ! -e /proc/self/status
    /bin/sh -ec "test -f /value"
    printf "PASS dynamic root and nested exec\\n"
'
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--debian", help="Prepared Debian instance path")
    parser.add_argument("--alpine", help="Prepared Alpine instance path")
    args = parser.parse_args()
    if not args.debian and not args.alpine:
        parser.error("Select at least one prepared userspace")
    suite = Suite(args.output, args.build)
    try:
        for kind in ("debian", "alpine"):
            instance = getattr(args, kind)
            if not instance:
                continue
            for backend in ("inode", "attachment"):
                case = {"name": kind + "-" + backend, "passed": False}
                suite.report["cases"].append(case)
                options = []
                if backend == "attachment":
                    directory = suite.base + "/" + kind + "-root"
                    suite.command(["mkdir", "-m", "700", directory])
                    options = ["--bind", directory, "/tmp"]
                output = suite.command(suite.run(instance, *options, "--", "/bin/sh", "-ec", script(kind)), timeout=45)
                assert "PASS dynamic root and nested exec" in output
                case["passed"] = True
        suite.report["passed"] = True
    finally:
        suite.finish()


if __name__ == "__main__":
    main()

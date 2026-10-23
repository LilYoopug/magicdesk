#!/usr/bin/env python3
"""Compile against an existing recipe Mesa build, then exercise its real queue."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    args = parser.parse_args()
    build = args.build.resolve()
    entries = json.loads((build / 'compile_commands.json').read_text())
    entry, = (e for e in entries if e['file'].endswith('/u_queue.c'))
    argv = entry.get('arguments') or shlex.split(entry['command'])
    flags = []
    iterator = iter(argv)
    for arg in iterator:
        if arg in ('-o', '-MF', '-MQ', '-MT'):
            next(iterator)
        elif arg not in ('-c', '-MD', '-MMD', entry['file']):
            flags.append(arg)
    # Use the exact build feature defines: they also select the public fence ABI.
    libraries = [build / p for p in ('src/util/libmesa_util.a',
                 'src/util/libmesa_util_simd.a', 'src/util/blake3/libblake3.a',
                 'src/c11/impl/libmesa_util_c11.a')]
    with tempfile.TemporaryDirectory(prefix='mesa-queue-') as directory:
        binary = Path(directory) / 'mesa-queue'
        subprocess.run([*flags, '-UNDEBUG', str(Path(__file__).with_suffix('.c').resolve()),
                        '-o', str(binary), '-Wl,--wrap=u_thread_create',
                        '-Wl,--start-group', *map(str, libraries), '-Wl,--end-group',
                        '-pthread', '-lm', '-ldl', '-lz'], cwd=entry['directory'], check=True)
        subprocess.run([str(binary)], check=True, timeout=70)


if __name__ == '__main__':
    main()

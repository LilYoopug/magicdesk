#!/usr/bin/env python3
"""Apply the hybrid adapters to verified source archives without building libc."""
import argparse
import hashlib
from pathlib import Path
import sys
import tarfile
import tempfile
import urllib.request
import re

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'shroot/libc'))
try:
    import integrate_glibc as glibc
    import integrate_musl as musl
    from source_integration import IntegrationError
finally:
    sys.path.pop(0)

SOURCES = {
    'musl': ('1.2.5', 'a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4', musl),
    'glibc': ('2.41', 'a5a26b22f545d6b7d7b3dd828e11e428f24f4fac43c934fb071b6a7d0828e901', glibc),
}


def check(kind, archive):
    version, digest, adapter = SOURCES[kind]
    with archive.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
            raise RuntimeError(f'{archive}: unexpected source checksum')
    wanted = set(adapter.FILES)
    if kind == 'glibc':
        wanted.update(('elf/dl-load.c', 'nptl/cancellation.c'))
    sources = {}
    prefix = f'{kind}-{version}/'
    # One sequential decompression, even for the large glibc archive.
    with tarfile.open(archive, mode='r|*') as stream:
        for member in stream:
            if member.name.startswith(prefix) and member.name[len(prefix):] in wanted:
                if not member.isfile():
                    raise RuntimeError(f'{member.name}: not a regular source file')
                sources[member.name[len(prefix):]] = stream.extractfile(member).read()
    if set(sources) != wanted:
        raise RuntimeError(f'{archive}: missing integration inputs')
    check_sources(kind, version, adapter, sources)


def check_sources(kind, version, adapter, sources):
    for profile in ('fixture', 'private') if kind == 'glibc' else ('fixture',):
        with tempfile.TemporaryDirectory(prefix='libc-sources-') as directory:
            root = Path(directory)
            for name, data in sources.items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            parameters = ['/opt/shroot/libc/test-generation/lib'] if profile == 'private' else []
            adapter.integrate(root, *parameters)
            before = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            try:
                adapter.integrate(root, *parameters)
            except IntegrationError:
                pass
            else:
                raise AssertionError('repeated integration must be rejected')
            after = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            if before != after:
                raise AssertionError('rejected integration modified sources')
        print(f'PASS {kind} {version} {profile}: complete source patch, repeat rejected without changes', flush=True)


def check_glibc_release(version):
    if not re.fullmatch(r'2\.[0-9]+', version):
        raise ValueError('expected a glibc release such as 2.39')
    # Source-only compatibility check against the upstream-maintained mirror.
    # Download only integration inputs, never execute or build downloaded code.
    base = f'https://raw.githubusercontent.com/bminor/glibc/glibc-{version}/'
    sources = {}
    for name in (*glibc.FILES, 'elf/dl-load.c', 'nptl/cancellation.c'):
        with urllib.request.urlopen(base + name, timeout=30) as response:
            sources[name] = response.read()
    if not re.search(rb'^__internal_syscall_cancel\s*\(', sources['nptl/cancellation.c'], re.M):
        with urllib.request.urlopen(base + 'sysdeps/unix/sysdep.h', timeout=30) as response:
            sources['sysdeps/unix/sysdep.h'] = response.read()
    check_sources('glibc', version, glibc, sources)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--musl', type=Path)
    parser.add_argument('--glibc', type=Path)
    parser.add_argument('--glibc-release', action='append', default=[], help='Fetch only source integration inputs from an upstream release tag')
    args = parser.parse_args()
    if not args.musl and not args.glibc and not args.glibc_release:
        parser.error('supply at least one source archive')
    for kind in SOURCES:
        if archive := getattr(args, kind):
            check(kind, archive)
    for version in args.glibc_release:
        check_glibc_release(version)


if __name__ == '__main__':
    main()

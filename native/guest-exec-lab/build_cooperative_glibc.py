#!/usr/bin/env python3
"""Build an isolated glibc fixture under shell Shroot; never install it into an OS.

TOOLCHAIN is a fresh prepare.mjs --suite trixie directory with gcc, g++, make,
python3, gawk, bison, sed, grep, bash and texinfo. Work and logs remain available
on failure. A successful build exports only the fixture, not its temporary OS.
"""
import argparse
import hashlib
import json
import re
import subprocess
import tarfile
from pathlib import Path
from test_oci_services import Suite

VERSION = '2.41'
SHA256 = 'a5a26b22f545d6b7d7b3dd828e11e428f24f4fac43c934fb071b6a7d0828e901'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('toolchain', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--resume', help='Exact retained builder directory from a failed receipt')
    parser.add_argument('--keep', action='store_true', help='Retain the isolated builder for incremental work')
    parser.add_argument('--probes-only', action='store_true', help='Rebuild probes in a retained, installed fixture')
    args = parser.parse_args()
    if not 1 <= args.jobs <= 16:
        parser.error('jobs must be in 1..16')
    if args.probes_only and not args.resume:
        parser.error('--probes-only requires --resume')
    lab = Path(__file__).resolve().parent
    integration = lab.parent / 'shroot/libc'
    structural = hashlib.sha256()
    for name in ('integrate_glibc.py', 'source_integration.py', 'glibc.patch', 'glibc-cancellation.patch', 'glibc_syscall.h'):
        structural.update(name.encode() + b'\0' + (integration / name).read_bytes() + b'\0')
    source_generation = structural.hexdigest()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if args.resume:
        receipts = [json.loads(p.read_text()) for p in (output / 'receipts').glob('*.json')]
        if not re.fullmatch(r'/data/local/tmp/md-oci-services-[0-9a-f]{32}', args.resume) or not any(
                r.get('directory') == args.resume and r.get('sourceSha256') == SHA256
                and r.get('sourceIntegrationSha256') == source_generation for r in receipts):
            parser.error('--resume must match this fixture\'s verified source and integration; '
                         'changed structural patches require a fresh build')
    archive = args.toolchain / f'glibc-{VERSION}.tar.xz'
    if not archive.exists():
        subprocess.run(['curl', '-fL', '--connect-timeout', '20', '--max-time', '180',
                        '-o', str(archive), f'https://ftp.gnu.org/gnu/glibc/glibc-{VERSION}.tar.xz'], check=True)
    with archive.open('rb') as stream:
        assert hashlib.file_digest(stream, 'sha256').hexdigest() == SHA256
    source = output / f'glibc-{VERSION}'
    if source.exists() and not args.resume:
        raise RuntimeError('Use a fresh output; do not mix modified source generations')
    if not args.resume:
        subprocess.run(['tar', '--no-same-owner', '-xJf', str(archive), '-C', str(output)], check=True)
        subprocess.run(['python', str(integration / 'integrate_glibc.py'), str(source)], check=True)
    root_archive = output / 'toolchain.tar'
    source_archive = output / 'source.tar'
    if not args.resume:
        with tarfile.open(root_archive, 'w') as stream:
            stream.add(args.toolchain / 'sysroot', arcname='.')
        with tarfile.open(source_archive, 'w') as stream:
            stream.add(source, arcname='source')
            stream.add(lab / 'test_cooperative_libc.c', arcname='probe.c')
            stream.add(lab / '../shroot/src/cooperative_entry.h', arcname='cooperative_entry.h')
            for name in ('gzip', 'perl', 'perl-base'):
                packages = list(args.toolchain.glob(name + '_*.deb'))
                assert len(packages) == 1, name
                stream.add(packages[0], arcname=name + '.deb')
    suite = Suite(output / 'receipts', args.build)
    try:
        suite.report['sourceSha256'] = SHA256
        suite.report['sourceIntegrationSha256'] = source_generation
        workspace = args.resume or suite.base
        suite.report['workspace'] = workspace
        if not args.resume:
            suite.transport.upload(suite.client, root_archive, workspace + '/toolchain.tar')
            suite.command([suite.image, 'rootfs', workspace + '/toolchain.tar', workspace + '/store'], timeout=600)
            suite.command(['mkdir', workspace + '/work'])
            suite.transport.upload(suite.client, source_archive, workspace + '/source.tar')
            # Toybox's extraction-only -o ignores host archive ownership too.
            suite.command(['tar', '-oxf', workspace + '/source.tar', '-C', workspace + '/work'], timeout=600)
        suite.command(['/system/bin/sh', '-c',
                       'if [ ! -d "$3" ]; then "$1" create "$2" "$3"; fi', 'builder',
                       suite.image, workspace + '/store', workspace + '/instance'], timeout=600)
        suite.command([suite.runner, '--store', workspace + '/instance', '--user', '0:0',
                       '--', '/usr/bin/mkdir', '-p', '/work', '/tmp'])
        guest = [suite.runner, '--store', workspace + '/instance', '--user', '0:0',
                 '--bind', workspace + '/work', '/work', '--env', 'PATH=/usr/bin:/bin', '--', '/bin/sh', '-c']
        for name in ('test_cooperative_libc.c', 'build-cooperative-glibc-probes.sh'):
            suite.transport.upload(suite.client, lab / name, workspace + '/work/' +
                                   ('probe.c' if name.endswith('.c') else name), overwrite=True)
        for source_file, destination in (
                (lab / '../shroot/src/cooperative_entry.h', 'cooperative_entry.h'),
                (lab / '../shroot/src/cooperative_entry.h', 'source/include/cooperative_entry.h'),
                (integration / 'glibc_entry.c', 'source/sysdeps/unix/sysv/linux/aarch64/shroot-entry.c'),
                (integration / 'glibc_syscall.h', 'source/sysdeps/unix/sysv/linux/aarch64/shroot-syscall.h'),
                (integration / 'glibc_entry_asm.S', 'source/sysdeps/unix/sysv/linux/aarch64/shroot-entry-asm.S')):
            suite.transport.upload(suite.client, source_file, workspace + '/work/' + destination, overwrite=True)
        configure = '''set -eu
mkdir -p /tmp /work/objects
cd /
for name in gzip perl perl-base; do dpkg-deb --fsys-tarfile /work/$name.deb | tar -xf -; done
cd /work/objects
if [ ! -f config.status ]; then
  CC=gcc CXX=g++ AWK=gawk ../source/configure --prefix=/usr --disable-werror --enable-kernel=5.15 > /work/configure.log 2>&1 || { tail -n 80 /work/configure.log; exit 1; }
fi
tail -n 10 /work/configure.log
'''
        if not args.probes_only:
            suite.command([*guest, configure], timeout=600)
            build = f'''set -eu
cd /work/objects
make -j{args.jobs} > /work/build.log 2>&1 || {{ tail -n 100 /work/build.log; exit 1; }}
make install DESTDIR=/work/sysroot > /work/install.log 2>&1 || {{ tail -n 80 /work/install.log; exit 1; }}
'''
            suite.command([*guest, build], timeout=3600)
        suite.command([*guest, '''set -eu
/bin/sh /work/build-cooperative-glibc-probes.sh
cd /work
tar -cf fixture.tar sysroot probe-static probe-dynamic configure.log build.log install.log
echo 'PASS glibc fixture build'
'''], timeout=600)
        suite.transport.download(suite.client, workspace + '/work/fixture.tar', output / 'fixture.tar', overwrite=True)
        subprocess.run(['tar', '--no-same-owner', '-xf', str(output / 'fixture.tar'), '-C', str(output)], check=True)
        suite.report['passed'] = True
        if not args.keep:
            suite.command(['rm', '-rf', workspace, suite.base], timeout=600)
        elif workspace != suite.base:
            suite.command(['rm', '-rf', suite.base], timeout=600)
    finally:
        suite.finish()


if __name__ == '__main__':
    main()

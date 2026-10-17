#!/usr/bin/env python3
"""Build the embedded libc recipe in a fresh official rootfs as Android shell."""
import argparse
import hashlib
import re
from pathlib import Path
import subprocess
from test_oci_services import Suite


def cached_preparation(suite, root, output, store, registry):
    # Adapt only the fixture name/current native bundle; the downloaded installer
    # and its cache/cleanup orchestration run unchanged under shell UID 2000.
    cli = output / 'fixture-cli'
    cli.write_text(f'''#!/system/bin/sh
set -eu
case "$1" in
    --probe) exec {suite.base}/libmagicdesk_guest_supervisor.so {suite.base}/libmagicdesk_guest_bootstrap.so --probe ;;
    path) [ "$2" = fixture ] || exit 2; printf '%s\\n' {store} ;;
    libc) shift; case "$1" in
        path) printf '%s\\n' {registry} ;;
        publish) exec {suite.image} libc-publish {registry} "$2" ;;
        *) exit 2 ;;
        esac ;;
    exec) shift; [ "$1" = fixture ] || exit 2; shift
        exec {suite.image} exec {store} --libc-registry {registry} "$@" ;;
    *) exit 2 ;;
esac
''')
    suite.command(['mkdir', '-p', suite.base + '/cli'])
    suite.transport.upload(suite.client, cli, suite.base + '/cli/shroot')
    suite.transport.upload(suite.client, root / 'scripts/install_linux.sh', suite.base + '/install_linux.sh')
    suite.command(['chmod', '700', suite.base + '/cli/shroot'])
    result = suite.command(['/system/bin/sh', '-ec',
                           'PATH="$1/cli:$PATH" /system/bin/sh "$1/install_linux.sh" --prepare-libc fixture --jobs 1',
                           'fixture', suite.base], timeout=180)
    assert 'Reusing Shroot libc:' in result, result
    assert 'Shroot libc prepared:' in result, result
    assert not suite.command(['ls', registry.removesuffix('/artifacts') + '/work'], quiet=True).strip()
    suite.command(['cmp', suite.base + '/install_linux.sh', registry.removesuffix('/artifacts') + '/install_linux.sh'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('rootfs', type=Path)
    parser.add_argument('--jobs', default='2', choices=[str(i) for i in range(1, 9)])
    parser.add_argument('--dns', default='1.1.1.1', help='Explicit fixture-only resolver')
    parser.add_argument('--keep', action='store_true')
    parser.add_argument('--resume', help='Existing fixture instance retained for this recipe')
    parser.add_argument('--prepared-musl', type=Path, help='Reuse a built musl fixture; no compiler/packages on phone')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = root / 'build/installer-libc'
    output.mkdir(parents=True, exist_ok=True)
    script = subprocess.check_output(['sh', str(root / 'scripts/install_linux.sh'), '--print-libc-setup'])
    digest = hashlib.sha256(script).hexdigest()
    payload = output / (digest + '.sh')
    payload.write_bytes(script)
    abi = int(re.search(r'#define MD_ENTRY_VERSION (\d+)',
                       (root / 'native/shroot/src/cooperative_entry.h').read_text()).group(1))
    suite = Suite(output, args.build)
    store = args.resume or suite.base + '/instance'
    registry = suite.base + '/libc/artifacts'
    suite.report.update(recipe=digest, instance=store, rootfs=str(args.rootfs), dns=args.dns)
    try:
        if not args.resume:
            suite.transport.upload(suite.client, args.rootfs, suite.base + '/rootfs.tar.gz')
            suite.command([suite.image, 'rootfs', suite.base + '/rootfs.tar.gz', suite.base + '/image'], timeout=600)
            suite.command([suite.image, 'create', suite.base + '/image', store], timeout=600)
        suite.command(['mkdir', '-p', suite.base + '/work', registry])
        suite.transport.upload(suite.client, payload, suite.base + '/work/setup.sh')
        suite.command([suite.runner, '--store', store, '--user', '0:0', '--',
                       '/bin/mkdir', '-p', '/run/shroot-libc-build', '/run/shroot-libc-cache', '/tmp'])
        guest = [suite.runner, '--store', store, '--user', '0:0',
                 '--libc-registry', registry,
                 '--bind', suite.base + '/work', '/run/shroot-libc-build',
                 '--bind-ro', registry, '/run/shroot-libc-cache',
                 '--env', 'DEBIAN_FRONTEND=noninteractive', '--env', 'SYSTEMD_IN_CHROOT=1', '--']
        if args.prepared_musl:
            # Small fixture-only executable; the libc itself is not rebuilt.
            sysroot = args.prepared_musl.resolve() / 'sysroot'
            resource = subprocess.check_output(['clang', '-print-resource-dir'], text=True).strip()
            probe = output / 'selection-probe'
            subprocess.run(['clang', '--target=aarch64-linux-musl', '--sysroot=' + str(sysroot),
                            '-isystem', str(sysroot / 'include'), '-iquote', str(root / 'native/shroot/src'),
                            '-fuse-ld=lld', '-O2', '-nostdlib', '-pie', '-Wl,--dynamic-linker=/lib/ld-musl-aarch64.so.1',
                            str(sysroot / 'lib/Scrt1.o'), str(sysroot / 'lib/crti.o'),
                            str(root / 'native/guest-exec-lab/test_libc_selection_guest.c'),
                            '-L' + str(sysroot / 'lib'), '-lc',
                            resource + '/lib/linux/libclang_rt.builtins-aarch64-android.a',
                            str(sysroot / 'lib/crtn.o'), '-o', str(probe)], check=True)
            suite.transport.upload(suite.client, probe, suite.base + '/work/probe')
            suite.command(['chmod', '755', suite.base + '/work/probe'])
            suite.command([*guest, '/run/shroot-libc-build/probe', 'base'])
            original = suite.command([*guest, '/bin/busybox', 'sha256sum', '/lib/ld-musl-aarch64.so.1'], quiet=True).split()[0]
            manifest = f'shroot-libc-1\n{abi}\nmusl\n1.2.5\n{digest}\n/lib/ld-musl-aarch64.so.1\n/lib/ld-musl-aarch64.so.1\n{original}\n{original}\nlib/libc.so\n'
            key = hashlib.sha256(manifest.encode()).hexdigest()
            local_manifest = output / 'fixture-manifest'
            local_manifest.write_text(manifest)
            suite.command(['mkdir', '-p', suite.base + '/work/candidate/lib'])
            suite.transport.upload(suite.client, local_manifest, suite.base + '/work/candidate/manifest')
            suite.transport.upload(suite.client, sysroot / 'lib/libc.so', suite.base + '/work/candidate/lib/libc.so')
            suite.command(['chmod', '755', suite.base + '/work/candidate/lib/libc.so'])
        else:
            suite.command([*guest, '/bin/sh', '-ec',
                       'printf "nameserver %s\\n" "$1" > /etc/resolv.conf; '
                       'if command -v apt-get >/dev/null; then apt-get update; fi', 'fixture', args.dns], timeout=600)
            suite.command([*guest, '/bin/sh', '/run/shroot-libc-build/setup.sh', 'shroot', args.jobs, digest], timeout=7200)
            key = suite.command(['cat', suite.base + '/work/result'], quiet=True).strip()
        suite.command([suite.image, 'libc-publish', registry, suite.base + '/work/candidate'])
        if args.prepared_musl:
            cached_preparation(suite, root, output, store, registry)
        for _ in range(2):
            if args.prepared_musl:
                suite.command([*guest, '/run/shroot-libc-build/probe', 'shroot'])
            suite.command([*guest, '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', '/bin/sh', '-ec', 'id; uname -a'])
        if args.prepared_musl:
            suite.command([*guest, '/bin/sh', '-ec',
                           'mkdir -p /nested/bin /nested/lib /nested/tmp; '
                           'cp /bin/busybox /nested/bin/sh; '
                           'cp -L /lib/ld-musl-aarch64.so.1 /nested/lib/ld-musl-aarch64.so.1; '
                           'cp /run/shroot-libc-build/probe /nested/bin/probe; '
                           'chroot /nested /bin/probe shroot'])
        suite.command([*guest, '/bin/sh', '/run/shroot-libc-build/setup.sh', 'base', args.jobs, digest])
        if args.prepared_musl:
            suite.command([*guest, '/run/shroot-libc-build/probe', 'base'])
        suite.command([suite.image, 'libc-prune', registry])
        assert not suite.command([suite.image, 'libc-list', registry], quiet=True).strip()
        suite.report['passed'] = True
        suite.report['artifact'] = key
        print('PASS installed libc: registry publication, ordinary exec, clean environment, Base and prune', flush=True)
        if not args.keep:
            suite.command(['rm', '-rf', suite.base])
    finally:
        suite.finish()


if __name__ == '__main__':
    main()

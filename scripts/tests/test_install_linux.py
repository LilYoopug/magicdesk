"""Installer orchestration without modifying the host or downloading packages."""
import errno
import gzip
import json
import lzma
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "install_linux.sh"
MIN_VERSION_CODE = int(re.search(r"^MIN_MAGICDESK_VERSION_CODE=(\d+)$", SCRIPT.read_text(), re.M).group(1))
MIN_VERSION_NAME = re.search(r"^MIN_MAGICDESK_VERSION_NAME=([\d.]+)$", SCRIPT.read_text(), re.M).group(1)
VERSION_QUERY = ["get_state", "--field", "data.app.versionCode"]


class InstallLinuxTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="magicdesk-install-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.log = self.directory / "calls.jsonl"
        self.version_log = self.directory / "version.jsonl"
        self.dns_log = self.directory / "dns.jsonl"
        self.payload = self.directory / "guest.sh"
        stub = self.directory / "shroot"
        stub.write_text("#!" + sys.executable + r'''
import json, os, sys
from pathlib import Path
if Path(sys.argv[0]).name == "id":
    print(os.environ.get("TEST_UID", "2000"))
    sys.exit(0)
args = sys.argv[1:]
if Path(sys.argv[0]).name == "magicdesk" and args and args[0] == "get_state":
    with open(os.environ["TEST_VERSION_LOG"], "a") as log:
        log.write(json.dumps(args) + "\n")
    if args != ["get_state", "--field", "data.app.versionCode"]:
        sys.exit(2)
    print(os.environ["TEST_VERSION_CODE"])
    sys.exit(int(os.environ.get("TEST_VERSION_STATUS", "0")))
if args[:2] == ["dns", "--check"]:
    import ipaddress
    with open(os.environ["TEST_DNS_LOG"], "a") as log:
        log.write(json.dumps(args) + "\n")
    if args[2] == "system":
        error = os.environ.get("TEST_DNS_ERROR", "")
        if error:
            print(error, file=sys.stderr)
            sys.exit(1)
    elif args[2] != "preserve":
        try:
            addresses = args[2].split(",")
            assert 1 <= len(addresses) <= 3
            for address in addresses:
                ipaddress.ip_address(address)
        except (ValueError, AssertionError):
            print("Invalid DNS server addresses", file=sys.stderr)
            sys.exit(1)
    sys.exit(0)
with open(os.environ["TEST_LOG"], "a") as log:
    log.write(json.dumps(args) + "\n")
stage = args[0]
if stage == "--probe":
    print(os.environ.get("TEST_RUNTIME_FEATURES", "libc-registry=1"))
if args[:2] == ["libc", "path"]:
    print(str(Path(os.environ["HOME"]) / "libc/artifacts"))
    sys.exit(0)
if stage == "path":
    if os.environ.get("TEST_IMAGE_ONLY") and not args[1].startswith("libc-build-"):
        sys.exit(1)
    print(str(Path(os.environ["HOME"]) / "source-store"))
    sys.exit(0)
if args[:2] == ["image", "exec"]:
    args = args[1:]
    stage = "exec"
if Path(sys.argv[0]).name == "magicdesk":
    if os.environ.get("TEST_FAIL") == "download":
        print("test download/checksum failure", file=sys.stderr)
        sys.exit(23)
    Path(args[2]).write_bytes(b"test download")
    sys.exit(0)
if stage == "list":
    print(os.environ.get("TEST_ENVIRONMENTS", ""))
if stage == "exec":
    if args[1] == "unpack":
        if args[-1] == "/mnt":
            Path(os.environ["TEST_PAYLOAD"] + ".reader").write_text(sys.stdin.read())
        sys.exit(23 if os.environ.get("TEST_FAIL") == "converter" else 0)
    stage = "setup" if "-s" in args else "detect" if len(args) == 8 else "validate"
    if stage == "detect":
        print(os.environ.get("TEST_DISTRO", "debian"))
    if stage == "setup":
        payload = sys.stdin.read()
        if args[-3] == "identify":
            changed = Path(os.environ["TEST_PAYLOAD"] + ".libc-changed").exists()
            manifest = "fixture updated manifest\n" if changed else "fixture target manifest\n"
            print(manifest, end="")
            if os.environ.get("TEST_LIBC_CACHED"):
                import hashlib
                key = hashlib.sha256(manifest.encode()).hexdigest()
                artifact = Path(os.environ["HOME"]) / "libc/artifacts" / key
                artifact.mkdir(parents=True, exist_ok=True)
                (artifact / "manifest").write_text(manifest)
            sys.exit(0)
        if args[-3] in ("turnip", "software", "auto"):
            stage = "graphics"
        if "version=6.3.6" in payload:
            stage = "kwin"
        if args[-3] in ("shroot", "base"):
            stage = "libc"
        suffix = {"graphics": ".gpu", "kwin": ".kwin", "libc": ".libc"}.get(stage, "")
        Path(os.environ["TEST_PAYLOAD"] + suffix).write_text(payload)
        if "MAGICDESK_BUILD_PHASE=dependencies" in args:
            if os.environ.get("TEST_FAIL_DEPENDENCIES") == stage:
                sys.exit(23)
            if stage == "kwin" and os.environ.get("TEST_LIBC_CHANGE_ON_KWIN_DEPS"):
                Path(os.environ["TEST_PAYLOAD"] + ".libc-changed").touch()
        if stage == "libc" and "--bind" in args and os.environ.get("TEST_FAIL") != "libc":
            import hashlib
            work = Path(args[args.index("--bind") + 1])
            manifest = (work / "manifest").read_text()
            key = hashlib.sha256(manifest.encode()).hexdigest()
            (work / "result").write_text(key + "\n")
            artifact = Path(os.environ["HOME"]) / "libc/artifacts" / key
            artifact.mkdir(parents=True, exist_ok=True)
            (artifact / "manifest").write_text(manifest)
        if stage == "setup" and os.environ.get("TEST_SETUP_FAILURES"):
            attempts = Path(os.environ["TEST_PAYLOAD"] + ".attempts")
            count = int(attempts.read_text()) + 1 if attempts.exists() else 1
            attempts.write_text(str(count))
            if count <= int(os.environ["TEST_SETUP_FAILURES"]):
                print("test package download failure", file=sys.stderr)
                sys.exit(23)
if os.environ.get("TEST_FAIL") == stage and "MAGICDESK_BUILD_PHASE=dependencies" not in args:
    print("test failure: " + stage, file=sys.stderr)
    sys.exit(23)
''')
        stub.chmod(0o755)
        shutil.copyfile(stub, self.directory / "id")
        (self.directory / "id").chmod(0o755)
        shutil.copyfile(stub, self.directory / "magicdesk")
        (self.directory / "magicdesk").chmod(0o755)
        self.environment = dict(os.environ, HOME=str(self.directory), PATH=str(self.directory) + os.pathsep + os.environ["PATH"],
                                TEST_LOG=str(self.log), TEST_PAYLOAD=str(self.payload), TMPDIR=str(self.directory),
                                TEST_DNS_LOG=str(self.dns_log),
                                TEST_VERSION_LOG=str(self.version_log), TEST_VERSION_CODE=str(MIN_VERSION_CODE))

    def run_script(self, *args, **environment):
        # EVENT_WAIT: installer exit; timeout fails a stuck subprocess.
        return subprocess.run(["sh", str(SCRIPT), *args], input="", text=True, capture_output=True,
                              env=dict(self.environment, **environment), timeout=15)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def system_setup_call(self):
        return next(c for c in self.calls() if c[0] == 'exec' and '-s' in c)

    def version_calls(self):
        return [json.loads(line) for line in self.version_log.read_text().splitlines()] if self.version_log.exists() else []

    def dns_checks(self):
        return [json.loads(line) for line in self.dns_log.read_text().splitlines()] if self.dns_log.exists() else []

    def test_dns_failure_stops_unattended_install_before_any_image_work(self):
        for distro in ('alpine', 'steamos', 'void'):
            with self.subTest(distro=distro):
                result = self.run_script('--yes', '--distro', distro, TEST_DNS_ERROR='No active-network DNS servers')
                self.assertEqual(1, result.returncode)
                self.assertIn('No active-network DNS servers', result.stderr)
                self.assertIn('Retry with --dns', result.stderr)
                self.assertNotIn('GUI=', result.stdout)
                self.assertEqual([], self.calls())

    def test_current_network_alias_uses_existing_dns_owner(self):
        for policy in ('auto', 'system'):
            with self.subTest(policy=policy):
                self.log.unlink(missing_ok=True)
                self.dns_log.unlink(missing_ok=True)
                result = self.run_script('--yes', '--dns', policy)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual([['dns', '--check', 'system']], self.dns_checks())
                install = next(c for c in self.calls() if c[0] == 'install')
                self.assertEqual(['--dns', 'system'], install[-2:])
                self.assertIn(['dns', 'debian', 'system', '--replace'], self.calls())
                self.assertIn('Network: Current network (DNS saved once; editable in Linux)', result.stdout)

    @unittest.skipUnless(hasattr(os, 'openpty'), 'PTY required')
    def test_current_network_is_the_default_advanced_choice(self):
        output = self.questions(b'alpine\nwork\nnone\nkeep\nkeep\nkeep\nkeep\nkeep\ny\n\nboth\n\n\nkeep\ny\n')
        self.assertIn('auto      Current network (recommended)', output)
        self.assertIn('preserve  Keep the Linux image/current Linux DNS settings', output)
        self.assertIn('Network [auto]', output)
        self.assertGreater(output.index('Network [auto]'), output.index('Additional settings ('))
        self.assertEqual([['dns', '--check', 'system']], self.dns_checks())
        self.assertIn('Linux is ready: work', output)

    def test_invalid_explicit_dns_is_checked_without_touching_an_image(self):
        result = self.run_script('--yes', '--dns', 'invalid')
        self.assertEqual(1, result.returncode)
        self.assertEqual([['dns', '--check', 'invalid']], self.dns_checks())
        self.assertEqual([], self.calls())

    def test_resume_keeps_resolver_without_requiring_android_network(self):
        result = self.run_script('--yes', '--resume', '--name', 'work', TEST_DNS_ERROR='offline')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([], self.dns_checks())

    def test_libc_keep_does_not_run_the_build_recipe(self):
        result = self.run_script('--yes', '--resume', '--name', 'work', '--libc', 'keep')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(Path(str(self.payload) + '.libc').exists())

    def test_default_libc_prepares_shared_build_for_install_and_resume(self):
        for args in (('--image', 'alpine:3.23'), ('--resume',)):
            with self.subTest(args=args):
                self.log.unlink(missing_ok=True)
                result = self.run_script('--yes', '--name', 'work', *args)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertIn('Linux libc: shroot', result.stdout)
                self.assertTrue(any(c[:2] == ['libc', 'path'] for c in self.calls()))
                self.assertTrue(any('rm -f /etc/shroot/libc-base' in a
                                    for c in self.calls() for a in c))
        self.assertTrue(Path(str(self.payload) + '.libc').exists())

    def test_libc_recipe_is_exported_without_android_access(self):
        result = self.run_script('--print-libc-setup', TEST_UID='10001', TEST_VERSION_STATUS='3')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('integrate_musl.py', result.stdout)
        self.assertIn('integrate_glibc.py', result.stdout)
        self.assertEqual([], self.calls())
        self.assertEqual([], self.version_calls())
        subprocess.run(['sh', '-n'], input=result.stdout, text=True, check=True)

    def test_libc_missing_runtime_capability_precedes_environment_mutation(self):
        result = self.run_script('--yes', '--distro', 'alpine', '--libc', 'shroot',
                                 TEST_RUNTIME_FEATURES='')
        self.assertEqual(1, result.returncode)
        self.assertIn('shared libc registry is unavailable', result.stderr)
        self.assertEqual([['--probe']], self.calls())
        self.assertFalse(self.payload.exists())

    def test_private_glibc_keeps_locale_data_and_exports_its_own_iconv_modules(self):
        script = self.run_script('--print-libc-setup').stdout
        self.assertIn('complocaledir = /usr/lib/locale', script)
        self.assertIn('zonedir = /usr/share/zoneinfo', script)
        self.assertIn('cp -RL "$work/stage$prefix/lib/gconv" candidate/lib/', script)
        self.assertNotIn('getconf GNU_LIBC_VERSION', script)

    def test_libc_identity_accepts_loader_banner_punctuation(self):
        script = self.run_script('--print-libc-setup').stdout
        identify = re.search(r'^identify_libc\(\) \{\n.*?^\}', script,
                             re.M | re.S).group(0)
        cases = (
            ('glibc', 'ld.so (GNU libc) stable release version 2.39.\nCopyright (C) 2024', '2.39'),
            ('glibc', 'ld.so (Debian GLIBC 2.41-12) 2.41\nCopyright (C) 2025', '2.41'),
            ('glibc', 'ld.so (Ubuntu GLIBC 2.39-0ubuntu8.6) 2.39', '2.39'),
            ('glibc', 'ld.so (GNU libc) stable release version 2.39..', None),
            ('glibc', 'ld.so (GNU libc) stable release version 2..39.', None),
            ('glibc', 'unrecognized loader output', None),
            ('musl', 'musl libc (aarch64)\nVersion 1.2.5\nDynamic Program Loader', '1.2.5'),
            ('musl', 'musl libc (aarch64)\nVersion 1..2.5\nDynamic Program Loader', None),
        )
        for index, (kind, banner, version) in enumerate(cases):
            with self.subTest(kind=kind, banner=banner):
                root = self.directory / ('libc-root-' + str(index))
                (root / 'lib').mkdir(parents=True)
                loader = root / 'lib' / ('ld-musl-aarch64.so.1' if kind == 'musl'
                                         else 'ld-linux-aarch64.so.1')
                loader.write_text('#!' + shutil.which('sh') +
                                  '\nprintf \'%s\\n\' "$TEST_LIBC_BANNER"\n'
                                  'exit "$TEST_LIBC_STATUS"\n')
                loader.chmod(0o755)
                (root / 'lib/libc.so.6').write_bytes(b'original libc')
                function = re.sub(r'/(?:usr/lib|lib64|lib)(?=[/ ])',
                                  lambda match: str(root) + match[0], identify)
                result = subprocess.run(['sh', '-ec', function +
                                         '\nabi=fixture; recipe=fixture; identify_libc; '
                                         'printf \'%s\\n\' "$manifest"'],
                                        env={**os.environ, 'TEST_LIBC_BANNER': banner,
                                             'TEST_LIBC_STATUS': '1' if kind == 'musl' else '0'},
                                        text=True, capture_output=True)
                if version is None:
                    self.assertEqual(1, result.returncode, result.stdout)
                    self.assertIn('Cannot identify libc version', result.stderr)
                else:
                    self.assertEqual(0, result.returncode, result.stderr)
                    manifest = result.stdout.splitlines()
                    self.assertEqual(['shroot-libc-1', 'fixture', kind, version], manifest[:4])
                    self.assertEqual(str(loader), manifest[5])

    def test_libc_build_dependencies_use_shared_repository_preparation(self):
        script = self.run_script('--print-libc-setup').stdout
        functions = '\n'.join(re.search(r'^' + name + r'\(\) \{\n.*?^\}', script,
                                         re.M | re.S).group(0)
                              for name in ('refresh_packages', 'install_libc_tools'))
        stubs = 'packages() { printf \'packages %s\\n\' "$*"; }\n'
        command = self.directory / 'package-command'
        command.write_text('#!' + shutil.which('sh') + '\nprintf \'%s %s\\n\' "${0##*/}" "$*"\n')
        command.chmod(0o755)
        for name in ('apt-get', 'apk', 'pacman', 'pacman-key', 'xbps-install', 'zypper'):
            (self.directory / name).symlink_to(command)
        for family, distro, expected in (
                ('apt', 'debian', ['apt-get update']),
                ('apk', 'alpine', ['apk update']),
                ('dnf', 'fedora', []),
                ('zypper', 'opensuse-tumbleweed', ['zypper --non-interactive refresh']),
                ('xbps', 'void', ['xbps-install -Suy xbps', 'xbps-install -uy']),
                ('pacman', 'arch', ['pacman-key --init', 'pacman-key --populate archlinuxarm',
                                    'pacman -Syu --noconfirm']),
                ('pacman', 'manjaro', ['pacman-key --init',
                                       'pacman-key --populate archlinuxarm manjaro manjaro-arm',
                                       'pacman -Syu --noconfirm']),
                ('pacman', 'artix', ['pacman-key --init', 'pacman-key --populate artix',
                                     'pacman -Syu --noconfirm']),
                ('pacman', 'custom', ['pacman -Syu --noconfirm']),
                ('recovery', 'steamos', ['pacman -Syu --noconfirm'])):
            with self.subTest(family=family, distro=distro):
                result = subprocess.run(['sh', '-ec', stubs + functions + '\ninstall_libc_tools'],
                                        env={**os.environ, 'family': family, 'ID': distro,
                                             'PATH': str(self.directory) + os.pathsep + os.environ['PATH']},
                                        text=True, capture_output=True)
                self.assertEqual(0, result.returncode, result.stderr)
                lines = result.stdout.splitlines()
                commands = [line for line in lines if line.startswith(('apt-get ', 'apk ',
                            'zypper ', 'xbps-install ', 'pacman ', 'pacman-key '))]
                self.assertEqual(expected, commands)
                self.assertTrue(lines[-1].startswith('packages ca-certificates '), lines)

    def test_libc_build_package_cleanup_retains_failure_status(self):
        script = self.run_script('--print-libc-setup').stdout
        start = script.index("trap 'status=$?; package_cleanup;")
        end = script.index('extract_integration\n', start)
        for status in (0, 23):
            with self.subTest(status=status):
                stubs = f'''set -eu
target=installed
package_cleanup() {{ printf 'cleaned\\n'; }}
install_libc_tools() {{ return {status}; }}
identify_libc() {{ :; }}
reuse_libc() {{ return 1; }}
'''
                result = subprocess.run(['sh', '-c', stubs + script[start:end]],
                                        text=True, capture_output=True)
                self.assertEqual(status, result.returncode, result.stderr)
                self.assertEqual('Installing libc build dependencies...\ncleaned\n', result.stdout)

    def test_libc_recipe_accepts_all_installer_distributions(self):
        for distro in ('debian', 'ubuntu', 'alpine', 'fedora', 'arch', 'opensuse',
                       'openkylin', 'deepin', 'manjaro', 'void', 'armtix', 'steamos'):
            with self.subTest(distro=distro):
                self.log.unlink(missing_ok=True)
                shutil.rmtree(self.directory / 'libc', ignore_errors=True)
                result = self.run_script('--yes', '--resume', '--distro', distro, '--name', 'work', '--libc', 'shroot', TEST_DISTRO=distro)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertFalse(any(c[0] == 'image' for c in self.calls()))
                build = next(c for c in self.calls() if '--bind' in c and c[-3] == 'shroot')
                self.assertEqual(['exec', 'work'], build[:2])
                self.assertIn('SHROOT_LIBC_BUILD_TARGET=installed', build)

    def test_libc_mode_and_recipe_identity_reach_guest(self):
        import hashlib
        script = self.run_script('--print-libc-setup').stdout
        digest = hashlib.sha256(script.encode()).hexdigest()
        for mode in ('shroot', 'base'):
            with self.subTest(mode=mode):
                result = self.run_script('--yes', '--resume', '--name', 'work', '--libc', mode, '--jobs', '3')
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertTrue(any(c[-3:] == [mode, '3', digest] for c in self.calls()))
                self.assertEqual(script, Path(str(self.payload) + '.libc').read_text())
                self.assertFalse(any(c[0] in ('install', 'remove') for c in self.calls()))

    def test_libc_prepare_oci_uses_temporary_environment_and_retains_original_image(self):
        result = self.run_script('--prepare-libc', 'alpine:3.23', '--jobs', '1', TEST_IMAGE_ONLY='1')
        self.assertEqual(0, result.returncode, result.stderr)
        install = next(c for c in self.calls() if c[0] == 'install')
        self.assertEqual('alpine:3.23', install[1])
        self.assertIn(['remove', install[-1]], self.calls())
        build = next(c for c in self.calls() if '--bind' in c and c[-3] == 'shroot')
        self.assertEqual(['exec', install[-1]], build[:2])
        self.assertIn('SHROOT_LIBC_BUILD_TARGET=image', build)
        self.assertFalse(any(c[0] == 'image' for c in self.calls()))

    def test_libc_build_failure_keeps_work_and_does_not_enable_target(self):
        result = self.run_script('--prepare-libc', 'work', TEST_FAIL='libc')
        self.assertEqual(1, result.returncode)
        self.assertIn('distribution libc was not replaced by Shroot', result.stderr)
        self.assertIn('Build packages are retained', result.stderr)
        self.assertEqual(1, len(list((self.directory / 'libc/work').glob('build.*'))))
        self.assertFalse(any(c[0] == 'image' for c in self.calls()))
        self.assertFalse(any('rm -f /etc/shroot/libc-base' in arg for c in self.calls() for arg in c))

    def test_libc_cache_hit_skips_build(self):
        result = self.run_script('--prepare-libc', 'work', TEST_LIBC_CACHED='1')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('Reusing Shroot libc:', result.stdout)
        self.assertNotIn('Preparing libc directly', result.stdout)
        self.assertFalse(any('--bind' in c for c in self.calls()))
        self.assertFalse(any(c[0] == 'image' for c in self.calls()))
        self.assertTrue(any('rm -f /etc/shroot/libc-base' in arg for c in self.calls() for arg in c))

    def test_libc_preparation_reports_build_and_enable_in_order(self):
        result = self.run_script('--prepare-libc', 'work', '--jobs', '3')
        self.assertEqual(0, result.returncode, result.stderr)
        stages = ['Checking installed libc', 'Preparing libc directly in work',
                  'Enabling libc selection', 'Shroot libc prepared:']
        positions = [result.stdout.index(stage) for stage in stages]
        self.assertEqual(sorted(positions), positions)
        self.assertIn('(jobs: 3)', result.stdout)
        self.assertIn('no environment copy', result.stdout)
        self.assertEqual([], list((self.directory / 'libc/work').glob('build.*')))

    def test_libc_build_reidentifies_installed_target_after_dependencies_but_pins_images(self):
        source = SCRIPT.parents[1] / 'native/shroot/libc/build.sh'
        preparation = 'identify_libc\n' + source.read_text().split('\nidentify_libc\n', 1)[1]
        preparation = preparation.split('\nextract_integration\n', 1)[0]
        cache = self.directory / 'cache'
        (cache / 'new').mkdir(parents=True)
        (cache / 'new/manifest').write_text('fixture new\n')
        for target in ('installed', 'image'):
            with self.subTest(target=target):
                work = self.directory / target
                work.mkdir()
                setup = r'''
set -eu
version=old
mode=shroot
identify_libc() { manifest="fixture $version"; key=$version; kind=musl; }
install_libc_tools() { version=new; printf 'tools installed\n'; }
package_cleanup() { :; }
'''
                result = subprocess.run(['sh', '-c', setup + preparation + '\necho compile-required'],
                                        env={**os.environ, 'target': target, 'work': str(work),
                                             'cache': str(cache)}, text=True, capture_output=True)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertIn('tools installed', result.stdout)
                if target == 'installed':
                    self.assertEqual('fixture new\n', (work / 'manifest').read_text())
                    self.assertEqual('new\n', (work / 'result').read_text())
                    self.assertNotIn('compile-required', result.stdout)
                else:
                    self.assertEqual('fixture old\n', (work / 'manifest').read_text())
                    self.assertFalse((work / 'result').exists())
                    self.assertIn('compile-required', result.stdout)

    def test_libc_changed_during_build_does_not_report_a_publishable_result(self):
        source = (SCRIPT.parents[1] / 'native/shroot/libc/build.sh').read_text()
        final_check = source[source.rindex('\nif [ "$target" = installed ]; then'):]
        work = self.directory / 'work'
        work.mkdir()
        result = subprocess.run(['sh', '-c', 'set -eu; target=installed; manifest=old; key=old; '
                                 'identify_libc() { manifest=new; key=new; };\n' + final_check],
                                cwd=work, text=True, capture_output=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Installed libc changed', result.stderr)
        self.assertFalse((work / 'result').exists())

    def test_libc_failure_preserves_environment_and_reports_mode(self):
        result = self.run_script('--yes', '--resume', '--name', 'work', '--libc', 'shroot', TEST_FAIL='libc')
        self.assertEqual(23, result.returncode)
        self.assertIn('Environment retained', result.stderr)
        self.assertIn('--resume', result.stderr)
        self.assertIn('libc=shroot', result.stderr)
        self.assertFalse(any(c[0] in ('install', 'remove') for c in self.calls()))

    def test_libc_invalid_mode_does_not_reach_guest(self):
        result = self.run_script('--yes', '--libc', 'automatic')
        self.assertEqual(1, result.returncode)
        self.assertEqual([], self.calls())

    def test_source_builds_prepare_libc_after_dependencies_and_reuse_it(self):
        for distro, gpu in (('steamos', 'auto'), ('debian', 'turnip')):
            with self.subTest(distro=distro, gpu=gpu):
                self.log.unlink(missing_ok=True)
                result = self.run_script('--yes', '--resume', '--distro', distro,
                                         '--name', 'work', '--gui', 'plasma', '--gpu', gpu,
                                         '--libc', 'shroot', TEST_DISTRO=distro)
                self.assertEqual(0, result.returncode, result.stderr)
                calls = self.calls()
                phases = [(i, c) for i, c in enumerate(calls)
                          if any(a.startswith('MAGICDESK_BUILD_PHASE=') for a in c)]
                self.assertEqual(4, len(phases))
                for start in (0, 2):
                    dep_index, dependencies = phases[start]
                    build_index, build = phases[start + 1]
                    self.assertIn('MAGICDESK_BUILD_PHASE=dependencies', dependencies)
                    self.assertIn('MAGICDESK_BUILD_PHASE=build', build)
                    self.assertEqual(dependencies[-1], build[-1])
                    self.assertTrue(any(c[-3] == 'identify' for c in calls[dep_index + 1:build_index]
                                        if len(c) >= 3))
                    self.assertTrue(any('rm -f /etc/shroot/libc-base' in a
                                        for c in calls[dep_index + 1:build_index] for a in c))
                self.assertFalse(any(c[-3] == 'identify' for c in calls[:phases[0][0]] if len(c) >= 3))
                self.assertFalse(any(c[0] == 'image' for c in calls))
                self.assertIn('Reusing Shroot libc:', result.stdout)

    def test_kwin_dependencies_changing_libc_prepare_the_new_identity_before_build(self):
        result = self.run_script('--yes', '--resume', '--name', 'work', '--gui', 'plasma',
                                 '--gpu', 'turnip', '--libc', 'shroot',
                                 TEST_LIBC_CHANGE_ON_KWIN_DEPS='1')
        self.assertEqual(0, result.returncode, result.stderr)
        calls = self.calls()
        self.assertEqual(2, sum('--bind' in c and c[-3] == 'shroot' for c in calls))
        self.assertFalse(any(c[0] == 'image' for c in calls))
        enable = [c[-1] for c in calls if any('rm -f /etc/shroot/libc-base' in a for a in c)]
        self.assertEqual(2, len(set(enable)))
        self.assertIn('MAGICDESK_BUILD_PHASE=build', calls[-1])

    def test_failed_build_dependencies_do_not_prepare_libc_or_start_compilers(self):
        result = self.run_script('--yes', '--resume', '--name', 'work', '--gpu', 'turnip',
                                 '--libc', 'shroot', TEST_FAIL_DEPENDENCIES='graphics')
        self.assertEqual(23, result.returncode, result.stderr)
        self.assertIn('installing build dependencies', result.stderr)
        self.assertFalse(any(c[:2] == ['image', 'backup'] for c in self.calls()))
        self.assertFalse(any('MAGICDESK_BUILD_PHASE=build' in c for c in self.calls()))

    def test_failed_libc_preparation_does_not_start_source_builds(self):
        result = self.run_script('--yes', '--resume', '--name', 'work', '--gpu', 'turnip',
                                 '--libc', 'shroot', TEST_FAIL='libc')
        self.assertEqual(23, result.returncode, result.stderr)
        self.assertTrue(any('MAGICDESK_BUILD_PHASE=dependencies' in c for c in self.calls()))
        self.assertFalse(any('MAGICDESK_BUILD_PHASE=build' in c for c in self.calls()))
        self.assertNotIn('Linux is ready', result.stdout)

    def test_source_build_phases_separate_packages_from_compilers(self):
        result = self.run_script('--yes', '--resume', '--name', 'work', '--gui', 'plasma', '--gpu', 'turnip')
        self.assertEqual(0, result.returncode, result.stderr)
        for suffix in ('.gpu', '.kwin'):
            script = Path(str(self.payload) + suffix).read_text()
            start = script.index('    if [ "$build_phase" != build ]; then')
            end_marker = '    [ "$build_phase" != dependencies ] || exit 0'
            end = script.index(end_marker, start) + len(end_marker)
            fragment = ('set -eu\npackages() { printf "packages\\n"; }\n'
                        + script[start:end] + '\nprintf "compile\\n"\n')
            for family in ('apt', 'recovery'):
                for phase, expected in (('all', 'packages\ncompile\n'),
                                        ('dependencies', 'packages\n'), ('build', 'compile\n')):
                    with self.subTest(recipe=suffix, family=family, phase=phase):
                        result = subprocess.run(['sh', '-c', fragment], capture_output=True,
                                                text=True, timeout=5,
                                                env={**os.environ, 'family': family, 'build_phase': phase})
                        self.assertEqual(0, result.returncode, result.stderr)
                        self.assertEqual(expected, result.stdout)

    @unittest.skipUnless(hasattr(os, 'openpty'), 'PTY required')
    def test_interactive_dns_repair_follows_configuration_and_retries_only_dns(self):
        output = self.questions(b'alpine\nwork\nxfce\nsoftware\n\n\nkeep\nkeep\nbasic\nn\nauto\ninvalid\n192.0.2.1\ny\n',
                                TEST_DNS_ERROR='No active-network DNS servers')
        self.assertGreater(output.index('Cannot prepare guest DNS'), output.index('Additional settings ('))
        self.assertEqual(1, output.count('Distribution ['))
        self.assertEqual([['dns', '--check', value] for value in ('system', 'system', 'invalid', '192.0.2.1')], self.dns_checks())
        install = next(c for c in self.calls() if c[0] == 'install')
        self.assertEqual(['--rootfs', '--name', 'work', '--dns', '192.0.2.1'], install[2:])
        self.assertIn('Linux is ready: work', output)

    @unittest.skipUnless(hasattr(os, 'openpty'), 'PTY required')
    def test_unavailable_dns_can_be_cancelled_without_installing(self):
        output = self.questions(b'alpine\nwork\nxfce\nsoftware\n\n\nkeep\nkeep\nbasic\nn\n\n',
                                TEST_DNS_ERROR='Android Private DNS is active')
        self.assertIn('Cancelled.', output)
        self.assertIn('Distribution [', output)
        self.assertEqual([], self.calls())

    @unittest.skipUnless(hasattr(os, 'openpty'), 'PTY required')
    def test_advanced_invalid_dns_retains_other_answers(self):
        output = self.questions(b'alpine\nwork\nxfce\nsoftware\nkeep\nkeep\nkeep\nbasic\ny\n\nboth\n\ninvalid\nkeep\npreserve\ny\n')
        self.assertEqual([['dns', '--check', value] for value in ('invalid', 'preserve')], self.dns_checks())
        self.assertEqual(1, output.count('Distribution ['))
        install = next(c for c in self.calls() if c[0] == 'install')
        self.assertEqual(['--rootfs', '--name', 'work', '--dns', 'preserve'], install[2:])

    @unittest.skipUnless(hasattr(os, 'openpty'), 'PTY required')
    def test_package_failure_can_change_dns_without_reinstalling_or_repeating_answers(self):
        output = self.questions(b'alpine\nwork\nxfce\nsoftware\n\n\nkeep\nkeep\nbasic\nn\ny\ndns\ninvalid\n192.0.2.1\n',
                                TEST_SETUP_FAILURES='1')
        self.assertIn('test package download failure', output)
        self.assertIn('Linux is ready: work', output)
        self.assertEqual(1, output.count('Distribution ['))
        self.assertEqual(1, sum(c[0] == 'install' for c in self.calls()))
        self.assertIn(['dns', 'work', '192.0.2.1', '--replace'], self.calls())
        setups = [c for c in self.calls() if c[0] == 'exec' and '-s' in c and c[-8] == 'xfce']
        self.assertEqual(2, len(setups))
        self.assertEqual(setups[0], setups[1])

    @unittest.skipUnless(hasattr(os, 'openpty'), 'PTY required')
    def test_package_retry_can_switch_to_current_network(self):
        output = self.questions(b'alpine\nwork\nnone\nkeep\nkeep\nkeep\nkeep\nkeep\ny\n\nboth\n\n192.0.2.1\nkeep\ny\ndns\nauto\n',
                                TEST_SETUP_FAILURES='1')
        self.assertEqual([['dns', '--check', p] for p in ('192.0.2.1', 'system')], self.dns_checks())
        self.assertIn(['dns', 'work', 'system', '--replace'], self.calls())
        self.assertEqual(1, sum(c[0] == 'install' for c in self.calls()))
        self.assertIn('Linux is ready: work', output)

    @unittest.skipUnless(hasattr(os, 'openpty'), 'PTY required')
    def test_package_retry_and_cancel_keep_the_environment(self):
        output = self.questions(b'alpine\nwork\nxfce\nsoftware\n\n\nkeep\nkeep\nbasic\nn\ny\ninvalid\nretry\n\n',
                                expected_exit=23, TEST_SETUP_FAILURES='2')
        self.assertIn('Environment retained.', output)
        self.assertEqual(1, sum(c[0] == 'install' for c in self.calls()))
        self.assertFalse(any(c[0] == 'remove' for c in self.calls()))

    def test_unattended_package_failure_never_retries(self):
        result = self.run_script('--yes', '--distro', 'alpine', TEST_SETUP_FAILURES='1')
        self.assertEqual(23, result.returncode)
        self.assertIn('--resume', result.stderr)
        self.assertEqual('1', Path(str(self.payload) + '.attempts').read_text())
        self.assertNotIn('Package setup: retry', result.stdout)

    def test_minimum_and_newer_versions_are_accepted_with_one_query(self):
        for version in (MIN_VERSION_CODE, MIN_VERSION_CODE + 1, 2147483647):
            with self.subTest(version=version):
                self.version_log.unlink(missing_ok=True)
                result = self.run_script("--yes", TEST_VERSION_CODE=str(version))
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual([VERSION_QUERY], self.version_calls())

    def test_old_versions_stop_before_questions_resume_or_recovery_work(self):
        for args in ((), ("--yes",), ("--yes", "--resume", "--name", "existing"),
                     ("--yes", "--distro", "steamos")):
            with self.subTest(args=args):
                self.version_log.unlink(missing_ok=True)
                result = self.run_script(*args, TEST_VERSION_CODE=str(MIN_VERSION_CODE - 1))
                self.assertEqual(1, result.returncode, result.stderr)
                self.assertIn("requires MagicDesk " + MIN_VERSION_NAME, result.stderr)
                self.assertIn("installed " + str(MIN_VERSION_CODE - 1), result.stderr)
                self.assertIn("Update MagicDesk", result.stderr)
                self.assertNotIn("Interactive input", result.stderr)
                self.assertEqual([VERSION_QUERY], self.version_calls())
                self.assertEqual([], self.calls())
                self.assertFalse(self.payload.exists())

    def test_unknown_or_failed_version_query_never_runs_shroot(self):
        for version, status in (("", "0"), ("null", "0"), ("2.0.3", "0"), ("218-dev", "0"),
                                ("218\n219", "0"), ("-1", "0"), ("+218", "0"),
                                (" 218", "0"), ("9" * 100, "0"), ("2147483648", "0"),
                                (str(MIN_VERSION_CODE), "1"), (str(MIN_VERSION_CODE), "3")):
            with self.subTest(version=version, status=status):
                result = self.run_script("--yes", TEST_VERSION_CODE=version, TEST_VERSION_STATUS=status)
                self.assertEqual(1, result.returncode, result.stderr)
                self.assertIn("MagicDesk version", result.stderr)
                self.assertEqual([], self.calls())
                self.assertFalse(self.payload.exists())

    def test_missing_magicdesk_fails_but_offline_commands_still_work(self):
        (self.directory / "magicdesk").unlink()
        # Restrict PATH after the host shell (including launcher wrappers) starts.
        # EVENT_WAIT: installer rejection; timeout fails a stuck subprocess.
        result = subprocess.run(["sh", "-c", 'PATH=$1; script=$2; shift 2; . "$script"',
                                 "installer-test", str(self.directory), str(SCRIPT), "--yes"],
                                input="", text=True, capture_output=True, env=self.environment, timeout=15)
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertIn("magicdesk is unavailable", result.stderr)
        for option in ("--help", "--list", "--print-mesa-patch", "--print-kwin-patch",
                       "--print-system-setup", "--print-graphics-setup", "--print-libc-setup",
                       "--print-recovery-reader", "--print-desktop-session", "--print-audio-session", "--print-steam-game"):
            with self.subTest(option=option):
                result = self.run_script(option, TEST_UID="10001", TEST_VERSION_STATUS="3")
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertTrue(result.stdout)
        self.assertEqual([], self.version_calls())
        self.assertEqual([], self.calls())

    def test_version_floor_does_not_exceed_this_apk(self):
        properties = dict(line.split("=", 1) for line in (SCRIPT.parents[1] / "gradle.properties").read_text().splitlines()
                          if "=" in line and not line.startswith("#"))
        self.assertLessEqual(MIN_VERSION_CODE, int(properties["magicDeskVersionCode"]))
        if MIN_VERSION_CODE == int(properties["magicDeskVersionCode"]):
            self.assertEqual(properties["magicDeskVersionName"], MIN_VERSION_NAME)
        result = self.run_script("--help")
        self.assertIn("Requires MagicDesk " + MIN_VERSION_NAME, result.stdout)
        self.assertIn("versionCode " + str(MIN_VERSION_CODE), result.stdout)

    def test_apps_install_uses_existing_commands_and_keeps_guest_setup_on_stdin(self):
        result = self.run_script("--yes", "--name", "work")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(["--probe"], self.calls()[0])
        install = next(c for c in self.calls() if c[0] == 'install')
        self.assertEqual(['--rootfs', '--name', 'work', '--dns', 'system'], install[2:])
        self.assertIn(["dns", "work", "system", "--replace"], self.calls())
        self.assertEqual(["exec", "work", "--user", "root", "--env", "DEBIAN_FRONTEND=noninteractive",
                          "--env", "SYSTEMD_IN_CHROOT=1",
                          "--", "/bin/sh", "-s", "--", "apps", "both", "keep", "keep", "", "basic", "keep", ""], self.system_setup_call())
        self.assertIn("Linux is ready: work", result.stdout)
        payload = self.payload.read_text()
        self.assertIn('apt-get install -y --no-install-recommends "$@" </dev/null', payload)
        self.assertIn('backend=wayland', payload)
        self.assertIn("X-MagicDesk-GraphicsMode=desktop", payload)
        self.assertIn("printf 'unset LC_ALL\\nexport LANG=%s\\n'", payload)
        self.assertIn('path-include /usr/share/locale/*', payload)
        self.assertNotIn("/data/local/tmp", payload)
        self.assertEqual(0, subprocess.run(["sh", "-n", str(self.payload)]).returncode)

    def test_explicit_xbps_network_preference_reaches_each_setup_stage(self):
        result = self.run_script('--yes', '--distro', 'void', '--image', 'example/void:test',
                                 '--gpu', 'turnip', '--libc', 'keep', FORCE_IPV4='1')
        self.assertEqual(0, result.returncode, result.stderr)
        stages = [call for call in self.calls() if call[0] == 'exec' and '-s' in call]
        self.assertEqual(3, len(stages))
        for call in stages:
            self.assertIn('FORCE_IPV4=1', call)
        self.assertNotIn('FORCE_IPV4=1', next(call for call in self.calls() if call[0] == 'install'))

    def test_print_system_setup_matches_installed_payload_without_host_operations(self):
        printed = self.run_script('--print-system-setup')
        self.assertEqual(0, printed.returncode, printed.stderr)
        self.assertEqual([], self.calls())
        self.assertEqual([], self.version_calls())
        installed = self.run_script('--yes', '--gui', 'none')
        self.assertEqual(0, installed.returncode, installed.stderr)
        self.assertEqual(self.payload.read_text(), printed.stdout)

    def test_xfce_profile_and_root_executor(self):
        result = self.run_script("--yes", "--gui", "xfce", TEST_UID="0")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("xfce", self.system_setup_call()[-8])

    def test_gui_installs_gl_dispatch_libraries_with_mesa_drivers(self):
        result = self.run_script('--yes', '--gui', 'apps')
        self.assertEqual(0, result.returncode, result.stderr)
        setup = self.payload.read_text()
        start = setup.index('    case "$family" in\n        apt) packages dbus-x11')
        end = setup.index('\n    dbus-uuidgen --ensure', start)
        command = 'family=apt\npackages() { printf "%s\\n" "$@"; }\n' + setup[start:end]
        # EVENT_WAIT: package selection exits; timeout fails a stuck recipe.
        selected = subprocess.run(['sh', '-eu', '-c', command], capture_output=True,
                                  text=True, timeout=5)
        self.assertEqual(0, selected.returncode, selected.stderr)
        packages = set(selected.stdout.splitlines())
        self.assertTrue({'libgl1-mesa-dri', 'libegl-mesa0', 'libglx-mesa0',
                         'libegl1', 'libgl1', 'libgles2'} <= packages)

    def test_audio_session_owns_graph_and_keeps_host_transport_separate(self):
        result = self.run_script('--print-audio-session')
        self.assertEqual(0, result.returncode, result.stderr)
        helper = self.directory / 'audio-session'
        helper.write_text(result.stdout)
        self.assertEqual(0, subprocess.run(['bash', '-n', str(helper)]).returncode)
        self.assertIn('libpipewire-module-pulse-tunnel', result.stdout)
        self.assertIn('node.name = magicdesk.android', result.stdout)
        self.assertIn('node.virtual = false', result.stdout)
        self.assertIn('default.clock.min-quantum = 1024', result.stdout)
        self.assertIn('pulse.min.req = 1024/48000', result.stdout)
        self.assertIn('pulse.min.quantum = 1024/48000', result.stdout)
        self.assertIn('pulse.latency = 60', result.stdout)
        self.assertIn('pw-link --input --monitor', result.stdout)
        self.assertLess(result.stdout.index('Guest Android audio sink was not configured.'),
                        result.stdout.index('"$@" <&0'))
        self.assertLess(result.stdout.index('pipewire-pulse.conf.d/90-magicdesk.conf'),
                        result.stdout.index('libpipewire-module-pulse-tunnel'))
        self.assertIn('MAGICDESK_AUDIO_SESSION=active', result.stdout)
        self.assertIn('export DISABLE_RTKIT=1', result.stdout)
        self.assertNotIn('module.rt.args', result.stdout)
        self.assertIn('EVENT_WAIT:', result.stdout)
        self.assertNotIn('sleep ', result.stdout)
        env = dict(self.environment)
        env.pop('MAGICDESK_AUDIO_PULSE', None)
        # EVENT_WAIT: without an audio capability, the original command exits normally.
        bypass = subprocess.run(['bash', str(helper), 'sh', '-c', 'exit 17'], env=env, timeout=5)
        self.assertEqual(17, bypass.returncode)
        nested = subprocess.run(['bash', str(helper), 'sh', '-c', 'exit 19'],
                                env=dict(env, MAGICDESK_AUDIO_PULSE='/unused',
                                         MAGICDESK_AUDIO_SESSION='active'), timeout=5)
        self.assertEqual(19, nested.returncode)
        result = self.run_script('--yes', '--gui', 'plasma')
        self.assertEqual(0, result.returncode, result.stderr)
        setup = self.payload.read_text()
        self.assertIn('packages pipewire pipewire-bin pipewire-pulse wireplumber pipewire-alsa', setup)
        self.assertIn('Exec=magicdesk-desktop-session %s', setup)

    def test_all_package_families_supply_audio_gamepads_and_wayland_decorations(self):
        self.assertEqual(0, self.run_script('--yes').returncode)
        setup = self.payload.read_text()
        start = setup.index('    case "$family" in\n        apt) packages pipewire')
        end = setup.index('\n    install_audio_session', start)
        expected = {
            'apt': {'pipewire-bin', 'pipewire-pulse', 'wireplumber', 'pipewire-alsa',
                    'libsdl2-2.0-0', 'libudev1', 'libdecor-0-plugin-1-cairo'},
            'apk': {'pipewire-tools', 'pipewire-pulse', 'wireplumber', 'pipewire-alsa',
                    'sdl2', 'eudev-libs', 'libdecor'},
            'dnf': {'pipewire-utils', 'pipewire-pulseaudio', 'wireplumber', 'pipewire-alsa',
                    'sdl2-compat', 'systemd-libs', 'libdecor'},
            'pacman': {'pipewire-pulse', 'wireplumber', 'pipewire-alsa', 'libpulse',
                       'sdl2', 'systemd-libs', 'libdecor'},
            'zypper': {'pipewire-pulseaudio', 'pipewire-tools', 'wireplumber', 'pipewire-alsa',
                       'libSDL2-2_0-0', 'libudev1', 'libdecor'},
            'xbps': {'pipewire', 'wireplumber', 'alsa-pipewire', 'SDL2', 'eudev-libudev', 'libdecor'},
        }
        expected['recovery'] = expected['pacman']
        for family, libraries in expected.items():
            with self.subTest(family=family):
                command = 'ID=arch\nfamily=' + family + '\npackages() { printf "%s\\n" "$@"; }\n' + setup[start:end]
                # EVENT_WAIT: distribution dependency selection must exit without host changes.
                result = subprocess.run(['sh', '-eu', '-c', command], capture_output=True, text=True, timeout=5)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertTrue(libraries <= set(result.stdout.splitlines()), result.stdout)
        command = 'ID=artix\nfamily=pacman\npackages() { printf "%s\\n" "$@"; }\n' + setup[start:end]
        result = subprocess.run(['sh', '-eu', '-c', command], capture_output=True, text=True, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('libudev', result.stdout.splitlines())
        self.assertIn('sdl2-compat', result.stdout.splitlines())
        self.assertNotIn('systemd-libs', result.stdout.splitlines())
        self.assertNotIn('SDL_JOYSTICK_HIDAPI=', setup)
        self.assertNotIn('SDL_AUDIODRIVER=', setup)
        self.assertNotIn('QML_DISABLE', setup)
        self.assertNotIn('KWIN_NO_TIMER_QUERY', setup)

    def test_new_package_families_use_their_mesa_tool_names(self):
        self.assertEqual(0, self.run_script('--yes', '--gpu', 'turnip').returncode)
        setup = Path(str(self.payload) + '.gpu').read_text()
        start = setup.index('    case "$family" in\n    apt) packages build-essential')
        end = setup.index('\n    esac', start) + len('\n    esac')
        for family, required in [('zypper', {'glslang-devel', 'python3-Mako', 'vulkan-tools'}),
                                 ('xbps', {'glslang', 'python3-Mako', 'Vulkan-Headers', 'Vulkan-Tools'})]:
            with self.subTest(family=family):
                command = 'family=' + family + '\npackages() { printf "%s\\n" "$@"; }\n' + setup[start:end]
                # EVENT_WAIT: dependency selection exits without installing host packages.
                result = subprocess.run(['sh', '-eu', '-c', command], capture_output=True, text=True, timeout=5)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertTrue(required <= set(result.stdout.splitlines()), result.stdout)

    def test_desktop_entry_refresh_preserves_selection_and_distribution_entries(self):
        self.assertEqual(0, self.run_script('--yes').returncode)
        setup = self.payload.read_text()
        start = setup.index('if [ "$gui_services" = yes ]; then\n    # Refresh only')
        end = setup.index('\nif [ "$fonts" != keep ]; then', start)
        applications = self.directory / 'local/share/applications'
        applications.mkdir(parents=True)
        for program in ('xfce4-session', 'weston', 'gnome-shell', 'startplasma-x11', 'startplasma-wayland'):
            executable = self.directory / program
            executable.write_text('#!/bin/sh\nexit 0\n')
            executable.chmod(0o755)
        old = applications / 'magicdesk-xfce.desktop'
        old.write_text('installer entry')
        custom = applications / 'user.desktop'
        custom.write_text('user entry')
        command = setup[start:end].replace('/usr/local/', str(self.directory / 'local') + '/')
        titles = {'xfce': 'Xfce Desktop', 'weston': 'Weston Desktop', 'gnome': 'GNOME Shell (development kit)',
                  'plasma-x11': 'Plasma Desktop (x11)', 'plasma-wayland': 'Plasma Desktop (wayland)'}
        for gui, modes in [('keep', ['xfce']), ('plasma', ['xfce', 'plasma-x11', 'plasma-wayland']),
                           ('weston', ['xfce', 'plasma-x11', 'plasma-wayland', 'weston']),
                           ('gnome', list(titles))]:
            # EVENT_WAIT: entry refresh must exit and preserve unrelated files.
            result = subprocess.run(['sh', '-eu', '-c', command],
                                    env=dict(self.environment, gui=gui, gui_services='yes', NAME='Alpine Linux', ID='alpine'),
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual('user entry', custom.read_text())
            self.assertEqual({f'magicdesk-{mode}.desktop' for mode in modes},
                             {p.name for p in applications.glob('magicdesk-*.desktop')})
            for mode in modes:
                entry = (applications / f'magicdesk-{mode}.desktop').read_text()
                self.assertIn(f'Name=Alpine Linux - {titles[mode]}\n', entry)
                self.assertIn('Exec=magicdesk-desktop-session ' + mode + '\n', entry)
                self.assertIn('X-MagicDesk-GraphicsMode=desktop\n', entry)
        # Repeated refresh reads OS identity, not the previous label or the instance name.
        for name in ('Debian GNU/Linux', 'Ubuntu', 'Fedora Linux', 'Arch Linux ARM',
                     'openSUSE Tumbleweed', 'openKylin', 'Deepin', 'Manjaro ARM',
                     'Void', 'Armtix', 'SteamOS', '', None):
            with self.subTest(os_name=name):
                environment = dict(self.environment, gui='keep', gui_services='yes', ID='alpine')
                environment.pop('NAME', None)
                if name is not None:
                    environment['NAME'] = name
                result = subprocess.run(['sh', '-eu', '-c', command], env=environment,
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual('user entry', custom.read_text())
                for mode, title in titles.items():
                    entry = (applications / f'magicdesk-{mode}.desktop').read_text()
                    self.assertIn(f'Name={name or "alpine"} - {title}\n', entry)

    def test_desktop_launch_owns_audio_and_preserves_gamepad_for_each_protocol(self):
        audio = self.directory / 'magicdesk-audio-session'
        audio.write_text('#!' + sys.executable + '\nimport json, os, sys\n'
                         'print(json.dumps({"argv": sys.argv[1:], "env": dict(os.environ)}))\n'
                         'sys.exit(23)\n')
        audio.chmod(0o755)
        bus = self.directory / 'dbus-run-session'
        bus.write_text('#!/bin/sh\nshift\nexport DBUS_SESSION_BUS_ADDRESS=unix:path=/test-bus\nexec "$@"\n')
        bus.chmod(0o755)
        config = self.directory / 'kwriteconfig6'
        config.write_text('#!/bin/sh\nexit 0\n')
        config.chmod(0o755)
        home = self.directory / 'home'
        home.mkdir()
        environment = dict(self.environment, HOME=str(home))
        environment.pop('MAGICDESK_MESA_PREFIX', None)
        launcher = self.run_script('--print-desktop-session').stdout
        launcher = launcher.replace('/etc/profile.d/', str(self.directory / 'profiles') + '/')
        launcher = launcher.replace('/tmp/.X11-unix', str(self.directory / 'x11'))
        modes = {'xfce': 'xfce4-session', 'weston': 'weston', 'gnome': 'gnome-shell',
                 'plasma-x11': 'startplasma-x11', 'plasma-wayland': 'startplasma-wayland'}
        for mode, program in modes.items():
            for inherited in (False, True):
                with self.subTest(mode=mode, inherited=inherited):
                    environment.pop('DBUS_SESSION_BUS_ADDRESS', None)
                    if inherited:
                        environment['DBUS_SESSION_BUS_ADDRESS'] = 'unix:path=/existing-bus'
                    environment.update(MAGICDESK_GAMEPAD_ENDPOINT='abstract-gamepad',
                                       MAGICDESK_AUDIO_PULSE='/tmp/android-pulse')
                    # EVENT_WAIT: launcher reaches its audio owner; expiry fails the fixture.
                    launched = subprocess.run(['sh', '-c', launcher, 'desktop', mode, 'a b'],
                                              env=environment, capture_output=True, text=True, timeout=5)
                    self.assertEqual(23, launched.returncode, launched.stderr)
                    captured = json.loads(launched.stdout)
                    self.assertEqual(program, captured['argv'][0])
                    self.assertEqual('a b', captured['argv'][-1])
                    self.assertEqual('abstract-gamepad', captured['env']['MAGICDESK_GAMEPAD_ENDPOINT'])
                    self.assertEqual('/tmp/android-pulse', captured['env']['MAGICDESK_AUDIO_PULSE'])
                    self.assertEqual('unix:path=/existing-bus' if inherited else 'unix:path=/test-bus',
                                     captured['env']['DBUS_SESSION_BUS_ADDRESS'])

    def test_root_desktop_autostart_preserves_user_and_distribution_settings(self):
        setup = self.run_script('--print-system-setup').stdout
        start = setup.index('mkdir -p /etc/magicdesk/root-session/autostart')
        end = setup.index('\n}\n', start)
        profile = self.directory / 'root-session'
        command = setup[start:end].replace('/etc/magicdesk/root-session', str(profile))
        subprocess.run(['sh', '-eu', '-c', command], check=True, timeout=5)
        entry = (profile / 'autostart/xfce-polkit.desktop').read_text()
        self.assertIn('Hidden=true\n', entry)
        launcher = self.run_script('--print-desktop-session').stdout
        launcher = launcher.replace('/etc/profile.d/', str(self.directory / 'profiles') + '/')
        capture = self.directory / 'magicdesk-audio-session'
        capture.write_text('#!' + sys.executable + '\nimport json, os\nprint(json.dumps(dict(os.environ)))\n')
        capture.chmod(0o755)
        identity = self.directory / 'id'
        for uid in (0, 1000):
            identity.write_text('#!/bin/sh\nprintf "%s\\n" ' + str(uid) + '\n')
            identity.chmod(0o755)
            for directories in (None, '/custom/xdg:/etc/xdg'):
                environment = dict(self.environment, DBUS_SESSION_BUS_ADDRESS='unix:path=/existing-bus',
                                   XDG_CONFIG_HOME='/user/config')
                environment.pop('XDG_CONFIG_DIRS', None)
                if directories is not None:
                    environment['XDG_CONFIG_DIRS'] = directories
                result = subprocess.run(['sh', '-c', launcher, 'desktop', 'xfce'],
                                        env=environment, capture_output=True, text=True, timeout=5)
                self.assertEqual(0, result.returncode, result.stderr)
                values = json.loads(result.stdout)
                self.assertEqual('/user/config', values['XDG_CONFIG_HOME'])
                expected = '/etc/magicdesk/root-session:' + (directories or '/etc/xdg') if uid == 0 else directories
                self.assertEqual(expected, values.get('XDG_CONFIG_DIRS'))

    def test_desktop_profile_selects_renderer_and_private_kwin_without_driver_overrides(self):
        capture = self.directory / 'magicdesk-audio-session'
        capture.write_text('#!' + sys.executable + '\nimport json, os, sys\n'
                           'print(json.dumps({"argv": sys.argv[1:], "env": dict(os.environ)}))\n')
        capture.chmod(0o755)
        config = self.directory / 'kwriteconfig6'
        config.write_text('#!/bin/sh\nexit 0\n')
        config.chmod(0o755)
        profiles = self.directory / 'profiles'
        profiles.mkdir()
        kwin = self.directory / 'kwin'
        (kwin / 'bin').mkdir(parents=True)
        executable = kwin / 'bin/kwin_wayland'
        executable.write_text('#!/bin/sh\nexit 0\n')
        executable.chmod(0o755)
        selection = self.directory / 'plasma-kwin.sh'
        selection.write_text('kwin_prefix=' + shlex.quote(str(kwin)) + '\n')
        launcher = self.run_script('--print-desktop-session').stdout
        launcher = launcher.replace('/etc/profile.d/', str(profiles) + '/')
        launcher = launcher.replace('/etc/magicdesk/plasma-kwin.sh', str(selection))
        launcher = launcher.replace('/tmp/.X11-unix', str(self.directory / 'x11'))
        environment = dict(self.environment, HOME=str(self.directory / 'home'),
                           DBUS_SESSION_BUS_ADDRESS='unix:path=/existing-bus')
        for key in ('MAGICDESK_MESA_PREFIX', 'KWIN_COMPOSE', 'QT_QUICK_BACKEND'):
            environment.pop(key, None)
        for gpu in ('software', 'turnip'):
            (profiles / 'magicdesk-graphics.sh').write_text(
                'export MAGICDESK_MESA_PREFIX=/opt/private-mesa\n' if gpu == 'turnip' else
                'export LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=llvmpipe\n')
            for mode in ('weston', 'plasma-wayland', 'plasma-x11'):
                with self.subTest(gpu=gpu, mode=mode):
                    # EVENT_WAIT: the launch reaches its audio owner with the selected graphics profile.
                    result = subprocess.run(['sh', '-c', launcher, 'desktop', mode],
                                            env=environment, capture_output=True, text=True, timeout=5)
                    self.assertEqual(0, result.returncode, result.stderr)
                    captured = json.loads(result.stdout)
                    env = captured['env']
                    if mode == 'weston':
                        self.assertIn('--renderer=' + ('gl' if gpu == 'turnip' else 'pixman'), captured['argv'])
                    elif mode == 'plasma-wayland' and gpu == 'software':
                        self.assertEqual('Q', env['KWIN_COMPOSE'])
                        self.assertEqual('software', env['QT_QUICK_BACKEND'])
                    elif mode == 'plasma-x11' and gpu == 'software':
                        self.assertNotIn('KWIN_COMPOSE', env)
                        self.assertEqual('software', env['QT_QUICK_BACKEND'])
                    else:
                        self.assertNotIn('KWIN_COMPOSE', env)
                        self.assertNotIn('QT_QUICK_BACKEND', env)
                    self.assertEqual(mode == 'plasma-wayland' and gpu == 'turnip',
                                     env['PATH'].startswith(str(kwin / 'bin') + ':'))
                    if gpu == 'turnip':
                        self.assertEqual('/opt/private-mesa', env['MAGICDESK_MESA_PREFIX'])
        selection.unlink()
        rejected = subprocess.run(['sh', '-c', launcher, 'desktop', 'plasma-wayland'],
                                  env=environment, capture_output=True, text=True, timeout=5)
        self.assertNotEqual(0, rejected.returncode)
        self.assertIn('Complete Plasma Turnip setup', rejected.stderr)

    def test_software_profile_uses_verified_lavapipe_on_steamos_only(self):
        payload = self.run_script('--print-graphics-setup', TEST_UID='10001').stdout
        root = self.directory / 'graphics-root'
        root.mkdir()
        release = root / 'os-release'
        payload = payload.replace('/etc/os-release', str(release))
        for original, name in (('/etc/profile.d', 'profiles'), ('/var/lib/magicdesk', 'state'),
                               ('/var/cache/magicdesk', 'cache')):
            payload = payload.replace(original, str(root / name))
        package_log = root / 'packages'
        for name, body in {
            'pacman': 'printf "%s\\n" "$*" >> ' + shlex.quote(str(package_log)),
            'gpgconf': 'exit 0',
            'vulkaninfo': 'test "${TEST_PROBE:-}" != fail; echo DRIVER_ID_MESA_LLVMPIPE',
            'eglinfo': ('test "$GALLIUM_DRIVER" = zink; test "$LIBGL_ALWAYS_SOFTWARE" = 1; '
                        'test "${MESA_VK_WSI_DEBUG-unset}" = unset; '
                        'test "$VK_DRIVER_FILES" = /usr/share/vulkan/icd.d/lvp_icd.aarch64.json; '
                        'test "${TEST_PROBE:-}" != wrong || { echo "OpenGL core profile renderer: hardware"; exit 0; }; '
                        'echo "OpenGL core profile renderer: zink Vulkan 1.3(llvmpipe)"'),
        }.items():
            script = self.directory / name
            script.write_text('#!/bin/sh\nset -eu\n' + body + '\n')
            script.chmod(0o755)
        profile = root / 'profiles/magicdesk-graphics.sh'
        for distro, outcome in (('steamos', 'pass'), ('steamos', 'fail'),
                                 ('steamos', 'wrong'), ('debian', 'pass')):
            with self.subTest(distro=distro, outcome=outcome):
                release.write_text('ID=' + distro + '\n')
                profile.parent.mkdir(exist_ok=True)
                profile.write_text('original profile\n')
                package_log.write_text('')
                result = subprocess.run(['sh', '-c', payload, 'graphics', 'software', '1', 'fixture'],
                                        env=dict(self.environment, TEST_PROBE=outcome),
                                        capture_output=True, text=True, timeout=5)
                if outcome != 'pass':
                    self.assertNotEqual(0, result.returncode, result.stdout)
                    self.assertEqual('original profile\n', profile.read_text())
                    self.assertIn('profile is unchanged', result.stderr)
                else:
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertIn('GALLIUM_DRIVER=' + ('zink' if distro == 'steamos' else 'llvmpipe'),
                                  profile.read_text())
                self.assertEqual(distro == 'steamos', 'vulkan-swrast llvm17-libs' in package_log.read_text())
                self.assertFalse(profile.with_name(profile.name + '.new').exists())

    def test_mixer_dependencies_refresh_for_existing_desktops(self):
        self.assertEqual(0, self.run_script('--yes').returncode)
        setup = self.payload.read_text()
        start = setup.index('    case "$ID" in\n        steamos) ;;')
        end = setup.index('\nfi\n', start)
        applications = self.directory / 'apps'
        applications.mkdir()
        snippet = setup[start:end].replace('/usr/local/share/applications', str(applications))
        command = 'packages() { printf "%s\\n" "$@"; }\n' + snippet
        for gui, existing, expected in (
                ('apps', (), {'pavucontrol'}),
                ('xfce', (), {'pavucontrol', 'xfce4-pulseaudio-plugin'}),
                ('keep', ('xfce', 'plasma-wayland'), {'pavucontrol', 'xfce4-pulseaudio-plugin', 'plasma-pa'})):
            for mode in existing:
                (applications / f'magicdesk-{mode}.desktop').touch()
            # EVENT_WAIT: dependency selection exits without starting a package manager.
            result = subprocess.run(['sh', '-eu', '-c', command],
                                    env=dict(self.environment, gui=gui, family='apt', ID='debian'),
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(expected, set(result.stdout.splitlines()))

    def test_gui_pipewire_clients_do_not_request_unavailable_realtime_services(self):
        result = self.run_script('--yes', '--gui', 'plasma')
        self.assertEqual(0, result.returncode, result.stderr)
        setup = self.payload.read_text()
        start = setup.index('    for config in client.conf client-rt.conf; do\n')
        end = setup.index('    done\n', start) + len('    done\n')
        directory = self.directory / 'pipewire'
        snippet = setup[start:end].replace('/etc/pipewire', str(directory))
        for config in ('client.conf', 'client-rt.conf'):
            folder = directory / (config + '.d')
            folder.mkdir(parents=True)
            (folder / '90-magicdesk-scheduling.conf').write_text('module.rt.args = {}\n')
            (folder / 'user.conf').write_text('retained')
        # EVENT_WAIT: owned configuration cleanup; timeout fails a stuck recipe.
        written = subprocess.run(['sh', '-eu', '-c', snippet], capture_output=True,
                                 text=True, timeout=5)
        self.assertEqual(0, written.returncode, written.stderr)
        for config in ('client.conf', 'client-rt.conf'):
            folder = directory / (config + '.d')
            self.assertFalse((folder / '90-magicdesk-scheduling.conf').exists())
            self.assertEqual('retained', (folder / 'user.conf').read_text())
        self.assertIn('export DISABLE_RTKIT=1', setup)
        self.assertLess(setup.index('if [ "$gui_services" = yes ]; then'), start)
        self.assertNotIn('rlimits.enabled = false', setup)
        self.assertNotIn('rt.time.hard =', setup)

    def test_application_paths_follow_guest_layout_and_keep_explicit_values(self):
        result = self.run_script('--yes', '--gui', 'plasma')
        self.assertEqual(0, result.returncode, result.stderr)
        setup = self.payload.read_text()
        profile = setup.split("<<'APPLICATIONS'\n", 1)[1].split('\nAPPLICATIONS\n', 1)[0]
        root = self.directory / 'application-paths'
        profile = profile.replace('/usr/lib', str(root / 'usr/lib'))
        command = profile + '\nprintf "%s" "${VLC_PLUGIN_PATH-unset}"'
        environment = dict(self.environment)
        environment.pop('VLC_PLUGIN_PATH', None)
        def run():
            # EVENT_WAIT: profile process exit; timeout fails a stuck recipe.
            value = subprocess.run(['sh', '-eu', '-c', command], env=environment,
                                   capture_output=True, text=True, timeout=5)
            self.assertEqual(0, value.returncode, value.stderr)
            return value.stdout
        self.assertEqual('unset', run())
        multiarch = root / 'usr/lib/aarch64-linux-gnu/vlc/plugins'
        multiarch.mkdir(parents=True)
        self.assertEqual(str(multiarch), run())
        native = root / 'usr/lib/vlc/plugins'
        native.mkdir(parents=True)
        self.assertEqual(str(native), run())
        for value in ('/custom/plugins', ''):
            environment['VLC_PLUGIN_PATH'] = value
            self.assertEqual(value, run())
        self.assertIn('. /etc/profile.d/magicdesk-applications.sh', setup)

    def test_steamos_uses_pinned_helper_and_local_oci_with_separate_library(self):
        result = self.run_script('--yes', '--distro', 'steamos', '--downloads', str(self.directory / 'downloads'))
        self.assertEqual(0, result.returncode, result.stderr)
        calls = self.calls()
        downloads = [c for c in calls if c[0] == 'download']
        self.assertEqual(4, len(downloads))
        self.assertTrue(all('--sha256' in c for c in downloads))
        installs = [c for c in calls if c[0] == 'install']
        self.assertIn('python@sha256:', installs[0][1])
        self.assertEqual(['--name', 'unpack', '--dns', 'system'], installs[0][2:])
        self.assertEqual(['--oci', '--name', 'steamos', '--dns', 'system'], installs[1][2:])
        reader = Path(str(self.payload) + '.reader').read_text()
        self.assertIn("'User': 'steamos'", reader)
        self.assertIn("parts['rootfs-A']", reader)
        setup = self.payload.read_text()
        self.assertIn("Updating SteamOS packages from the image repositories", setup)
        self.assertIn('refresh_packages\n        dbus-uuidgen --ensure', setup)
        self.assertIn('pacman -Syu --noconfirm </dev/null', setup)
        setup_index = next(i for i, c in enumerate(calls) if '-s' in c)
        steam_index = next(i for i, c in enumerate(calls) if any('steam.tar.zst' in a for a in c))
        self.assertLess(setup_index, steam_index)
        self.assertIn(['remove', 'unpack'], calls)
        self.assertEqual(['prune'], calls[-1])
        self.assertFalse(list(self.directory.glob('magicdesk-import-*')))

    def steam_game_fixture(self):
        helper = self.directory / 'steam-game.py'
        helper.write_text(self.run_script('--print-steam-game').stdout)
        tool = self.directory / 'FEX tool'
        tool.mkdir()
        manifest = {'emulator_v0': {
            'argv': './usr/bin/FEX', 'container_argv': ['./usr/bin/FEX', '--option'],
            'main_argv': './FEXCompatTool', 'server_argv': './usr/bin/FEXServerManager',
            'environment': {'FEX_PORTABLE': '1'}, 'container_environment': {'FEX_ROOTFS': ''},
            'required_architectures': ['aarch64-linux-gnu'], 'required_libraries': ['libc.so.6'],
        }}
        source = tool / 'emulator.json'
        source.write_text(json.dumps(manifest))
        capture = tool / 'capture.py'
        capture.write_text('import json, os, sys\nprint(json.dumps({"argv": sys.argv[1:], '
                           '"manifest": os.environ.get("PRESSURE_VESSEL_EMULATOR")}))\n')
        environment = dict(self.environment, XDG_CACHE_HOME=str(self.directory / 'cache'),
                           STEAM_COMPAT_TOOL_PATHS=str(tool))
        environment.pop('PRESSURE_VESSEL_EMULATOR', None)
        return helper, source, capture, environment

    def test_steam_game_derives_manifest_without_modifying_valve_or_arguments(self):
        helper, source, capture, environment = self.steam_game_fixture()
        original = source.read_bytes()
        command = [sys.executable, str(helper), sys.executable, str(capture), 'a b', '--test']
        # EVENT_WAIT: launcher replaces itself with the capture process; timeout fails the test.
        result = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr)
        captured = json.loads(result.stdout)
        self.assertEqual(['a b', '--test'], captured['argv'])
        target = Path(captured['manifest'])
        wrapped = json.loads(target.read_text())['emulator_v0']
        self.assertEqual([str(source.parent / 'usr/bin/FEX')], wrapped['argv'])
        self.assertEqual(['/usr/bin/sh', '-c'], wrapped['main_argv'][:2])
        self.assertEqual(str(source.parent / 'FEXCompatTool'), wrapped['main_argv'][-1])
        self.assertEqual('--option', wrapped['container_argv'][-1])
        self.assertEqual(['libc.so.6', 'libreadline.so.8'], wrapped['required_libraries'])
        self.assertEqual(original, source.read_bytes())
        repeated = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=5)
        self.assertEqual(str(target), json.loads(repeated.stdout)['manifest'])
        updated = json.loads(original)
        updated['emulator_v0']['main_argv'] = './NewCompatTool'
        source.write_text(json.dumps(updated))
        changed = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=5)
        self.assertNotEqual(str(target), json.loads(changed.stdout)['manifest'])

    def test_steam_game_respects_custom_emulator_and_native_commands(self):
        helper, source, capture, environment = self.steam_game_fixture()
        command = [sys.executable, str(helper), sys.executable, str(capture)]
        environment['PRESSURE_VESSEL_EMULATOR'] = '/custom/emulator.json'
        result = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=5)
        self.assertEqual('/custom/emulator.json', json.loads(result.stdout)['manifest'])
        environment.pop('PRESSURE_VESSEL_EMULATOR')
        source.unlink()
        result = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=5)
        self.assertIsNone(json.loads(result.stdout)['manifest'])

    def test_steam_game_finds_selected_tool_in_arguments(self):
        helper, source, capture, environment = self.steam_game_fixture()
        environment.pop('STEAM_COMPAT_TOOL_PATHS')
        result = subprocess.run([sys.executable, str(helper), sys.executable, str(capture)],
                                env=environment, text=True, capture_output=True, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr)
        target = Path(json.loads(result.stdout)['manifest'])
        wrapped = json.loads(target.read_text())['emulator_v0']
        self.assertEqual(str(source.parent / 'FEXCompatTool'), wrapped['main_argv'][-1])

    def test_steam_container_environment_is_scoped_and_preserves_search_paths(self):
        helper, source, capture, environment = self.steam_game_fixture()
        result = subprocess.run([sys.executable, str(helper), sys.executable, str(capture)],
                                env=environment, text=True, capture_output=True, timeout=5)
        target = Path(json.loads(result.stdout)['manifest'])
        wrapper = json.loads(target.read_text())['emulator_v0']['main_argv'][2]
        capture.write_text('import json, os, sys\nprint(json.dumps([os.environ.get(k) for k in sys.argv[1:]]))\n')
        command = ['sh', '-c', wrapper, 'container', sys.executable, str(capture),
                   'FEX_ROOTFS', 'LD_LIBRARY_PATH', 'LIBGL_DRIVERS_PATH']
        for root, expected in [('', '/'), ('/selected', '/selected'), (None, None)]:
            env = dict(environment, MAGICDESK_MESA_PREFIX='/private mesa',
                       LD_LIBRARY_PATH='/runtime/lib', LIBGL_DRIVERS_PATH='/runtime/dri')
            env.pop('FEX_ROOTFS', None)
            if root is not None:
                env['FEX_ROOTFS'] = root
            result = subprocess.run(command, env=env, text=True, capture_output=True, timeout=5)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual([expected, '/private mesa/lib:/runtime/lib',
                              '/private mesa/lib/dri:/runtime/dri'], json.loads(result.stdout))
        env = dict(environment, FEX_ROOTFS='', LD_LIBRARY_PATH='/runtime/lib')
        env.pop('MAGICDESK_MESA_PREFIX', None)
        env.pop('LIBGL_DRIVERS_PATH', None)
        result = subprocess.run(command, env=env, text=True, capture_output=True, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(['/', '/runtime/lib', None], json.loads(result.stdout))

    def test_steamos_rejects_package_recipes_before_download(self):
        for option in (('--gui', 'apps'), ('--fonts', 'cjk'),
                       ('--image', 'arbitrary:latest'), ('--package', 'firefox')):
            with self.subTest(option=option):
                result = self.run_script('--yes', '--distro', 'steamos', *option)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual([], self.calls())

    def test_recovery_failure_retains_work_and_never_imports_partial_output(self):
        result = self.run_script('--yes', '--distro', 'steamos', '--downloads', str(self.directory / 'downloads'),
                                 TEST_FAIL='converter')
        self.assertEqual(23, result.returncode)
        self.assertIn('retained for inspection', result.stderr)
        self.assertEqual(1, len([c for c in self.calls() if c[0] == 'install']))
        self.assertNotIn(['prune'], self.calls())

    def test_setup_marks_only_package_processes_as_unbooted(self):
        result = self.run_script('--yes', '--resume', '--name', 'steam',
                                 '--gui', 'plasma', '--gpu', 'software', TEST_DISTRO='steamos')
        self.assertEqual(0, result.returncode, result.stderr)
        executions = [call for call in self.calls() if call[0] == 'exec']
        self.assertTrue(any('-s' in call for call in executions))
        self.assertTrue(any('-s' not in call for call in executions))
        for call in executions:
            package_setup = '-s' in call and call[-3] != 'identify'
            self.assertEqual(package_setup, 'SYSTEMD_IN_CHROOT=1' in call)
        for export in ('--print-system-setup', '--print-graphics-setup',
                       '--print-desktop-session', '--print-audio-session'):
            self.assertNotIn('SYSTEMD_IN_CHROOT', self.run_script(export).stdout)
        setup = self.run_script('--print-system-setup').stdout
        self.assertIn('install -d -o root -g root -m 1777 /tmp/.X11-unix /tmp/.ICE-unix', setup)

    def test_steamos_resume_does_not_download_or_convert(self):
        result = self.run_script('--yes', '--resume', '--name', 'steam', TEST_DISTRO='steamos')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(all(c[0] not in ('install', 'download', 'prune') for c in self.calls()))

    def test_steamos_desktop_bootstrap_supplies_sdk_links_and_preserves_existing_paths(self):
        result = self.run_script('--yes', '--resume', '--name', 'steam', TEST_DISTRO='steamos')
        self.assertEqual(0, result.returncode, result.stderr)
        command = next(c[-1] for c in self.calls() if any('steam.tar.zst' in a for a in c))
        command = command.replace('[ "$(id -un)" = steamos ]', ':')
        home = self.directory / 'steam-home'
        client = home / '.local/share/Steam'
        client.mkdir(parents=True)
        config = home / '.steam'
        config.mkdir()
        (config / 'sdk32').symlink_to('custom-missing-sdk')
        (config / 'sdk64').write_text('user-owned')
        for _ in range(2):
            # EVENT_WAIT: bootstrap exit; timeout fails a stuck client setup.
            setup = subprocess.run(['sh', '-c', command],
                                   env=dict(self.environment, HOME=str(home)),
                                   capture_output=True, text=True, timeout=5)
            self.assertEqual(0, setup.returncode, setup.stderr)
        self.assertEqual(client, (config / 'root').resolve())
        for link, target in (('sdkarm64', 'linuxarm64'), ('binarm64', 'steamrtarm64'),
                             ('bin32', 'ubuntu12_32'), ('bin64', 'ubuntu12_64')):
            self.assertEqual(client / target, (config / link).resolve())
        self.assertEqual('custom-missing-sdk', os.readlink(config / 'sdk32'))
        self.assertEqual('user-owned', (config / 'sdk64').read_text())

    def test_steamos_plasma_uses_matching_kwin_and_shared_gpu_recipe(self):
        result = self.run_script('--yes', '--resume', '--name', 'steam', '--gui', 'plasma',
                                 '--gpu', 'auto', TEST_DISTRO='steamos')
        self.assertEqual(0, result.returncode, result.stderr)
        kwin = Path(str(self.payload) + '.kwin').read_text()
        self.assertIn('version=6.2.5', kwin)
        self.assertIn('5cc450a6e41105c8c49929b72550b331237f96aafb294690f4707bdc5f776848', kwin)
        self.assertIn('m_presentationBuffer = m_backend->backend()->importBuffer', kwin)
        self.assertNotIn('bool WaylandCompositor::createRenderer()', kwin)
        self.assertIn('KGSL is unavailable', Path(str(self.payload) + '.gpu').read_text())
        self.assertIn('Plasma Desktop (wayland)', result.stdout)
        self.assertNotIn('Individual apps:', result.stdout)
        self.assertEqual(0, subprocess.run(['sh', '-n'], input=kwin, text=True).returncode)

    def test_steamos_defaults_to_plasma_and_automatic_gpu(self):
        result = self.run_script('--yes', '--distro', 'steamos', '--downloads', str(self.directory / 'downloads'))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('GUI=plasma | graphics=auto', result.stdout)
        self.assertTrue(Path(str(self.payload) + '.kwin').is_file())
        self.assertTrue(Path(str(self.payload) + '.gpu').is_file())

    def test_kwin_patch_versions_share_fence_contract(self):
        for version in ('6.2.5', '6.3.6'):
            result = self.run_script('--print-kwin-patch', version, TEST_UID='10001')
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn('DMA_BUF_IOCTL_EXPORT_SYNC_FILE', result.stdout)
            self.assertIn('DMA_BUF_IOCTL_IMPORT_SYNC_FILE', result.stdout)
            self.assertIn('QCoreApplication::exit(1)', result.stdout)
            self.assertEqual([], self.calls())
        self.assertNotEqual(0, self.run_script('--print-kwin-patch', '6.4.0').returncode)

    def test_steamos_update_failure_retains_environment_before_client_setup(self):
        result = self.run_script('--yes', '--resume', '--name', 'steam',
                                 TEST_DISTRO='steamos', TEST_FAIL='setup')
        self.assertEqual(23, result.returncode)
        self.assertIn('Environment retained', result.stderr)
        self.assertNotIn('Linux is ready', result.stdout)
        self.assertTrue(all(not any('steam.tar.zst' in a for a in c) for c in self.calls()))

    def test_steamos_package_failure_releases_already_imported_conversion(self):
        result = self.run_script('--yes', '--distro', 'steamos',
                                 '--downloads', str(self.directory / 'downloads'), TEST_FAIL='setup')
        self.assertEqual(23, result.returncode)
        self.assertIn('Environment retained', result.stderr)
        self.assertIn(['remove', 'unpack'], self.calls())
        self.assertEqual(['prune'], self.calls()[-1])
        self.assertFalse(list(self.directory.glob('magicdesk-import-*')))

    def test_steamos_existing_name_is_rejected_before_fetching(self):
        result = self.run_script('--yes', '--distro', 'steamos', TEST_ENVIRONMENTS='steamos\tsource\t/store')
        self.assertNotEqual(0, result.returncode)
        self.assertIn('already exists', result.stderr)
        self.assertEqual([['--probe'], ['list']], self.calls())

    def test_steamos_work_cannot_overlap_read_only_cache(self):
        result = self.run_script('--yes', '--distro', 'steamos', '--downloads', str(self.directory),
                                 TMPDIR=str(self.directory / 'tmp'))
        self.assertNotEqual(0, result.returncode)
        self.assertIn('outside the read-only download cache', result.stderr)
        self.assertTrue(all(c[0] not in ('install', 'download') for c in self.calls()))

    def test_recovery_dns_failure_does_not_fetch_recovery_archive(self):
        result = self.run_script('--yes', '--distro', 'steamos', '--downloads', str(self.directory / 'downloads'),
                                 TEST_FAIL='install')
        self.assertEqual(23, result.returncode)
        self.assertTrue(all(c[0] != 'download' for c in self.calls()))

    def test_app_launch_hints_match_selected_protocol(self):
        for protocol in ("x11", "wayland", "both"):
            with self.subTest(protocol=protocol):
                result = self.run_script("--yes", "--name", "work", "--protocol", protocol)
                self.assertEqual(0, result.returncode, result.stderr)
                hints = result.stdout.split("Next steps:\n", 1)[1]
                self.assertIn("open Apps (Start)", hints)
                self.assertIn("Refresh beside the search field", hints)
                for backend in ("x11", "wayland"):
                    for title in ("Mousepad", "Thunar", "Xfce Terminal"):
                        self.assertEqual(protocol in (backend, "both"), f"{title} ({backend})" in hints)
                self.assertIn("not a whole Linux desktop", hints)
                self.assertNotIn("Whole desktop:", hints)
                self.assertIn("Shroot environments > work > New session", hints)
                self.assertIn("Console: shroot login work\n", hints)

    def test_desktop_launch_hints_match_generated_entry_not_app_protocol(self):
        profiles = (("xfce", "debian", "wayland", "Xfce Desktop"),
                    ("weston", "debian", "x11", "Weston Desktop"),
                    ("gnome", "fedora", "x11", "GNOME Shell (development kit)"))
        for gui, distro, protocol, title in profiles:
            with self.subTest(gui=gui):
                result = self.run_script("--yes", "--distro", distro, "--gui", gui, "--protocol", protocol)
                self.assertEqual(0, result.returncode, result.stderr)
                hints = result.stdout.split("Next steps:\n", 1)[1]
                self.assertIn(f"title='{title}'", self.payload.read_text())
                self.assertIn(title, hints)
                for _, _, _, other_title in profiles:
                    if other_title != title:
                        self.assertNotIn(other_title, hints)
                if gui == "gnome":
                    self.assertIn("requires a Linux system bus", hints)

    def test_console_only_hints_do_not_offer_uninstalled_gui(self):
        result = self.run_script("--yes", "--name", "tools", "--gui", "none")
        self.assertEqual(0, result.returncode, result.stderr)
        hints = result.stdout.split("Next steps:\n", 1)[1]
        self.assertIn("No GUI was installed by this run", hints)
        self.assertNotIn("open Apps", hints)
        self.assertNotIn("Individual apps:", hints)
        self.assertNotIn("Whole desktop:", hints)
        self.assertIn("Console: shroot login tools\n", hints)

    def test_plasma_recipe_is_explicit_pinned_and_separate_from_mesa(self):
        result = self.run_script("--yes", "--gui", "plasma", "--gpu", "turnip", "--jobs", "4")
        self.assertEqual(0, result.returncode, result.stderr)
        kwin = Path(str(self.payload) + ".kwin").read_text()
        gpu = Path(str(self.payload) + ".gpu").read_text()
        self.assertIn("version=6.3.6", kwin)
        self.assertIn("27f2205f06d58f1d1f480d2a94ae24022c2f95b9c1fdc5a549f8e143713fce12", kwin)
        self.assertIn('patch --batch --forward --fuzz=0', kwin)
        self.assertIn('mv "$work/stage$prefix" "$prefix"', kwin)
        self.assertIn('mv "$candidate" /etc/magicdesk/plasma-kwin.sh', kwin)
        self.assertIn('-DCMAKE_AUTOGEN_PARALLEL="$jobs"', kwin)
        self.assertIn('[ -n "${MAGICDESK_MESA_PREFIX:-}" ] || exit 0', kwin)
        self.assertNotIn("version=6.3.6", gpu)
        self.assertIn('export KWIN_COMPOSE=Q QT_QUICK_BACKEND=software', self.payload.read_text())
        plasma = self.run_script('--print-desktop-session').stdout
        self.assertLess(plasma.index('mkdir -p -m 1777 /tmp/.X11-unix'),
                        plasma.index('set -- startplasma-wayland'))
        self.assertIn('Plasma Desktop (wayland)', result.stdout)
        self.assertEqual("4", self.calls()[-1][-2])
        self.assertEqual(0, subprocess.run(["sh", "-n"], input=kwin, text=True).returncode)

    def test_plasma_rejects_unsupported_distributions_before_mutation(self):
        for distro in ("ubuntu", "alpine", "fedora", "arch"):
            result = self.run_script("--yes", "--distro", distro, "--gui", "plasma")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("requires Debian 13", result.stderr)
            self.assertEqual([], self.calls())

    def test_kwin_recipe_identity_does_not_depend_on_build_parallelism(self):
        fingerprints = []
        for jobs in ("1", "4"):
            result = self.run_script("--yes", "--name", "plasma", "--resume",
                                     "--gui", "plasma", "--gpu", "turnip", "--jobs", jobs)
            self.assertEqual(0, result.returncode, result.stderr)
            fingerprints.append(self.calls()[-1][-1])
            self.assertEqual(jobs, self.calls()[-1][-2])
        self.assertRegex(fingerprints[0], r"^[0-9a-f]{64}$")
        self.assertEqual(*fingerprints)

    def test_kwin_build_failure_preserves_environment_and_reports_resume(self):
        result = self.run_script("--yes", "--name", "plasma", "--resume", "--gui", "plasma",
                                 "--gpu", "turnip", TEST_FAIL="kwin")
        self.assertEqual(23, result.returncode, result.stderr)
        self.assertIn("preparing the nested Plasma compositor", result.stderr)
        self.assertIn("--name plasma --resume", result.stderr)
        self.assertIn("GUI=plasma GPU=turnip", result.stderr)
        self.assertNotIn("Linux is ready", result.stdout)
        self.assertNotIn("install", [args[0] for args in self.calls()])

    def test_kwin_patch_export_is_read_only_and_contains_buffer_sync(self):
        result = self.run_script("--print-kwin-patch", TEST_UID="10001")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([], self.calls())
        self.assertIn('deviceFeedback ? 4 : 3', result.stdout)
        self.assertIn('DMA_HEAP_IOCTL_ALLOC', result.stdout)
        self.assertIn('DMA_BUF_IOCTL_EXPORT_SYNC_FILE', result.stdout)
        self.assertIn('DMA_BUF_IOCTL_IMPORT_SYNC_FILE', result.stdout)
        self.assertIn('m_dmaBufReads', result.stdout)
        self.assertIn('EglSwapchain::create', result.stdout)
        self.assertIn('device && device->supportsSyncObjTimelines()', result.stdout)
        self.assertIn('backend->graphicsBufferAllocator()', result.stdout)
        self.assertIn('m_eglDisplay->acquireDmaBuf(buffer, true)', result.stdout)
        self.assertIn('m_eglDisplay->releaseDmaBuf(m_current->buffer', result.stdout)
        self.assertIn('if (!compositor->createRenderer())', result.stdout)
        self.assertIn('QCoreApplication::exit(1)', result.stdout)
        self.assertNotIn('glFinish(', result.stdout)

    def test_resume_validates_without_reinstalling(self):
        result = self.run_script("--yes", "--name", "existing", "--resume", "--libc", "keep")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(["exec", "--probe", "exec", "exec"], [args[0] for args in self.calls()])
        self.assertEqual(["sh", "debian", "13"], self.calls()[2][-3:])
        self.assertEqual(["keep", "both", "keep", "keep", "", "keep", "keep", ""], self.calls()[-1][-8:])
        hints = result.stdout.split("Next steps:\n", 1)[1]
        self.assertIn("Existing GUI entries were preserved", hints)
        self.assertNotIn("Individual apps:", hints)
        self.assertNotIn("Whole desktop:", hints)
        self.assertIn("Console: shroot login existing\n", hints)

    def test_distribution_profiles_share_setup_and_selected_image(self):
        images = {"fedora": "registry.fedoraproject.org/fedora:44", "openkylin": "openkylin/openkylin:latest",
                  "deepin": "linuxdeepin/deepin:crimson-arm64"}
        for distro, source in images.items():
            for gui in ("none", "apps", "xfce", "weston"):
                with self.subTest(distro=distro, gui=gui):
                    self.log.unlink(missing_ok=True)
                    result = self.run_script("--yes", "--distro", distro, "--gui", gui)
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertEqual(["install", source, "--name", distro, "--dns", "system"], self.calls()[1])
                    self.assertEqual(gui, self.system_setup_call()[-8])
                    self.assertEqual(0, subprocess.run(["sh", "-n", str(self.payload)]).returncode)

    def test_official_rootfs_sources_are_verified_and_share_setup(self):
        profiles = ((distro, gui)
                    for distro in ('debian', 'ubuntu', 'alpine', 'arch', 'opensuse', 'manjaro', 'void', 'armtix')
                    for gui in ('none', 'apps', 'xfce', 'weston'))
        for distro, gui in profiles:
            with self.subTest(distro=distro, gui=gui):
                self.log.unlink(missing_ok=True)
                result = self.run_script('--yes', '--distro', distro, '--gui', gui,
                                         '--downloads', str(self.directory / 'downloads'))
                self.assertEqual(0, result.returncode, result.stderr)
                calls = self.calls()
                downloads = [c for c in calls if c[0] == 'download']
                self.assertEqual(1, len(downloads))
                self.assertTrue(downloads[0][1].startswith('https://'))
                self.assertEqual('--sha256', downloads[0][-2])
                self.assertRegex(downloads[0][-1], r'^[0-9a-f]{64}$')
                install = next(c for c in calls if '--rootfs' in c)
                self.assertEqual(['--rootfs', '--name', distro, '--dns', 'system'], install[2:])
                self.assertEqual(gui, next(c for c in calls if '-s' in c)[-8])
                self.assertEqual(0, subprocess.run(['sh', '-n', str(self.payload)]).returncode)
                if distro in ('debian', 'ubuntu', 'alpine', 'arch', 'manjaro'):
                    self.assertFalse(any(c[0] == 'exec' and c[1] == 'unpack' for c in calls))
                    self.assertEqual(downloads[0][2], install[1])
                else:
                    helper = next(c for c in calls if c[0] == 'install' and '--rootfs' not in c)
                    self.assertTrue(helper[1].startswith('python@sha256:'))
                    converter = next(c for c in calls if c[:2] == ['exec', 'unpack'])
                    self.assertIn('--bind-ro', converter)
                    self.assertIn('/mnt/rootfs.tar.gz', converter)
                    self.assertEqual([['remove', 'unpack'], ['prune']], calls[-2:])
                self.assertFalse(list(self.directory.glob('magicdesk-import-*')))

    def test_rootfs_converter_preserves_uncompressed_tar_bytes(self):
        result = self.run_script('--yes', '--distro', 'void', '--downloads', str(self.directory / 'downloads'))
        self.assertEqual(0, result.returncode, result.stderr)
        converter = next(c for c in self.calls() if c[:2] == ['exec', 'unpack'])
        code = converter[converter.index('-c') + 1]
        original = bytes(range(256)) * 5000
        source, target = self.directory / 'source.xz', self.directory / 'target.gz'
        source.write_bytes(lzma.compress(original))
        # EVENT_WAIT: streaming decompressor exits; timeout fails the conversion test.
        converted = subprocess.run([sys.executable, '-c', code, str(source), str(target)], timeout=10)
        self.assertEqual(0, converted.returncode)
        self.assertEqual(original, gzip.decompress(target.read_bytes()))

    def test_rootfs_download_failure_never_imports_or_starts_converter(self):
        for distro in ('debian', 'arch', 'opensuse'):
            with self.subTest(distro=distro):
                self.log.unlink(missing_ok=True)
                result = self.run_script('--yes', '--distro', distro, TEST_FAIL='download')
                self.assertEqual(23, result.returncode)
                self.assertIn('test download/checksum failure', result.stderr)
                self.assertNotIn('Linux is ready', result.stdout)
                self.assertEqual(['--probe', 'list', 'download'], [c[0] for c in self.calls()])

    def test_rootfs_cache_with_wrong_digest_is_not_imported(self):
        cache = self.directory / 'downloads'
        cache.mkdir()
        (cache / 'rootfs.tar.gz').write_bytes(b'corrupt cached rootfs')
        result = self.run_script('--yes', TEST_FAIL='download')
        self.assertEqual(23, result.returncode)
        self.assertTrue(any(c[0] == 'download' for c in self.calls()))
        self.assertFalse(any(c[0] == 'install' for c in self.calls()))

    def test_rootfs_failure_retains_conversion_but_does_not_import_partial_output(self):
        result = self.run_script('--yes', '--distro', 'void', '--downloads', str(self.directory / 'downloads'),
                                 TEST_FAIL='converter')
        self.assertEqual(23, result.returncode)
        self.assertIn('work retained', result.stderr)
        self.assertFalse(any('--rootfs' in c or c[0] == 'remove' for c in self.calls()))

    def test_rootfs_recipes_accept_explicit_oci_override_without_converter(self):
        for distro in ('debian', 'ubuntu', 'alpine', 'arch', 'opensuse', 'manjaro', 'void', 'armtix'):
            with self.subTest(distro=distro):
                self.log.unlink(missing_ok=True)
                source = 'example/' + distro + ':custom'
                result = self.run_script('--yes', '--distro', distro, '--image', source)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(['install', source, '--name', distro, '--dns', 'system'], self.calls()[1])
                self.assertFalse(any(c[0] == 'download' for c in self.calls()))

    def test_resume_normalizes_distribution_ids_without_downloading(self):
        for os_id, recipe in (('ubuntu', 'ubuntu'), ('alpine', 'alpine'), ('archarm', 'arch'),
                              ('opensuse-tumbleweed', 'opensuse'), ('openkylin', 'openkylin'),
                              ('deepin', 'deepin'), ('manjaro-arm', 'manjaro'), ('void', 'void'), ('artix', 'armtix')):
            with self.subTest(os_id=os_id):
                self.log.unlink(missing_ok=True)
                result = self.run_script('--yes', '--resume', '--name', 'existing', '--distro', recipe,
                                         TEST_DISTRO=os_id)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(recipe, self.calls()[2][-2])
                self.assertFalse(any(c[0] in ('download', 'install') for c in self.calls()))

    def test_settings_are_literal_arguments_and_additional_packages_accumulate(self):
        result = self.run_script("--yes", "--distro", "ubuntu", "--protocol", "wayland", "--locale", "ru_RU.UTF-8",
                                 "--timezone", "Asia/Krasnoyarsk", "--create-user", "developer", "--fonts", "cjk",
                                 "--cache", "clean", "--package", "git", "--package", "gdb")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(["apps", "wayland", "ru_RU.UTF-8", "Asia/Krasnoyarsk", "developer", "cjk", "clean", "git gdb"],
                         self.system_setup_call()[-8:])
        self.assertIn("--user developer", result.stdout)
        self.assertIn("--bind", result.stdout)
        self.assertIn("--magicdesk", result.stdout)

    def test_resume_detects_distribution_but_rejects_mismatch(self):
        result = self.run_script("--yes", "--name", "work", "--resume", TEST_DISTRO="alpine")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(["sh", "alpine", "3.23"], self.calls()[2][-3:])
        self.log.unlink()
        result = self.run_script("--yes", "--name", "work", "--resume", "--distro", "debian", TEST_DISTRO="alpine")
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(1, len(self.calls()))
        self.assertFalse("-s" in self.calls()[0])

    def test_invalid_settings_fail_before_any_environment_call(self):
        for args in [("--resume",), ("--distro", "unknown"), ("--timezone", "../etc"),
                     ("--timezone", "/tmp"), ("--timezone", "UTC;id"), ("--locale", "$(id)"),
                     ("--create-user", "root"), ("--create-user", "--root"), ("--package", "-y"),
                     ("--package", "curl;id"), ("--package", "../pkg"), ("--protocol", "auto"),
                     ("--cache", "all"), ("--arch-sandbox", "disable-filesystem"),
                     ("--gui", "none", "--gpu", "turnip")]:
            with self.subTest(args=args):
                result = self.run_script("--yes", *args)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual([], self.calls())

    def test_arch_uses_package_sandbox_without_opt_out_or_signature_changes(self):
        result = self.run_script("--yes", "--distro", "arch")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('pacman -Syu --noconfirm </dev/null', self.payload.read_text())
        self.assertNotIn("--disable-sandbox", self.payload.read_text())
        self.assertNotIn("SigLevel", self.payload.read_text())
        self.assertNotIn('Glycin/Bubblewrap image loader', result.stdout)

    def test_list_is_read_only_and_names_all_sources(self):
        result = self.run_script("--list", TEST_UID="10001")
        self.assertEqual(0, result.returncode)
        self.assertIn("Arch Linux ARM official rootfs", result.stdout)
        self.assertNotIn("menci/archlinuxarm", result.stdout)
        self.assertIn("registry.fedoraproject.org/fedora:44", result.stdout)
        self.assertEqual([], self.calls())

    def test_dns_is_explicit_and_resume_does_not_replace_it(self):
        result = self.run_script("--yes", "--dns", "192.0.2.1,192.0.2.2")
        self.assertEqual(0, result.returncode, result.stderr)
        install = next(c for c in self.calls() if c[0] == 'install')
        self.assertEqual(["--dns", "192.0.2.1,192.0.2.2"], install[-2:])
        self.assertIn(["dns", "debian", "192.0.2.1,192.0.2.2", "--replace"], self.calls())
        self.log.unlink()
        result = self.run_script("--yes", "--name", "work", "--resume", "--dns", "192.0.2.1")
        self.assertNotEqual(0, result.returncode)
        self.assertEqual([], self.calls())
        result = self.run_script("--yes", "--dns", "preserve")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn("dns", [a[0] for a in self.calls()])

    def test_failure_is_not_reported_as_success_or_followed_by_more_work(self):
        for stage, count in [("--probe", 1), ("download", 3), ("install", 4), ("dns", 5), ("validate", 6), ("setup", 7)]:
            with self.subTest(stage=stage):
                self.log.unlink(missing_ok=True)
                self.payload.unlink(missing_ok=True)
                result = self.run_script("--yes", TEST_FAIL=stage)
                self.assertEqual(23, result.returncode)
                self.assertEqual(count, len(self.calls()))
                self.assertNotIn("Linux is ready", result.stdout)
                self.assertNotIn("Next steps:", result.stdout)
                self.assertIn("Installation stopped", result.stderr)
                if stage == "setup":
                    self.assertIn("--resume", result.stderr)

    def test_failed_resume_never_installs_over_an_existing_environment(self):
        result = self.run_script("--yes", "--resume", "--name", "work", TEST_FAIL="validate")
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(23, result.returncode)
        self.assertFalse(self.payload.exists())
        self.assertNotIn("install", [args[0] for args in self.calls()])

    def test_bad_names_and_options_do_not_mutate_any_environment(self):
        for args in [("--name", "../bad"), ("--name", "bad;id"), ("--name", "-bad"),
                     ("--name", "a" * 65), ("--gui", "gnome"), ("--unknown",), ("--gui",),
                     ("--gpu", "invalid"), ("--jobs", "0"), ("--jobs", "9"), ("--jobs", "1;id"),
                     ("--print-mesa-patch", "--yes")]:
            with self.subTest(args=args):
                self.assertNotEqual(0, self.run_script("--yes", *args).returncode)
                self.assertEqual([], self.calls())

    def test_regular_app_uid_is_rejected_without_elevation(self):
        self.assertNotEqual(0, self.run_script("--yes", TEST_UID="10001").returncode)
        self.assertEqual([], self.calls())

    def test_noninteractive_stdin_requires_explicit_consent(self):
        result = self.run_script()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("--yes", result.stderr)
        self.assertEqual([], self.calls())

    def test_help_needs_no_privileged_executor(self):
        result = self.run_script("--help", TEST_UID="10001")
        self.assertEqual(0, result.returncode)
        self.assertIn("software rendering", result.stdout)
        self.assertEqual([], self.calls())

    def test_patch_export_needs_no_executor_and_includes_egl_and_kgsl_capabilities(self):
        result = self.run_script("--print-mesa-patch", TEST_UID="10001")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("disp->Options.ForceSoftware || disp->Options.Zink", result.stdout)
        self.assertIn("+   priv->driver = psc->kopper ? GLX_DRIVER_ZINK_YES : GLX_DRIVER_SW;", result.stdout)
        self.assertIn("+   if (psc->kopper)", result.stdout)
        self.assertIn("+   if (!psc->kopper)", result.stdout)
        self.assertIn('XQueryExtension(priv->dpy, "DRI3"', result.stdout)
        self.assertIn("zink_present_readback(screen, pctx, pres, level, layer,", result.stdout)
        self.assertIn("pipe_texture_map(pipe, pres, level, layer, PIPE_MAP_READ,", result.stdout)
        self.assertIn("displaytarget_destroy(screen->winsys, res->sw_dt)", result.stdout)
        self.assertIn("IOCTL_KGSL_READ_CALIBRATED_TIMESTAMPS", result.stdout)
        self.assertIn("dev->local_fd, &timestamp) == 0", result.stdout)
        self.assertIn("kgsl_read_gpu_timestamp(dev->fd, ts)", result.stdout)
        for extension in ("KHR_calibrated_timestamps", "EXT_calibrated_timestamps"):
            self.assertIn(f"+      .{extension} = has_calibrated_timestamps,", result.stdout)
        self.assertEqual([], self.calls())

    def test_gpu_recipe_is_fingerprinted_and_independent_of_parallelism(self):
        import hashlib
        for gpu, jobs in [("turnip", "2"), ("turnip", "4"), ("software", "2")]:
            with self.subTest(gpu=gpu, jobs=jobs):
                self.log.unlink(missing_ok=True)
                result = self.run_script("--yes", "--name", "debian", "--resume", "--gpu", gpu, "--jobs", jobs)
                self.assertEqual(0, result.returncode, result.stderr)
                payload = Path(str(self.payload) + ".gpu")
                digest = hashlib.sha256(payload.read_bytes()).hexdigest()
                stages = [c for c in self.calls() if '-s' in c and c[-3] == gpu]
                self.assertEqual(2, len(stages))
                for call in stages:
                    self.assertEqual([gpu, jobs, digest], call[-3:])
                self.assertEqual(0, subprocess.run(["sh", "-n", str(payload)]).returncode)
                self.assertIn(self.run_script("--print-mesa-patch").stdout, payload.read_text())
                self.assertIn("--fuzz=0", payload.read_text())
                self.assertLess(payload.read_text().index("vulkaninfo --summary"),
                                payload.read_text().index('mv -f "$candidate" "$profile"'))

    def test_gpu_failure_preserves_environment_and_reports_exact_resume_command(self):
        result = self.run_script("--yes", "--resume", "--name", "gpu-work", "--gpu", "turnip",
                                 "--jobs", "3", TEST_FAIL="graphics")
        self.assertEqual(23, result.returncode, result.stderr)
        self.assertIn("--name gpu-work --resume", result.stderr)
        self.assertIn("GPU=turnip jobs=3", result.stderr)
        self.assertNotIn("Linux is ready", result.stdout)
        self.assertNotIn("install", [args[0] for args in self.calls()])

    def profile_recipe(self):
        result = self.run_script("--yes", "--name", "debian", "--resume", "--gpu", "turnip")
        self.assertEqual(0, result.returncode, result.stderr)
        payload = Path(str(self.payload) + ".gpu").read_text()
        return payload[payload.index("# Remove only our previously exported library directory"):]

    def test_profile_activation_requires_successful_turnip_probe(self):
        recipe = self.profile_recipe()
        profile = self.directory / "graphics.sh"
        probe = self.directory / "vulkaninfo"
        for body, accepted in [("exit 1", False), ("echo driverID = DRIVER_ID_MESA_LLVMPIPE", False),
                               ("echo driverID = DRIVER_ID_MESA_TURNIP", True)]:
            with self.subTest(body=body):
                probe.write_text("#!/bin/sh\n" + body + "\n")
                probe.chmod(0o755)
                profile.write_text("previous profile\n")
                environment = dict(self.environment, gpu="turnip", ID="debian", automatic="no",
                                   prefix="/opt/magicdesk/mesa/test",
                                   candidate=str(profile) + ".new", profile=str(profile), work=str(self.directory))
                result = subprocess.run(["sh", "-eu", "-c", recipe], env=environment,
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(accepted, result.returncode == 0, result.stderr)
                if accepted:
                    self.assertIn("MESA_LOADER_DRIVER_OVERRIDE=zink", profile.read_text())
                    activated = subprocess.run(
                        ["sh", "-eu", "-c", '. "$1"; printf "%s|%s" '
                         '"$MESA_LOADER_DRIVER_OVERRIDE" "${GALLIUM_DRIVER-unset}"',
                         "sh", str(profile)],
                        env=dict(environment, GALLIUM_DRIVER="zink"),
                        capture_output=True, text=True, timeout=5)
                    self.assertEqual(0, activated.returncode, activated.stderr)
                    self.assertEqual("zink|zink", activated.stdout)
                else:
                    self.assertEqual("previous profile\n", profile.read_text())

    def test_software_profile_removes_only_previous_mesa_library_path(self):
        recipe = self.profile_recipe()
        profile = self.directory / "software.sh"
        environment = dict(self.environment, gpu="software", ID="debian",
                           candidate=str(profile) + ".new", profile=str(profile))
        subprocess.run(["sh", "-eu", "-c", recipe], env=environment, check=True,
                       capture_output=True, timeout=5)
        environment.update(MAGICDESK_MESA_PREFIX="/opt/old", LD_LIBRARY_PATH="/custom:/opt/old/lib:/other",
                           VK_DRIVER_FILES="/old/icd.json", MESA_LOADER_DRIVER_OVERRIDE="zink",
                           MESA_VK_WSI_DEBUG="noshm")
        result = subprocess.run(["sh", "-eu", "-c", '. "$1"; . "$1"; printf "%s|%s|%s|%s|%s|%s" '
                                 '"$LD_LIBRARY_PATH" "$LIBGL_ALWAYS_SOFTWARE" "$GALLIUM_DRIVER" '
                                 '"${VK_DRIVER_FILES-unset}" "${MAGICDESK_MESA_PREFIX-unset}" '
                                 '"${MESA_VK_WSI_DEBUG-unset}"', "sh", str(profile)],
                                env=environment, capture_output=True, text=True, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("/custom:/other|1|llvmpipe|unset|unset|unset", result.stdout)

    def test_fex_graphics_defaults_preserve_overrides_and_follow_profile(self):
        recipe = self.profile_recipe()
        config = self.directory / 'fex-thunks.json'
        config.write_text('{"ThunksDB":{"GL":"1","Vulkan":"1"}}')
        recipe = recipe.replace('/opt/magicdesk/fex-thunks.json', str(config))
        probe = self.directory / 'vulkaninfo'
        probe.write_text('#!/bin/sh\necho driverID = DRIVER_ID_MESA_TURNIP\n')
        probe.chmod(0o755)
        profiles = []
        for gpu in ('turnip', 'software'):
            profile = self.directory / (gpu + '.sh')
            env = dict(self.environment, gpu=gpu, ID='debian', automatic='no',
                       prefix='/opt/magicdesk/mesa/test',
                       candidate=str(profile) + '.new', profile=str(profile), work=str(self.directory))
            subprocess.run(['sh', '-eu', '-c', recipe], env=env, capture_output=True,
                           check=True, timeout=5)
            profiles.append(str(profile))
        script = '. "$1"; . "$1"; printf "%s|%s|%s|%s\\n" ' \
                 '"$FEX_THUNKCONFIG" "${FEX_HOSTENV-unset}" "$PRESSURE_VESSEL_FILESYSTEMS_RO" "$FEX_APP_CONFIG"; ' \
                 '. "$2"; printf "%s|%s|%s|%s\\n" ' \
                 '"${FEX_THUNKCONFIG-unset}" "${FEX_HOSTENV-unset}" ' \
                 '"$PRESSURE_VESSEL_FILESYSTEMS_RO" "$FEX_APP_CONFIG"'
        prefix = '/opt/magicdesk/mesa/test'
        for custom in (False, True):
            env = dict(self.environment, FEX_APP_CONFIG='/user/game.json',
                       PRESSURE_VESSEL_FILESYSTEMS_RO='/user/files')
            if custom:
                env.update(FEX_THUNKCONFIG='/user/thunks.json', FEX_HOSTENV='TEST=1')
            result = subprocess.run(['sh', '-eu', '-c', script, 'sh', *profiles],
                                    env=env, capture_output=True, text=True, timeout=5)
            self.assertEqual(0, result.returncode, result.stderr)
            chosen = '/user/thunks.json|TEST=1' if custom else str(config) + '|unset'
            retained = '/user/thunks.json|TEST=1' if custom else 'unset|unset'
            self.assertEqual(chosen + '|' + prefix + ':' + str(config) + ':/user/files|/user/game.json\n' +
                             retained + '|/user/files|/user/game.json\n', result.stdout)

    @unittest.skipUnless(hasattr(os, "openpty"), "PTY required")
    def test_questions_use_saved_script_stdin(self):
        output = self.questions(b"debian\ninteractive\nxfce\nkeep\n\n\nkeep\nkeep\nbasic\nn\ny\n")
        install = next(c for c in self.calls() if c[0] == 'install')
        self.assertEqual(['--rootfs', '--name', 'interactive', '--dns', 'system'], install[2:])
        setup = next(c for c in self.calls() if c[0] == 'exec' and '-s' in c)
        self.assertEqual("xfce", setup[-8])
        self.assertIn('Linux libc: shroot', output)
        self.assertLess(output.index('Linux libc:'), output.index('Additional settings ('))
        self.assertEqual(1, output.count('Linux libc: shroot (build/reuse accelerated libc)/base/keep [shroot]'))
        self.assertIn('Compiler jobs for libc/Mesa/KWin (1-8) [2]', output)
        self.assertTrue(Path(str(self.payload) + '.libc').exists())

    @unittest.skipUnless(hasattr(os, "openpty"), "PTY required")
    def test_advanced_questions_select_real_options_without_command_flags(self):
        output = self.questions(b"ubuntu\ninteractive\napps\nsoftware\nkeep\nru_RU.UTF-8\nAsia/Krasnoyarsk\ncjk\ny\n"
                            b"developer\nwayland\ngit gdb\n192.0.2.1\nclean\ny\n")
        install = next(c for c in self.calls() if c[0] == 'install')
        self.assertEqual(['--rootfs', '--name', 'interactive', '--dns', '192.0.2.1'], install[2:])
        self.assertEqual(["apps", "wayland", "ru_RU.UTF-8", "Asia/Krasnoyarsk", "developer", "cjk", "clean", "git gdb"],
                         self.calls()[-3][-8:])
        self.assertIn("Guest account=developer | extra packages=git gdb", output)
        self.assertFalse(Path(str(self.payload) + '.libc').exists())

    @unittest.skipUnless(hasattr(os, 'openpty'), 'PTY required')
    def test_main_questions_select_base_without_building_libc(self):
        output = self.questions(b'alpine\nwork\nnone\nkeep\nbase\nkeep\nkeep\nkeep\nn\ny\n')
        self.assertIn('Linux libc: base', output)
        self.assertNotIn('Compiler jobs for libc/Mesa/KWin', output)
        self.assertFalse(any(c[:2] == ['image', 'backup'] for c in self.calls()))
        self.assertTrue(any('-s' in c and c[-3] == 'base' for c in self.calls()))

    @unittest.skipUnless(hasattr(os, 'openpty'), 'PTY required')
    def test_steamos_main_jobs_apply_to_libc_mesa_and_kwin(self):
        output = self.questions(b'steamos\n\n\nturnip\n\n4\nkeep\nkeep\nn\ny\n',
                                TEST_DISTRO='steamos')
        self.assertIn('Linux libc: shroot', output)
        self.assertEqual(1, output.count('Compiler jobs for libc/Mesa/KWin (1-8) [2]'))
        self.assertIn('Compiler jobs for libc/Mesa/KWin: 4', output)
        builds = [c for c in self.calls() if '-s' in c and (
            ('--bind' in c and c[-3] == 'shroot') or 'MAGICDESK_BUILD_PHASE=build' in c)]
        self.assertEqual(3, len(builds))
        self.assertTrue(all(c[-2] == '4' for c in builds))

    def questions(self, answers, expected_exit=0, **environment):
        master, slave = os.openpty()
        self.addCleanup(os.close, master)
        process = subprocess.Popen(["sh", str(SCRIPT)], stdin=slave, stdout=slave, stderr=slave,
                                   env=dict(self.environment, **environment))
        os.close(slave)
        def cleanup():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
        self.addCleanup(cleanup)
        os.write(master, answers)
        output = bytearray()
        deadline = time.monotonic() + 15
        with selectors.DefaultSelector() as selector:
            selector.register(master, selectors.EVENT_READ)
            # EVENT_WAIT: PTY output/EOF; timeout detects a question/input deadlock.
            while True:
                self.assertTrue(selector.select(max(0, deadline - time.monotonic())), "Installer PTY stalled")
                try:
                    data = os.read(master, 4096)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not data:
                    break
                output.extend(data)
        self.assertEqual(expected_exit, process.wait(timeout=5), output.decode())
        return output.decode()


if __name__ == "__main__":
    unittest.main()

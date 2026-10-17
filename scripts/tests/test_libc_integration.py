"""Source-only libc integration contracts; no compiler, device or downloads."""
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
LIBC = ROOT / 'native/shroot/libc'
sys.path.insert(0, str(LIBC))
try:
    import integrate_glibc as glibc
    import integrate_musl as musl
    from source_integration import IntegrationError, SourceIntegration
finally:
    sys.path.pop(0)


class SourceIntegrationTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='libc-integration-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write(self, name, text):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        return target

    def snapshot(self):
        return {str(p.relative_to(self.root)): p.read_bytes()
                for p in self.root.rglob('*') if p.is_file()}

    def test_regex_requires_exact_count_before_mutating(self):
        path = self.write('source.c', 'old old\n')
        tree = SourceIntegration(self.root, ['source.c'])
        for text in ('old', 'missing'):
            with self.assertRaises(IntegrationError):
                tree.regex('source.c', text, 'new')
            self.assertEqual(tree.files['source.c'], path.read_text())

    def test_callback_failure_does_not_mutate_source(self):
        self.write('source.c', 'old\n')
        tree = SourceIntegration(self.root, ['source.c'])
        before = self.snapshot()
        def reject(_):
            raise IntegrationError('ambiguous wrapper')
        with self.assertRaises(IntegrationError):
            tree.regex('source.c', 'old', reject)
        self.assertEqual(before, self.snapshot())

    def test_hybrid_publication_and_permissions(self):
        path = self.write('source.c', 'before\nold\nafter\n')
        path.chmod(0o640)
        tree = SourceIntegration(self.root, ['source.c'])
        tree.replace('source.c', 'old', 'prepared')
        tree.add('new.h', '#define ENTRY 1\n')
        diff = self.write('change.patch', '--- a/source.c\n+++ b/source.c\n'
                          '@@ -1,3 +1,3 @@\n before\n-prepared\n+patched\n after\n')
        self.assertEqual(path.read_text(), 'before\nold\nafter\n')
        tree.finish(diff)
        self.assertEqual(path.read_text(), 'before\npatched\nafter\n')
        self.assertEqual(path.stat().st_mode & 0o777, 0o640)
        self.assertEqual((self.root / 'new.h').read_text(), '#define ENTRY 1\n')

    def test_rejected_patch_leaves_regex_and_added_files_unpublished(self):
        self.write('source.c', 'before\nold\nafter\n')
        tree = SourceIntegration(self.root, ['source.c'])
        tree.replace('source.c', 'old', 'prepared')
        tree.add('new.h', 'new\n')
        diff = self.write('bad.patch', '--- a/source.c\n+++ b/source.c\n'
                          '@@ -1,3 +1,3 @@\n wrong context\n-prepared\n+patched\n after\n')
        before = self.snapshot()
        with self.assertRaisesRegex(IntegrationError, 'source tree unchanged'):
            tree.finish(diff)
        self.assertEqual(before, self.snapshot())

    def test_second_patch_failure_does_not_publish_first_patch(self):
        self.write('source.c', 'old\n')
        tree = SourceIntegration(self.root, ['source.c'])
        first = self.write('first.patch', '--- a/source.c\n+++ b/source.c\n@@ -1 +1 @@\n-old\n+new\n')
        second = self.write('second.patch', '--- a/source.c\n+++ b/source.c\n@@ -1 +1 @@\n-missing\n+bad\n')
        before = self.snapshot()
        with self.assertRaises(IntegrationError):
            tree.finish(first, second)
        self.assertEqual(before, self.snapshot())

    def test_missing_patch_tool_is_explicit(self):
        self.write('source.c', 'old\n')
        tree = SourceIntegration(self.root, ['source.c'])
        with patch('source_integration.shutil.which', return_value=None):
            with self.assertRaisesRegex(IntegrationError, 'patch is required'):
                tree.finish(self.root / 'anything.patch')

    def test_patch_cannot_silently_add_an_unmanaged_file(self):
        self.write('source.c', 'old\n')
        tree = SourceIntegration(self.root, ['source.c'])
        diff = self.write('extra.patch', '--- /dev/null\n+++ b/extra.c\n@@ -0,0 +1 @@\n+extra\n')
        before = self.snapshot()
        with self.assertRaisesRegex(IntegrationError, 'outside the integration manifest'):
            tree.finish(diff)
        self.assertEqual(before, self.snapshot())

    def test_existing_integration_is_not_overwritten(self):
        self.write('source.c', 'old\n')
        self.write('new.h', 'already integrated\n')
        tree = SourceIntegration(self.root, ['source.c'])
        with self.assertRaises(IntegrationError):
            tree.add('new.h', 'replacement\n')
        self.assertEqual((self.root / 'new.h').read_text(), 'already integrated\n')

    def test_escaping_source_symlink_is_rejected(self):
        (self.root / 'source.c').symlink_to(LIBC / 'musl_entry.c')
        with self.assertRaises(IntegrationError):
            SourceIntegration(self.root, ['source.c'])

    def musl_tree(self, mutation=lambda text: text):
        wrappers = '#define __SYSCALL_LL_E(x) (x)\n'
        for arity in range(7):
            arguments = ', '.join(['long number'] + [f'long arg{i}' for i in range(arity)])
            wrappers += (f'static\tinline long __syscall{arity} ( {arguments} )\n{{\n'
                         ' asm volatile("svc 0"); return number;\n}\n')
        self.write(musl.ARCH, mutation(wrappers))
        return SourceIntegration(self.root, [musl.ARCH])

    def test_musl_all_arities_with_whitespace_and_renamed_parameters(self):
        tree = self.musl_tree()
        musl.redirect_syscalls(tree)
        result = tree.files[musl.ARCH]
        self.assertEqual(result.count('&& __shroot_try('), 7)
        self.assertEqual(result.count('asm volatile("svc 0")'), 7)
        self.assertIn('__shroot_try(number, 0, 0, 0, 0, 0, 0, &_shroot_result)', result)
        self.assertIn('__shroot_try(number, arg0, arg1, arg2, arg3, arg4, arg5, &_shroot_result)', result)

    def test_musl_duplicate_arity_rejected(self):
        tree = self.musl_tree(lambda text: text.replace('__syscall5', '__syscall6'))
        before = self.snapshot()
        with self.assertRaises(IntegrationError):
            musl.redirect_syscalls(tree)
        self.assertEqual(before, self.snapshot())

    def test_musl_unknown_signature_rejected(self):
        tree = self.musl_tree(lambda text: text.replace('long arg3', 'void *arg3'))
        with self.assertRaises(IntegrationError):
            musl.redirect_syscalls(tree)

    def test_musl_missing_wrapper_rejected(self):
        tree = self.musl_tree(lambda text: text.replace('__syscall2', '__syscall_other'))
        with self.assertRaises(IntegrationError):
            musl.redirect_syscalls(tree)

    def glibc_tree(self, mutation=lambda text: text):
        header = ('#\tdefine DO_CALL(syscall_name, args) \\\n'
                  ' mov x8, SYS_ify (syscall_name); \\\n'
                  ' svc 0\n'
                  '# define INTERNAL_SYSCALL_RAW(name, nr, args...) raw_svc(name)\n'
                  '# undef INTERNAL_SYSCALL\n'
                  '# define UNRELATED svc 0\n')
        self.write(glibc.ARCH + 'sysdep.h', mutation(header))
        self.write(glibc.ARCH + 'syscall.S', 'ENTRY (syscall)\n svc\t0x0\nPSEUDO_END (syscall)\n'
                   'ENTRY (unrelated)\n svc 0\nPSEUDO_END (unrelated)\n')
        return SourceIntegration(self.root, [glibc.ARCH + 'sysdep.h', glibc.ARCH + 'syscall.S'])

    def test_glibc_only_known_wrapper_and_macro(self):
        tree = self.glibc_tree()
        glibc.redirect_syscalls(tree)
        self.assertIn('# define UNRELATED svc 0', tree.files[glibc.ARCH + 'sysdep.h'])
        self.assertIn('SHROOT_KERNEL_SYSCALL_RAW(name, nr, args...) raw_svc(name)',
                      tree.files[glibc.ARCH + 'sysdep.h'])
        self.assertEqual(tree.files[glibc.ARCH + 'sysdep.h'].count('# include <shroot-syscall.h>'), 2)
        self.assertIn('ENTRY (unrelated)\n svc 0', tree.files[glibc.ARCH + 'syscall.S'])
        self.assertEqual(tree.files[glibc.ARCH + 'syscall.S'].count('SHROOT_DO_SYSCALL'), 1)

    def test_glibc_unexpected_syscall_instruction_rejected(self):
        tree = self.glibc_tree(lambda text: text.replace(' svc 0\n', ' svc 1\n'))
        with self.assertRaises(IntegrationError):
            glibc.redirect_syscalls(tree)

    def test_glibc_duplicate_macro_rejected(self):
        tree = self.glibc_tree(lambda text: text + '# define DO_CALL(n, a) \\\n svc 0\n')
        with self.assertRaises(IntegrationError):
            glibc.redirect_syscalls(tree)

    def test_glibc_objectlike_macro_is_not_a_syscall_wrapper(self):
        # A space before '(' changes a C macro's meaning, unlike function syntax.
        tree = self.glibc_tree(lambda text: text.replace('DO_CALL(', 'DO_CALL ('))
        with self.assertRaises(IntegrationError):
            glibc.redirect_syscalls(tree)

    def test_glibc_invalid_private_path_rejected_before_source_access(self):
        for path in ('/usr/lib', '/opt/shroot/libc/../../lib', '/opt/shroot/libc/a"/lib', ''):
            with self.subTest(path=path), self.assertRaises(IntegrationError):
                glibc.integrate(self.root / 'missing', path)

    def test_glibc_build_hooks_do_not_depend_on_neighbouring_symbols_or_tests(self):
        self.write('elf/Makefile', 'rtld-stubbed-symbols = \\\n  old_symbol \\\n  malloc\n')
        self.write(glibc.ARCH + 'Makefile', 'ifeq ($(subdir),misc)\nsysdep_headers += sys/elf.h\nendif\n')
        tree = SourceIntegration(self.root, ['elf/Makefile', glibc.ARCH + 'Makefile'])
        glibc.build_hooks(tree)
        self.assertIn('old_symbol', tree.files['elf/Makefile'])
        self.assertIn('__shroot_syscall_asm', tree.files['elf/Makefile'])
        self.assertIn('sysdep_routines += shroot-entry shroot-entry-asm', tree.files[glibc.ARCH + 'Makefile'])

    def test_legacy_cancellation_is_verified_and_unchanged(self):
        text = ''.join('#define ' + name + '(...) \\\n  ({ int sc_cancel_oldtype = LIBC_CANCEL_ASYNC (); \\\n     LIBC_CANCEL_RESET (sc_cancel_oldtype); })\n'
                       for name in ('SYSCALL_CANCEL', 'INTERNAL_SYSCALL_CANCEL'))
        self.write('sysdeps/unix/sysdep.h', text)
        tree = SourceIntegration(self.root, ['sysdeps/unix/sysdep.h'])
        glibc.legacy_cancellation(tree)
        self.assertEqual(text, tree.files['sysdeps/unix/sysdep.h'])
        tree.files['sysdeps/unix/sysdep.h'] = text.replace('LIBC_CANCEL_RESET', 'changed_reset')
        with self.assertRaises(IntegrationError):
            glibc.legacy_cancellation(tree)

    def test_installer_payload_contains_canonical_patches_and_headers(self):
        generator = runpy.run_path(str(ROOT / 'scripts/embed-libc-integration.py'))
        script = subprocess.check_output(['sh', '-c', generator['payload']() + '\nlibc_integration'])
        output = self.root / 'embedded'
        subprocess.run([sys.executable, '-c', script.decode(), str(output)], check=True)
        expected = [LIBC.parent / 'src/cooperative_entry.h', *(
            p for p in LIBC.iterdir() if p.suffix in ('.py', '.h', '.c', '.S', '.patch'))]
        for source in expected:
            with self.subTest(source=source.name):
                self.assertEqual((output / source.relative_to(LIBC.parent)).read_bytes(), source.read_bytes())

    def test_checked_in_payload_is_current(self):
        subprocess.run([sys.executable, str(ROOT / 'scripts/embed-libc-integration.py'), '--check'], check=True)


if __name__ == '__main__':
    unittest.main()

"""The installer's embedded GL-extension publisher, without a Flatpak install."""
import configparser
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'install_linux.sh'


class FlatpakGLTest(unittest.TestCase):
    def setUp(self):
        source = SCRIPT.read_text().split("cat <<'FLATPAK_GL_PY'\n", 1)[1].split('\nFLATPAK_GL_PY', 1)[0]
        self.helper = types.ModuleType('flatpak_gl')
        exec(compile(source, str(SCRIPT) + ':flatpak_gl_helper', 'exec'), self.helper.__dict__)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.base = self.root / 'flatpak'
        self.prefix = self.root / 'mesa'
        (self.prefix / 'lib').mkdir(parents=True)
        (self.prefix / '.complete').write_text('recipe-one\n')
        for name in ['libvulkan_freedreno.so', 'libEGL_mesa.so.0', 'libgallium.so']:
            (self.prefix / 'lib' / name).write_bytes(b'library')
        for path, library in [('vulkan/icd.d/freedreno_icd.aarch64.json', 'libvulkan_freedreno.so'),
                              ('glvnd/egl_vendor.d/50_mesa.json', 'libEGL_mesa.so.0')]:
            manifest = self.prefix / 'share' / path
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text(json.dumps({'file_format_version': '1.0.0',
                                           'ICD': {'library_path': str(self.prefix / 'lib' / library)}}))
        self.verifier = patch.object(self.helper, 'verify_runtime')
        self.verify = self.verifier.start()
        self.addCleanup(self.verifier.stop)
        self.link = self.base / 'extension' / self.helper.EXTENSION / 'aarch64/25.08'

    def runtime(self, name='org.freedesktop.Platform', commit='commit-one', layout='lib/aarch64-linux-gnu/GL'):
        base = self.base / 'runtime' / name / 'aarch64/25.08'
        deployment = base / commit
        deployment.mkdir(parents=True)
        (deployment / 'files').mkdir()
        (deployment / 'metadata').write_text(
            '[Runtime]\nname=' + name + '\n[Extension org.freedesktop.Platform.GL]\n'
            'versions=25.08;25.08-extra;1.4\nsubdirectories=true\ndirectory=' + layout + '\n')
        (base / 'active').unlink(missing_ok=True)
        (base / 'active').symlink_to(commit)
        return deployment

    def test_no_flatpak_is_noop(self):
        self.helper.prepare(self.base, self.prefix)
        self.assertFalse(self.base.exists())

    def test_system_extension_parents_remain_readable_with_private_umask(self):
        self.runtime()
        before = os.umask(0o077)
        try:
            self.helper.prepare(self.base, self.prefix)
        finally:
            os.umask(before)
        for directory in (self.link, self.link.parent, self.link.parent.parent,
                          self.base / 'extension', self.base / 'overrides'):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o755)

    def test_publish_relocated_library_bundle_without_rebuild(self):
        self.runtime()
        self.helper.prepare(self.base, self.prefix)
        self.assertTrue(self.link.is_dir())
        self.assertFalse(self.link.is_symlink())
        self.verify.assert_called_once()
        icd = json.loads((self.link / 'vulkan/icd.d/magicdesk.json').read_text())
        self.assertEqual(icd['ICD']['library_path'],
                         '/usr/lib/aarch64-linux-gnu/GL/host/lib/libvulkan_freedreno.so')
        self.assertEqual((self.link / 'lib/libgallium.so').read_bytes(), b'library')
        self.assertFalse((self.link.parent / '1.4').exists())
        self.assertFalse((self.link.parent / '25.08-extra').exists())

    def test_unchanged_receipt_does_not_repeat_abi_probe(self):
        self.runtime()
        self.helper.prepare(self.base, self.prefix)
        target = self.link.stat().st_ino
        self.helper.prepare(self.base, self.prefix)
        self.verify.assert_called_once()
        self.assertEqual(self.link.stat().st_ino, target)

    def test_environment_keeps_user_permissions_and_explicit_driver_choice(self):
        self.runtime()
        path = self.base / 'overrides/global'
        path.parent.mkdir()
        path.write_text('[Context]\nfilesystems=~/Documents;\nunset-environment=OTHER;\n'
                        '[Environment]\nVK_DRIVER_FILES=/custom/icd.json\n')
        path.chmod(0o600)
        self.helper.prepare(self.base, self.prefix)
        data = configparser.ConfigParser(interpolation=None)
        data.optionxform = str
        data.read(path)
        self.assertEqual(data['Context']['filesystems'], '~/Documents;')
        self.assertEqual(data['Environment']['VK_DRIVER_FILES'], '/custom/icd.json')
        unset = data['Context']['unset-environment'].split(';')
        self.assertIn('OTHER', unset)
        self.assertIn('__EGL_VENDOR_LIBRARY_FILENAMES', unset)
        self.assertIn('GBM_BACKENDS_PATH', unset)
        self.assertNotIn('VK_DRIVER_FILES', unset)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        before = path.read_bytes()
        self.helper.prepare(self.base, self.prefix)
        self.assertEqual(path.read_bytes(), before)

    def test_failed_admission_does_not_change_environment(self):
        self.runtime()
        self.verify.side_effect = ValueError('incompatible')
        with self.assertRaises(ValueError):
            self.helper.prepare(self.base, self.prefix)
        self.assertFalse((self.base / 'overrides/global').exists())

    def test_admission_loads_gbm_backend_as_well_as_top_level_libraries(self):
        runtime = self.runtime()
        loader = runtime / 'files/lib/ld-linux-aarch64.so.1'
        loader.parent.mkdir()
        loader.touch()
        backend = self.prefix / 'lib/gbm/dri_gbm.so'
        backend.parent.mkdir()
        backend.touch()
        backend.with_name('alias_gbm.so').symlink_to(backend.name)
        self.verifier.stop()
        with patch.object(self.helper.subprocess, 'run') as run:
            run.return_value.returncode = 0
            self.helper.verify_runtime(runtime / 'metadata', self.prefix)
        command = run.call_args.args[0]
        self.assertIn('/mdgl/lib/gbm/dri_gbm.so', command)
        self.assertIn('/mdgl/lib/libgallium.so', command)
        self.assertNotIn('/mdgl/lib/gbm/alias_gbm.so', command)

    def test_update_is_atomic_and_retains_running_sandbox_bundle(self):
        self.runtime()
        self.helper.prepare(self.base, self.prefix)
        before = self.link.stat().st_ino
        (self.prefix / '.complete').write_text('recipe-two\n')
        self.helper.prepare(self.base, self.prefix)
        self.assertNotEqual(self.link.stat().st_ino, before)
        retired = list((self.base / '.magicdesk-gl').glob('retired-*'))
        self.assertEqual(len(retired), 1)
        self.assertEqual(retired[0].stat().st_ino, before)
        self.assertTrue((retired[0] / 'lib/libgallium.so').is_file())

    def test_failed_retirement_after_exchange_never_deletes_old_libraries(self):
        self.runtime()
        self.helper.prepare(self.base, self.prefix)
        old = self.link.stat().st_ino
        (self.prefix / '.complete').write_text('recipe-two\n')
        rename = os.rename

        def fail_retirement(source, target):
            if Path(target).name.startswith('retired-'):
                raise OSError('test retirement failure')
            return rename(source, target)

        with patch.object(self.helper.os, 'rename', side_effect=fail_retirement):
            with self.assertRaisesRegex(ValueError, 'retirement failure'):
                self.helper.prepare(self.base, self.prefix)
        retained = [p for p in (self.base / '.magicdesk-gl').iterdir()
                    if p.is_dir() and p.stat().st_ino == old]
        self.assertEqual(len(retained), 1)
        self.assertEqual((retained[0] / 'lib/libgallium.so').read_bytes(), b'library')

    def test_new_runtime_commit_requires_admission_again(self):
        self.runtime()
        self.helper.prepare(self.base, self.prefix)
        before = self.link.stat().st_ino
        self.runtime(commit='commit-two')
        self.helper.prepare(self.base, self.prefix)
        self.assertEqual(self.verify.call_count, 2)
        self.assertEqual(self.link.stat().st_ino, before)
        self.assertEqual(list((self.base / '.magicdesk-gl').glob('retired-*')), [])

    def test_all_runtimes_sharing_a_branch_must_load_it(self):
        self.runtime()
        self.runtime('org.kde.Platform')
        self.helper.prepare(self.base, self.prefix)
        self.assertEqual(self.verify.call_count, 2)

    def test_abi_failure_retires_old_selection_without_publishing_candidate(self):
        self.runtime()
        self.helper.prepare(self.base, self.prefix)
        old = self.link.stat().st_ino
        self.runtime(commit='incompatible')
        self.verify.side_effect = ValueError('missing GLIBC symbol')
        with self.assertRaisesRegex(ValueError, 'missing GLIBC'):
            self.helper.prepare(self.base, self.prefix)
        self.assertFalse(self.link.exists())
        retired = list((self.base / '.magicdesk-gl').glob('retired-*'))
        self.assertEqual(retired[0].stat().st_ino, old)
        self.assertEqual(list((self.base / '.magicdesk-gl').glob('.prepare-*')), [])

    def test_does_not_replace_foreign_host_extension(self):
        self.runtime()
        self.link.mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, 'independently installed'):
            self.helper.prepare(self.base, self.prefix)
        self.assertTrue(self.link.is_dir())
        self.verify.assert_not_called()

    def test_disable_only_retires_owned_selections(self):
        self.runtime()
        self.helper.prepare(self.base, self.prefix)
        foreign = self.link.parent / '24.08'
        foreign.mkdir()
        self.helper.prepare(self.base, None)
        self.assertFalse(self.link.exists())
        self.assertTrue(foreign.is_dir())

    def test_rejects_path_escape(self):
        self.runtime(layout='lib/../../outside')
        with self.assertRaisesRegex(ValueError, 'Invalid GL'):
            self.helper.prepare(self.base, self.prefix)

    def test_installer_and_desktop_use_the_same_helper(self):
        script = SCRIPT.read_text()
        self.assertIn('exec /usr/local/bin/magicdesk-flatpak-gl "$1"', script)
        self.assertIn('magicdesk-flatpak-gl || echo', script)
        self.assertNotIn('FLATPAK_GL_DRIVERS=host', script)


if __name__ == '__main__':
    unittest.main()

"""Checked source transformations followed by an exact-context unified patch."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


class IntegrationError(RuntimeError):
    pass


class SourceIntegration:
    def __init__(self, source, paths):
        self.source = Path(source).resolve()
        self.original = {}
        self.modes = {}
        for name in paths:
            path = self.source / name
            if path.is_symlink() or not path.resolve().is_relative_to(self.source) or not path.is_file():
                raise IntegrationError(f'{name}: expected a source file within the tree')
            self.original[name] = path.read_text()
            self.modes[name] = path.stat().st_mode & 0o777
        self.files = self.original.copy()

    def replace(self, name, before, after):
        self.regex(name, re.escape(before), lambda _: after)

    def regex(self, name, pattern, replacement, count=1):
        expression = re.compile(pattern, re.MULTILINE)
        actual = len(list(expression.finditer(self.files[name])))
        if actual != count:
            raise IntegrationError(f'{name}: expected {count} integration boundaries, found {actual}')
        self.files[name] = expression.sub(replacement, self.files[name])

    def add(self, name, content):
        path = self.source / name
        if name in self.files or path.exists() or path.is_symlink():
            raise IntegrationError(f'{name}: integration file already exists; use fresh sources')
        if not path.resolve().is_relative_to(self.source):
            raise IntegrationError(f'{name}: integration path escapes the source tree')
        self.files[name] = content
        self.modes[name] = 0o644

    def finish(self, *patches):
        if not shutil.which('patch'):
            raise IntegrationError('GNU patch is required for libc integration')
        # Validate all transformations and the complete patch off-tree.
        with tempfile.TemporaryDirectory(prefix='shroot-libc-') as directory:
            staged = Path(directory)
            for name, content in self.files.items():
                target = staged / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content)
            for patch in patches:
                command = ['patch', '--batch', '--forward', '--fuzz=0',
                           '--no-backup-if-mismatch', '-p1', '-i', str(Path(patch).resolve())]
                for flags in (['--dry-run'], []):
                    result = subprocess.run([*command, *flags], cwd=staged, text=True,
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            env={**os.environ, 'LC_ALL': 'C'})
                    if result.returncode:
                        raise IntegrationError(f'libc patch rejected; source tree unchanged:\n{result.stdout}')
            actual = {p.relative_to(staged).as_posix() for p in staged.rglob('*') if p.is_file()}
            if actual != set(self.files):
                raise IntegrationError('libc patch changed files outside the integration manifest')
            result = {name: (staged / name).read_text() for name in self.files}
        # These are disposable build sources, not the installed libc. An IO
        # failure during publication requires a fresh source extraction.
        for name, content in result.items():
            if self.original.get(name) == content:
                continue
            target = self.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(mode='w', dir=target.parent, delete=False) as output:
                    temporary = Path(output.name)
                    output.write(content)
                temporary.chmod(self.modes[name])
                temporary.replace(target)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)

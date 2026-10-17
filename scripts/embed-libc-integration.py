#!/usr/bin/env python3
"""Regenerate/check the self-contained installer payload from native libc sources."""
import argparse
import base64
import json
import re
from pathlib import Path
import textwrap
import zlib

ROOT = Path(__file__).resolve().parent.parent
START = '# BEGIN GENERATED LIBC INTEGRATION\n'
END = '# END GENERATED LIBC INTEGRATION\n'


def payload():
    base = ROOT / 'native/shroot'
    paths = [base / 'src/cooperative_entry.h', *sorted(
        p for p in (base / 'libc').iterdir() if p.suffix in ('.py', '.c', '.h', '.S', '.patch', '.sh'))]
    sources = {p.relative_to(base).as_posix(): p.read_text() for p in paths}
    encoded = base64.b64encode(zlib.compress(json.dumps(sources, sort_keys=True).encode(), 9)).decode()
    abi = re.search(r'^#define MD_ENTRY_VERSION (\d+)', sources['src/cooperative_entry.h'], re.M)[1]
    builder = (base / 'libc/build.sh').read_text()
    return START + 'libc_entry_abi() { printf "%s\\n" "' + abi + '"; }\n' + \
        "libc_build() {\n    cat <<'LIBC_BUILD'\n" + builder + "LIBC_BUILD\n}\n" + '''libc_integration() {
    cat <<'LIBC_INTEGRATION'
import base64, json, sys, zlib
from pathlib import Path
root = Path(sys.argv[1])
sources = json.loads(zlib.decompress(base64.b64decode(''' + "'''\n" + '\n'.join(textwrap.wrap(encoded, 100)) + "\n'''" + ''')))
for name, content in sources.items():
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
LIBC_INTEGRATION
}
''' + END


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    installer = ROOT / 'scripts/install_linux.sh'
    text = installer.read_text()
    first, last = text.index(START), text.index(END) + len(END)
    updated = text[:first] + payload() + text[last:]
    if args.check:
        if text != updated:
            raise SystemExit('Run python scripts/embed-libc-integration.py')
    else:
        installer.write_text(updated)


if __name__ == '__main__':
    main()

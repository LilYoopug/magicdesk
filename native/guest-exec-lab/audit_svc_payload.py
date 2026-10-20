#!/usr/bin/env python3
"""Reject hidden linker dependencies in the copied machine-entry driver."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def sections(path):
    tool = os.environ.get('LLVM_READELF', 'llvm-readelf')
    document, = json.loads(subprocess.check_output(
        [tool, '--elf-output-style=JSON', '--sections', str(path)], text=True))
    assert document['FileSummary']['Arch'] == 'aarch64'
    return [item['Section'] for item in document['Sections']]


def audit(build):
    objects = [path for path in (build / 'CMakeFiles/trace_svc_patch.dir').rglob('svc_payload.c.o')
               if path.parent.name == 'src']
    assert len(objects) == 1, objects
    obj, = objects
    table = sections(obj)
    payload, = [s for s in table if s['Name']['Name'] == 'md_svc_payload']
    assert 0 < payload['Size'] < 16384
    assert not any(s['Type']['Name'] in ('SHT_REL', 'SHT_RELA') and s['Size']
                   and s['Info'] == payload['Index'] for s in table), 'copied driver has relocations'
    binary = build / 'libmagicdesk_guest_trace_svc_patch.so'
    linked, = [s for s in sections(binary) if s['Name']['Name'] == 'md_svc_payload']
    original = obj.read_bytes()[payload['Offset']:payload['Offset'] + payload['Size']]
    final = binary.read_bytes()[linked['Offset']:linked['Offset'] + linked['Size']]
    assert final == original, 'linker changed the supposedly position-independent driver'
    return dict(size=len(final), sha256=hashlib.sha256(final).hexdigest(), relocations=0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.build)))

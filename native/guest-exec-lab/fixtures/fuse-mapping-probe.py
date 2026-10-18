#!/usr/bin/env python3
"""Compare read and initial private/shared mapping bytes, without modifying a file."""
import argparse
import hashlib
import json
import mmap
import os


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path')
    args = parser.parse_args()
    fd = os.open(args.path, os.O_RDONLY | os.O_CLOEXEC)
    passed = True
    try:
        length = min(os.fstat(fd).st_size, 1024 * 1024)
        if not length:
            parser.error('the probe needs a nonempty regular file')
        reference = os.pread(fd, length, 0)
        if len(reference) != length:
            raise RuntimeError('short reference read')
        for name, flag in (('private', mmap.MAP_PRIVATE), ('shared', mmap.MAP_SHARED)):
            result = {'mapping': name, 'bytes': length, 'passed': False}
            try:
                with mmap.mmap(fd, length, flags=flag, prot=mmap.PROT_READ) as mapping:
                    actual = mapping[:]
                result.update(passed=actual == reference, sha256=hashlib.sha256(actual).hexdigest())
            except OSError as error:
                result.update(errno=error.errno, error=str(error))
            print(json.dumps(result), flush=True)
            passed = passed and result['passed']
    finally:
        os.close(fd)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Check deep-path lookup and mixed namespace IO; report, never assert timing."""
import json
import os
from pathlib import Path
import shutil
import tempfile
import time


def measure(name, operation):
    start = time.monotonic()
    count = operation()
    print(json.dumps({"phase": name, "operations": count,
                      "seconds": time.monotonic() - start}), flush=True)


def main():
    root = Path(tempfile.mkdtemp(prefix="md-path-workload-"))
    try:
        directory = root.joinpath(*["level" for _ in range(16)])
        directory.mkdir(parents=True)
        files = [directory / f"file-{i}" for i in range(32)]
        for path in files:
            path.write_bytes(b"namespace data")
        identities = [path.stat().st_ino for path in files]

        def reads():
            for _ in range(16):
                for path, inode in zip(files, identities):
                    assert path.stat().st_ino == inode
                    with path.open("rb") as stream:
                        assert stream.read() == b"namespace data"
            return 1024

        def existing_writes():
            for _ in range(8):
                for path, inode in zip(files, identities):
                    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
                    try:
                        assert os.fstat(fd).st_ino == inode
                        assert os.pwrite(fd, b"namespace data", 0) == 14
                    finally:
                        os.close(fd)
            return 256

        def mutations():
            for i in range(64):
                path = directory / "created"
                target = directory / "renamed"
                path.write_bytes(str(i).encode())
                path.rename(target)
                assert target.read_bytes() == str(i).encode()
                target.unlink()
                assert files[i % 32].read_bytes() == b"namespace data"
            return 64

        for _ in range(3):
            measure("deep-read", reads)
            measure("existing-writable", existing_writes)
            measure("create-rename-unlink", mutations)
    finally:
        shutil.rmtree(root)


if __name__ == "__main__":
    main()

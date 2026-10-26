#!/usr/bin/env python3
"""Lower MagicDesk's Android floor from API 34 to API 33 (Android 13).

Idempotent: running it twice changes nothing. Only module build.gradle files
that declare minSdk 34 are touched.

kernel-fixes is deliberately left alone. It declares minSdk 36, ships as its
own separate APK, and is not required to run the app.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TARGETS = [
    "app/build.gradle",
    "audio-runtime/build.gradle",
    "hidden-api-stubs/build.gradle",
    "hosted-runtime/build.gradle",
    "launcher-template/build.gradle",
    "terminal-emulator/build.gradle",
    "wayland-runtime/build.gradle",
    "x11-runtime/build.gradle",
]
PATTERN = re.compile(r"(\bminSdk\s*=?\s*)34\b")


def main() -> int:
    changed = 0
    for rel in TARGETS:
        path = ROOT / rel
        if not path.is_file():
            print(f"skip (missing): {rel}")
            continue
        text = path.read_text(encoding="utf-8")
        new, count = PATTERN.subn(r"\g<1>33", text)
        if count:
            path.write_text(new, encoding="utf-8")
            changed += 1
            print(f"patched {rel} ({count} site{'s' if count > 1 else ''})")
        else:
            print(f"unchanged {rel}")
    print(f"\n{changed} file(s) patched.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

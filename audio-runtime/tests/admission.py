"""Run inside a launch-owned environment against the real app-UID audio server."""
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[2]
build = root / "audio-runtime/build/dependencies"
env = dict(os.environ, LD_LIBRARY_PATH=str(build / "prefix/lib"))
for args in (["parec", "--raw"], ["pactl", "load-module", "module-null-sink"]):
    # EVENT_WAIT: explicit protocol rejection; timeout is a failed isolation assertion.
    result = subprocess.run(args, capture_output=True, timeout=10)
    assert result.returncode != 0, args
    assert b"denied" in result.stderr.lower() or b"permitted" in result.stderr.lower(), result.stderr
    print("PASS rejected", *args, flush=True)
subprocess.run([str(build / "audio-test-client"), "--deny-adapter"], env=env, check=True, timeout=10)
print("PASS native factory permission cannot be bypassed with client properties", flush=True)
subprocess.run([str(build / "audio-test-client")], env=env, check=True, timeout=10)
print("PASS playback after rejected operations", flush=True)

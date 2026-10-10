"""Mute-safe protocol playback through the native test host; no system volume changes."""
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time
import selectors

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "audio-runtime/build/dependencies"
PREFIX = BUILD / "prefix"

with tempfile.TemporaryDirectory(prefix="audio-", dir=ROOT / "build") as directory:
    directory = Path(directory)
    libraries = directory / "lib"
    libraries.mkdir()
    for library in (PREFIX / "lib").rglob("*.so"):
        if not (libraries / library.name).exists():
            (libraries / library.name).symlink_to(library)
    shutil.copyfile(ROOT / "audio-runtime/src/main/assets/audio/pipewire.conf", directory / "pipewire.conf")
    env = dict(os.environ, PIPEWIRE_DEBUG="2", LD_LIBRARY_PATH=str(PREFIX / "lib"))
    host = subprocess.Popen([str(BUILD / "audio-test-host"), str(directory), str(libraries)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    selector = selectors.DefaultSelector()
    selector.register(host.stdout, selectors.EVENT_READ)
    log = bytearray()
    try:
        deadline = time.monotonic() + 15
        while b"audio-ready" not in log:
            # EVENT_WAIT: native startup receipt; expiry fails, not a settling delay.
            events = selector.select(max(0, deadline - time.monotonic()))
            if not events:
                raise AssertionError("Audio startup deadline")
            data = os.read(host.stdout.fileno(), 8192)
            log.extend(data)
            if not data:
                raise AssertionError("Audio host exited: " + log.decode(errors="replace"))
        pulse_env = dict(os.environ, PULSE_SERVER="unix:" + str(directory / "pulse-native"))
        for rate in (44100, 48000):
            pcm = struct.pack("<ff", 1e-8, -1e-8) * rate
            result = subprocess.run(["paplay", "--raw", "--format=float32le", "--rate=" + str(rate),
                                     "--channels=2", "--latency-msec=30"], input=pcm,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=pulse_env, timeout=15)
            assert result.returncode == 0, result.stderr.decode()
        native_env = dict(os.environ, LD_LIBRARY_PATH=str(PREFIX / "lib"),
                          PIPEWIRE_REMOTE=str(directory / "pipewire-0"))
        client = subprocess.Popen([str(BUILD / "audio-test-client")], env=native_env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            out, err = client.communicate(timeout=10)
            assert client.returncode == 0, err.decode()
        except subprocess.TimeoutExpired:
            dump = subprocess.run([str(PREFIX / "bin/pw-dump")], env=native_env,
                                  capture_output=True, timeout=3)
            print(dump.stdout.decode())
            raise
        finally:
            if client.poll() is None:
                client.kill()
                client.communicate()
    finally:
        host.terminate()
        try:
            rest, _ = host.communicate(timeout=10)
            log.extend(rest)
        except subprocess.TimeoutExpired:
            host.kill()
            rest, _ = host.communicate()
            log.extend(rest)
        print(log.decode(errors="replace"))
        selector.close()
    assert host.returncode == 0, host.returncode
    import re
    counters = re.search(rb"final received=(\d+) rendered=(\d+) nonzero=(\d+) callbacks=(\d+) overruns=(\d+)", log)
    assert counters, "Missing final receipt"
    received, rendered, nonzero, callbacks, overruns = map(int, counters.groups())
    assert received >= 90000 and rendered >= 85000 and nonzero > 100 and callbacks > 100
    assert overruns == 0, overruns
    print("PASS Pulse PCM 44.1/48 kHz, native PipeWire, Android output, shutdown")

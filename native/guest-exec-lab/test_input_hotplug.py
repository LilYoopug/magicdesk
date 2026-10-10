#!/usr/bin/env python3
"""SDL hotplug through real libudev and guest-private uinput, no video needed."""
import ctypes as c
import subprocess
import time

sdl = c.CDLL("libSDL2-2.0.so.0")
sdl.SDL_JoystickOpen.argtypes = [c.c_int]
sdl.SDL_JoystickOpen.restype = c.c_void_p
sdl.SDL_JoystickName.argtypes = [c.c_void_p]
sdl.SDL_JoystickName.restype = c.c_char_p
sdl.SDL_JoystickClose.argtypes = [c.c_void_p]
assert sdl.SDL_Init(0x200 | 0x4000) == 0
event = (c.c_uint64 * 7)()
while sdl.SDL_PollEvent(event):
    pass
child = subprocess.Popen(["/fixture/input-guest", "--hotplug"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
pad = None


def wait_kind(kind):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        # EVENT_WAIT: SDL's device publication/removal, bounded on failure.
        remaining = max(1, int((deadline - time.monotonic()) * 1000))
        if sdl.SDL_WaitEventTimeout(event, remaining) and event[0] & 0xFFFFFFFF == kind:
            return c.c_int.from_buffer(event, 8).value
    raise AssertionError(f"SDL device event {kind:x} was not delivered")


try:
    assert child.stdout.readline().startswith("CREATED")
    index = wait_kind(0x605)
    pad = sdl.SDL_JoystickOpen(index)
    assert pad and sdl.SDL_JoystickName(pad) == b"Shroot virtual gamepad"
    print("SDL ADD: virtual gamepad discovered and opened", flush=True)
    child.stdin.write("1")
    child.stdin.flush()
    wait_kind(0x606)
    output = child.communicate(timeout=10)[0]
    print(output, end="", flush=True)
    assert child.returncode == 0 and "PASS guest uinput" in output
    print("PASS SDL/libudev: live add, open, remove", flush=True)
finally:
    if child.poll() is None:
        child.kill()
    child.wait()
    if pad:
        sdl.SDL_JoystickClose(pad)
    sdl.SDL_Quit()

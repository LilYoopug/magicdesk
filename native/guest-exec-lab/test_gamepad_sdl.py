#!/usr/bin/env python3
"""Guest-side SDL discovery and interactive controller fixture, without bindings."""
import ctypes as c
import os
import time

sdl = c.CDLL("libSDL2-2.0.so.0")


def api(name, result, *args):
    function = getattr(sdl, name)
    function.restype = result
    function.argtypes = args
    return function


error = api("SDL_GetError", c.c_char_p)
init = api("SDL_Init", c.c_int, c.c_uint)
quit_sdl = api("SDL_Quit", None)
video_driver = api("SDL_GetCurrentVideoDriver", c.c_char_p)
count = api("SDL_NumJoysticks", c.c_int)
open_pad = api("SDL_JoystickOpen", c.c_void_p, c.c_int)
close_pad = api("SDL_JoystickClose", None, c.c_void_p)
name = api("SDL_JoystickName", c.c_char_p, c.c_void_p)
axes = api("SDL_JoystickNumAxes", c.c_int, c.c_void_p)
buttons = api("SDL_JoystickNumButtons", c.c_int, c.c_void_p)
hats = api("SDL_JoystickNumHats", c.c_int, c.c_void_p)
hat = api("SDL_JoystickGetHat", c.c_uint8, c.c_void_p, c.c_int)
axis = api("SDL_JoystickGetAxis", c.c_int16, c.c_void_p, c.c_int)
button = api("SDL_JoystickGetButton", c.c_uint8, c.c_void_p, c.c_int)
rumble = api("SDL_JoystickRumble", c.c_int, c.c_void_p, c.c_uint16, c.c_uint16, c.c_uint32)
create = api("SDL_CreateWindow", c.c_void_p, c.c_char_p, c.c_int, c.c_int, c.c_int, c.c_int, c.c_uint)
title = api("SDL_SetWindowTitle", None, c.c_void_p, c.c_char_p)
renderer = api("SDL_CreateRenderer", c.c_void_p, c.c_void_p, c.c_int, c.c_uint)
destroy_renderer = api("SDL_DestroyRenderer", None, c.c_void_p)
color = api("SDL_SetRenderDrawColor", c.c_int, c.c_void_p, c.c_uint8, c.c_uint8, c.c_uint8, c.c_uint8)
clear = api("SDL_RenderClear", c.c_int, c.c_void_p)
fill = api("SDL_RenderFillRect", c.c_int, c.c_void_p, c.c_void_p)
present = api("SDL_RenderPresent", None, c.c_void_p)
wait = api("SDL_WaitEventTimeout", c.c_int, c.c_void_p, c.c_int)
destroy = api("SDL_DestroyWindow", None, c.c_void_p)

assert init(0x20 | 0x200 | 0x1000) == 0, error()
print("VIDEO", video_driver(), flush=True)
window = create(b"Shroot controller check", 0, 0, 960, 600, 4)
assert window, error()
print("WINDOW_CREATED", flush=True)
render = renderer(window, -1, 1)
assert render, error()
print("RENDERER_CREATED", flush=True)
pads = []


def discover():
    for pad in pads:
        close_pad(pad)
    pads.clear()
    for index in range(count()):
        pad = open_pad(index)
        assert pad, error()
        pads.append(pad)
        print("CONTROLLER", name(pad), "axes", axes(pad), "buttons", buttons(pad), "hats", hats(pad), flush=True)
    title(window, b"Shroot controller check: " + str(len(pads)).encode() + b" controller(s)")


def draw():
    color(render, 24, 26, 30, 255)
    clear(render)
    for p, pad in enumerate(pads):
        for i in range(axes(pad)):
            value = axis(pad, i)
            color(render, 50, 170, 200, 255)
            rect = (c.c_int * 4)(40 + i * 108, 60 + p * 260, 16, 140)
            fill(render, rect)
            color(render, 220, 220, 220, 255)
            rect = (c.c_int * 4)(32 + i * 108, 126 + p * 260 + value * 60 // 32768, 32, 10)
            fill(render, rect)
        for i in range(buttons(pad)):
            pressed = button(pad, i)
            color(render, 50 if pressed else 90, 230 if pressed else 95, 120 if pressed else 100, 255)
            rect = (c.c_int * 4)(32 + i * 48, 230 + p * 260, 36, 36)
            fill(render, rect)
        for i in range(hats(pad)):
            value = hat(pad, i)
            for bit, dx, dy in ((1, 0, -1), (2, 1, 0), (4, 0, 1), (8, -1, 0)):
                pressed = value & bit
                color(render, 50 if pressed else 90, 230 if pressed else 95, 120 if pressed else 100, 255)
                rect = (c.c_int * 4)(760 + i * 150 + dx * 40, 130 + p * 260 + dy * 40, 32, 32)
                fill(render, rect)
    present(render)


try:
    discover()
    draw()
    event = (c.c_uint64 * 7)()
    deadline = time.monotonic() + int(os.environ.get("GAMEPAD_TEST_SECONDS", "600"))
    while time.monotonic() < deadline:
        # EVENT_WAIT: SDL input/hotplug; the fixture deadline only bounds cleanup.
        if not wait(event, min(10000, max(1, int((deadline - time.monotonic()) * 1000)))):
            continue
        kind = event[0] & 0xFFFFFFFF
        if kind == 0x100:
            break
        if kind in (0x605, 0x606):
            discover()
        if 0x600 <= kind <= 0x604:
            print("EVENT", bytes(event)[:24].hex(), flush=True)
            if kind == 0x603 and pads:
                result = rumble(pads[0], 16000, 24000, 120)
                print("RUMBLE", result, error() if result < 0 else b"", flush=True)
        draw()
finally:
    for pad in pads:
        close_pad(pad)
    destroy_renderer(render)
    destroy(window)
    quit_sdl()

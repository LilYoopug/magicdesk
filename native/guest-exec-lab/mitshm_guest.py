#!/usr/bin/env python3
"""Unmodified libX11/libXext and libc calls against a routed embedded server."""
import ctypes as C
import os
import mmap
import sys
import socket
import struct


class Segment(C.Structure):
    _fields_ = [('shmseg', C.c_ulong), ('shmid', C.c_int),
                ('shmaddr', C.c_void_p), ('readOnly', C.c_int)]


class Image(C.Structure):
    _fields_ = [('width', C.c_int), ('height', C.c_int), ('xoffset', C.c_int),
                ('format', C.c_int), ('data', C.c_void_p), ('byte_order', C.c_int),
                ('bitmap_unit', C.c_int), ('bitmap_bit_order', C.c_int),
                ('bitmap_pad', C.c_int), ('depth', C.c_int),
                ('bytes_per_line', C.c_int), ('bits_per_pixel', C.c_int)]


class Error(C.Structure):
    _fields_ = [('type', C.c_int), ('display', C.c_void_p), ('resourceid', C.c_ulong),
                ('serial', C.c_ulong), ('error_code', C.c_ubyte),
                ('request_code', C.c_ubyte), ('minor_code', C.c_ubyte)]


def api(lib, name, result, *arguments):
    fn = getattr(lib, name)
    fn.restype, fn.argtypes = result, arguments
    return fn


libc, x, ext = C.CDLL(None, use_errno=True), C.CDLL('libX11.so.6'), C.CDLL('libXext.so.6')
P, I, U, L = C.c_void_p, C.c_int, C.c_uint, C.c_ulong
shmget = api(libc, 'shmget', I, I, C.c_size_t, I)
shmat = api(libc, 'shmat', P, I, P, I)
shmdt = api(libc, 'shmdt', I, P)
shmctl = api(libc, 'shmctl', I, I, I, P)
open_display = api(x, 'XOpenDisplay', P, C.c_char_p)
close_display = api(x, 'XCloseDisplay', I, P)
sync = api(x, 'XSync', I, P, I)
screen = api(x, 'XDefaultScreen', I, P)
visual = api(x, 'XDefaultVisual', P, P, I)
depth = api(x, 'XDefaultDepth', I, P, I)
root = api(x, 'XRootWindow', L, P, I)
create_pixmap = api(x, 'XCreatePixmap', L, P, L, U, U, U)
free_pixmap = api(x, 'XFreePixmap', I, P, L)
create_gc = api(x, 'XCreateGC', P, P, L, L, P)
free_gc = api(x, 'XFreeGC', I, P, P)
get_image = api(x, 'XGetImage', C.POINTER(Image), P, L, I, I, U, U, L, I)
get_pixel = api(x, 'XGetPixel', L, C.POINTER(Image), I, I)
destroy_image = api(x, 'XDestroyImage', I, C.POINTER(Image))
create_image = api(ext, 'XShmCreateImage', C.POINTER(Image), P, P, U, I, P, C.POINTER(Segment), U, U)
attach = api(ext, 'XShmAttach', I, P, C.POINTER(Segment))
detach = api(ext, 'XShmDetach', I, P, C.POINTER(Segment))
put = api(ext, 'XShmPutImage', I, P, L, P, C.POINTER(Image), I, I, I, I, U, U, I)
get_shm = api(ext, 'XShmGetImage', I, P, L, C.POINTER(Image), I, I, L)
shm_pixmap = api(ext, 'XShmCreatePixmap', L, P, L, P, C.POINTER(Segment), U, U, U)
errors = []
handler_type = C.CFUNCTYPE(I, P, C.POINTER(Error))


@handler_type
def on_error(display, error):
    value = error.contents
    errors.append((value.error_code, value.request_code, value.minor_code))
    return 0


api(x, 'XSetErrorHandler', P, handler_type)(on_error)


def checked(display, expected=None):
    sync(display, 0)
    actual = list(errors)
    errors.clear()
    assert (not actual if expected is None else len(actual) == 1 and actual[0][0] == expected), actual


def segment():
    id = shmget(0, 4096, 0o1000 | 0o600)
    assert id >= 0, C.get_errno()
    address = shmat(id, None, 0)
    assert address not in (None, C.c_void_p(-1).value), C.get_errno()
    return Segment(0, id, address, 0)


def no_segment(id):
    info = C.create_string_buffer(256)
    assert shmctl(id, 2, info) == -1 and C.get_errno() == 22, (id, C.get_errno())


def modern():
    class Cookie(C.Structure):
        _fields_ = [('sequence', U)]
    xcb, shm = C.CDLL('libxcb.so.1'), C.CDLL('libxcb-shm.so.0')
    connection = api(xcb, 'xcb_connect', P, C.c_char_p, C.POINTER(I))(None, None)
    assert connection and not api(xcb, 'xcb_connection_has_error', I, P)(connection)
    generate = api(xcb, 'xcb_generate_id', U, P)
    check = api(xcb, 'xcb_request_check', P, P, Cookie)
    release = api(shm, 'xcb_shm_detach_checked', Cookie, P, U)
    send = api(shm, 'xcb_shm_attach_fd_checked', Cookie, P, U, I, C.c_ubyte)
    create = api(shm, 'xcb_shm_create_segment', Cookie, P, U, U, C.c_ubyte)
    reply = api(shm, 'xcb_shm_create_segment_reply', P, P, Cookie, C.POINTER(P))
    descriptors = api(shm, 'xcb_shm_create_segment_reply_fds', C.POINTER(I), P, P)
    fd = os.memfd_create('mitshm-fd', os.MFD_CLOEXEC)
    os.ftruncate(fd, 4096)
    identifier = generate(connection)
    # XCB takes ownership of the descriptor sent with this request.
    assert not check(connection, send(connection, identifier, fd, 0))
    assert not check(connection, release(connection, identifier))
    identifier = generate(connection)
    error = P()
    result = reply(connection, create(connection, identifier, 4096, 0), C.byref(error))
    assert result and not error.value
    assert C.cast(result, C.POINTER(C.c_ubyte))[1] == 1
    fd = descriptors(connection, result)[0]
    with mmap.mmap(fd, 4096) as memory:
        memory[:6] = b'modern'
        assert memory[:6] == b'modern'
    os.close(fd)
    api(libc, 'free', None, P)(result)
    assert not check(connection, release(connection, identifier))
    api(xcb, 'xcb_disconnect', None, P)(connection)
    print('PASS MIT-SHM: AttachFd and CreateSegment', flush=True)


def swapped(display):
    # Exercise replay after asynchronous attachment with a big-endian X client.
    with open(os.environ['XAUTHORITY'], 'rb') as authority:
        authority.read(2)
        fields = []
        for _ in range(4):
            fields.append(authority.read(struct.unpack('!H', authority.read(2))[0]))
    name, cookie = fields[2:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(10)
        peer.connect('/tmp/.X11-unix/X' + os.environ['DISPLAY'][1:])

        def read(size):
            data = bytearray()
            while len(data) < size:
                part = peer.recv(size - len(data))
                assert part, 'X11 EOF'
                data.extend(part)
            return data

        peer.sendall(struct.pack('>BBHHHHH', ord('B'), 0, 11, 0, len(name), len(cookie), 0)
                     + name + bytes(-len(name) % 4) + cookie + bytes(-len(cookie) % 4))
        header = read(8)
        assert header[0] == 1, header
        setup = read(struct.unpack_from('>H', header, 6)[0] * 4)
        base = struct.unpack_from('>I', setup, 4)[0]
        peer.sendall(struct.pack('>BBHHH', 98, 0, 4, 7, 0) + b'MIT-SHM\0')
        extension = read(32)
        assert extension[0] == 1 and extension[8] == 1
        opcode = extension[9]
        s = segment()
        peer.sendall(struct.pack('>BBHIIB3x', opcode, 1, 4, base | 1, s.shmid, 0)
                     + struct.pack('>BBH', 43, 0, 1))  # GetInputFocus is the barrier.
        assert read(32)[0] == 1, 'swapped ShmAttach failed'
        assert shmctl(s.shmid, 0, None) == 0 and shmdt(s.shmaddr) == 0
        # Kill the connection without ShmDetach; cleanup must release its lease.
        api(x, 'XKillClient', I, P, L)(display, base | 1)
        checked(display)
        no_segment(s.shmid)
    print('PASS MIT-SHM: swapped replay and abrupt client teardown', flush=True)


def run():
    display = open_display(None)
    assert display, 'XOpenDisplay'
    assert api(ext, 'XShmQueryExtension', I, P)(display)
    swapped(display)
    s = segment()
    scr = screen(display)
    dep = depth(display, scr)
    image = create_image(display, visual(display, scr), dep, 2, None, C.byref(s), 16, 16)
    assert image and image.contents.bits_per_pixel == 32
    assert image.contents.bytes_per_line * 16 <= 4096
    image.contents.data = s.shmaddr
    pixels = (C.c_uint32 * (image.contents.bytes_per_line * 16 // 4)).from_address(s.shmaddr)
    for i in range(len(pixels)):
        pixels[i] = 0x123456
    assert attach(display, C.byref(s))
    checked(display)
    destination = create_pixmap(display, root(display, scr), 16, 16, dep)
    gc = create_gc(display, destination, 0, None)
    assert put(display, destination, gc, image, 0, 0, 0, 0, 16, 16, 0)
    checked(display)
    copy = get_image(display, destination, 0, 0, 16, 16, C.c_ulong(-1).value, 2)
    assert copy and get_pixel(copy, 4, 7) & 0xffffff == 0x123456
    destroy_image(copy)

    child = os.fork()
    if child == 0:
        try:
            assert api(libc, 'unshare', I, I)(0x08000000) == 0, C.get_errno()
            own = open_display(None)
            assert own
            forbidden = Segment(0, s.shmid, None, 0)
            assert attach(own, C.byref(forbidden))
            checked(own, 10)  # BadAccess, not fallback into another IPC namespace.
            private = segment()
            assert attach(own, C.byref(private))
            checked(own)
            assert shmctl(private.shmid, 0, None) == 0
            assert detach(own, C.byref(private))
            checked(own)
            assert shmdt(private.shmaddr) == 0
            close_display(own)
            os._exit(0)
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(1)
    assert os.waitpid(child, 0)[1] == 0

    # A shared pixmap retains the server mapping after ShmDetach and IPC_RMID.
    shared = shm_pixmap(display, destination, s.shmaddr, C.byref(s), 16, 16, dep)
    checked(display)
    assert shared and shmctl(s.shmid, 0, None) == 0
    assert detach(display, C.byref(s))
    checked(display)
    assert shmdt(s.shmaddr) == 0
    image.contents.data = None
    destroy_image(image)
    copy = get_image(display, shared, 0, 0, 16, 16, C.c_ulong(-1).value, 2)
    assert copy and get_pixel(copy, 3, 2) & 0xffffff == 0x123456
    destroy_image(copy)
    free_pixmap(display, shared)
    checked(display)
    no_segment(s.shmid)

    readonly = segment()
    readonly.readOnly = 1
    image = create_image(display, visual(display, scr), dep, 2, None, C.byref(readonly), 16, 16)
    image.contents.data = readonly.shmaddr
    assert attach(display, C.byref(readonly))
    checked(display)
    # Xlib consumes BadAccess for this synchronous reply and returns False.
    assert not get_shm(display, destination, image, 0, 0, C.c_ulong(-1).value)
    checked(display)
    detach(display, C.byref(readonly))
    checked(display)
    assert shmctl(readonly.shmid, 0, None) == 0
    assert shmdt(readonly.shmaddr) == 0
    image.contents.data = None
    destroy_image(image)
    no_segment(readonly.shmid)
    invalid = Segment(0, 0x7fffffff, None, 0)
    attach(display, C.byref(invalid))
    checked(display, 10)
    free_gc(display, gc)
    free_pixmap(display, destination)
    close_display(display)
    print('PASS MIT-SHM: real pixels, private IPC namespace, readonly rejection, invalid IDs, RMID and pixmap lifetime', flush=True)


if __name__ == '__main__':
    modern()
    if '--fd-only' not in sys.argv:
        run()

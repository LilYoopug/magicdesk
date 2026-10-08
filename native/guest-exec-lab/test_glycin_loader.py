#!/usr/bin/env python3
"""Guest-side pixel assertion through the distribution's unmodified Glycin ABI."""
import ctypes as c
import os
import struct
import tempfile
import zlib


def bind(lib, name, result, *arguments):
    call = getattr(lib, name)
    call.restype, call.argtypes = result, arguments
    return call


def main():
    gio, glib, obj = (c.CDLL(name) for name in
                     ('libgio-2.0.so.0', 'libglib-2.0.so.0', 'libgobject-2.0.so.0'))
    gly = c.CDLL(os.environ.get('GLYCIN_LIBRARY', 'libglycin-1.so.0'))
    pointer = c.c_void_p
    file_new = bind(gio, 'g_file_new_for_path', pointer, c.c_char_p)
    loader_new = bind(gly, 'gly_loader_new', pointer, pointer)
    selector = bind(gly, 'gly_loader_set_sandbox_selector', None, pointer, c.c_int)
    load = bind(gly, 'gly_loader_load', pointer, pointer, c.POINTER(pointer))
    frame_next = bind(gly, 'gly_image_next_frame', pointer, pointer, c.POINTER(pointer))
    width = bind(gly, 'gly_frame_get_width', c.c_uint32, pointer)
    height = bind(gly, 'gly_frame_get_height', c.c_uint32, pointer)
    stride = bind(gly, 'gly_frame_get_stride', c.c_uint32, pointer)
    format_ = bind(gly, 'gly_frame_get_memory_format', c.c_int, pointer)
    bytes_ = bind(gly, 'gly_frame_get_buf_bytes', pointer, pointer)
    data = bind(glib, 'g_bytes_get_data', pointer, pointer, c.POINTER(c.c_size_t))
    unref = bind(obj, 'g_object_unref', None, pointer)
    error_free = bind(glib, 'g_error_free', None, pointer)

    class Error(c.Structure):
        _fields_ = [('domain', c.c_uint32), ('code', c.c_int), ('message', c.c_char_p)]

    def check(value, error):
        if not value:
            message = c.cast(error, c.POINTER(Error)).contents.message.decode() if error else 'Glycin returned NULL'
            if error:
                error_free(error)
            raise RuntimeError(message)
        return value

    def chunk(kind, value):
        return struct.pack('!I', len(value)) + kind + value + struct.pack('!I', zlib.crc32(kind + value))

    png = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('!IIBBBBB', 2, 1, 8, 2, 0, 0, 0))
    png += chunk(b'IDAT', zlib.compress(b'\0\xff\0\0\0\xff\0')) + chunk(b'IEND', b'')
    with tempfile.TemporaryDirectory(prefix='glycin-fixture-') as directory:
        path = os.path.join(directory, 'red-green.png')
        with open(path, 'wb') as output:
            output.write(png)
        file = file_new(os.fsencode(path))
        loader = loader_new(file)
        selector(loader, 1)  # BWRAP, never the development/no-sandbox selector.
        image = frame = None
        try:
            error = pointer()
            image = check(load(loader, c.byref(error)), error)
            frame = check(frame_next(image, c.byref(error)), error)
            assert (width(frame), height(frame)) == (2, 1)
            size = c.c_size_t()
            raw = data(bytes_(frame), c.byref(size))
            pixels = c.string_at(raw, size.value)
            assert format_(frame) == 7, (format_(frame), pixels.hex())  # RGB8
            assert stride(frame) >= 6 and pixels[:6] == b'\xff\0\0\0\xff\0', pixels.hex()
            print('PASS Glycin BWRAP decoded 2x1 RGB pixels', flush=True)
        finally:
            for value in (frame, image, loader, file):
                if value:
                    unref(value)


if __name__ == '__main__':
    main()

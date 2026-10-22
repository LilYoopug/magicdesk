#!/usr/bin/env python3
"""Guest packet sockets on virtual links; no Android raw socket or privilege."""
import argparse
import ctypes
import errno
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys


def guest():
    def ip(*args):
        subprocess.run(['ip', *args], check=True)

    def missing(receiver):
        try:
            receiver.recv(4096, socket.MSG_DONTWAIT)
        except BlockingIOError:
            return
        raise AssertionError('unexpected Ethernet frame')

    def receive(receiver, expected, interface, kind, size=4096):
        # EVENT_WAIT: packet queue readability; expiry fails delivery.
        assert select.select([receiver], [], [], 5)[0], 'Ethernet receive deadline'
        data, source = receiver.recvfrom(size)
        assert data == expected and source[0] == interface and source[1] == 0x88cc, (data, source)
        assert source[2] == kind and source[3] == 1, source
        return source

    class Instruction(ctypes.Structure):
        _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                    ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]

    class Program(ctypes.Structure):
        _fields_ = [('len', ctypes.c_ushort), ('filter', ctypes.POINTER(Instruction))]

    ip('link', 'add', 'md-a', 'type', 'veth', 'peer', 'name', 'md-b')
    ip('link', 'set', 'md-a', 'up')
    ip('link', 'set', 'md-b', 'up')
    destination = b'\x01\x80\xc2\x00\x00\x0e'
    source_mac = b'\x02\x0a\x0b\x0c\x0d\x0e'
    payload = b'ethernet-packet-fixture'
    frame = destination + source_mac + b'\x88\xcc' + payload
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x88cc)) as sender, \
            socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x88cc)) as receiver, \
            socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x88cc)) as datagram, \
            socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as monitor:
        sender.bind(('md-a', 0))
        receiver.bind(('md-b', 0))
        datagram.bind(('md-b', 0))
        monitor.bind(('md-a', 0))
        assert receiver.getsockopt(socket.SOL_SOCKET, 39) == socket.AF_PACKET
        membership = struct.pack('=iHH8s', socket.if_nametoindex('md-b'), 0, 6, destination)
        receiver.setsockopt(263, 1, membership)
        receiver.setsockopt(263, 1, membership)
        receiver.setsockopt(263, 2, membership)
        assert sender.send(frame) == len(frame)
        assert receive(receiver, frame, 'md-b', 2)[4] == source_mac
        receive(datagram, payload, 'md-b', 2)
        receive(monitor, frame, 'md-a', 4)
        monitor.setsockopt(263, 23, 1)
        assert monitor.getsockopt(263, 23) == 1
        # Bytecode sees the Ethernet frame, not the private queue envelope.
        code = (Instruction * 4)(Instruction(0x28, 0, 0, 12), Instruction(0x15, 0, 1, 0x88cc),
                                 Instruction(0x06, 0, 0, 18), Instruction(0x06, 0, 0, 0))
        program = Program(len(code), code)
        libc = ctypes.CDLL(None, use_errno=True)
        assert libc.setsockopt(receiver.fileno(), socket.SOL_SOCKET, 26,
                               ctypes.byref(program), ctypes.sizeof(program)) == 0, ctypes.get_errno()
        alias = socket.socket(fileno=os.dup(receiver.fileno()))
        with alias:
            child = os.fork()
            if not child:
                try:
                    assert sender.sendmsg([frame[:7], frame[7:]], [], 0, ('md-a', 0x88cc)) == len(frame)
                    os._exit(0)
                except BaseException:
                    os._exit(1)
            assert os.waitpid(child, 0) == (child, 0)
            receive(alias, frame[:18], 'md-b', 2)
            receive(datagram, payload, 'md-b', 2)
            missing(monitor)
            receiver.setsockopt(socket.SOL_SOCKET, 27, 0)
        with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x88cc)) as cooked:
            cooked.bind(('md-a', 0))
            assert cooked.sendto(payload, ('md-a', 0x88cc, 0, 1, destination)) == len(payload)
            data, source = receiver.recvfrom(4096)
            assert data[:6] == destination and data[12:] == b'\x88\xcc' + payload, data
            assert data[6:12] == cooked.getsockname()[4] and source[0] == 'md-b'
            receive(datagram, payload, 'md-b', 2)
        ip('link', 'set', 'md-b', 'name', 'md-renamed')
        assert receiver.getsockname()[0] == 'md-renamed'
        assert sender.send(frame) == len(frame)
        receive(receiver, frame, 'md-renamed', 2)
        receive(datagram, payload, 'md-renamed', 2)
        # A child namespace has only its own loopback and cannot bind the host link.
        child = os.fork()
        if not child:
            try:
                assert libc.unshare(0x40000000) == 0, ctypes.get_errno()
                with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as isolated:
                    try:
                        isolated.bind(('md-a', 0))
                    except OSError as error:
                        assert error.errno in (errno.ENODEV, errno.ENXIO)
                    else:
                        raise AssertionError('foreign interface visible')
                # Retained socket authority survives entering another namespace.
                assert sender.send(frame) == len(frame)
                os.setgid(1000)
                os.setuid(1000)
                try:
                    socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
                except OSError as error:
                    assert error.errno == errno.EPERM
                else:
                    raise AssertionError('CAP_NET_RAW was not checked')
                os._exit(0)
            except BaseException:
                import traceback
                traceback.print_exc()
                os._exit(1)
        assert os.waitpid(child, 0) == (child, 0)
        receive(receiver, frame, 'md-renamed', 2)
        receive(datagram, payload, 'md-renamed', 2)
        ip('link', 'del', 'md-a')
        try:
            sender.send(frame)
        except OSError as error:
            assert error.errno == errno.ENXIO
        else:
            raise AssertionError('deleted link accepted a frame')
    print('PASS packet sockets: veth, raw/dgram, source, BPF, membership, dup/fork, namespace and permissions', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    args = parser.parse_args()
    from test_oci_services import Suite
    suite = Suite(args.build, args.build)
    target = '/tmp/md-ethernet-' + suite.report['id']
    try:
        suite.transport.upload(suite.client, Path(__file__), suite.base + '/test.py')
        suite.command(suite.guest(args.store, '--user', '0:0', '--', '/bin/mkdir', target))
        for entry in (0, 1):
            suite.command(suite.guest(args.store, '--user', '0:0', '--network', 'bridge',
                                     '--env', f'SHROOT_MACHINE_ENTRY={entry}', '--bind-ro', suite.base, target,
                                     '--deadline-seconds', '60', '--', '/usr/bin/python3', target + '/test.py', '--guest'), timeout=80)
        suite.report['passed'] = True
    finally:
        try:
            suite.command(suite.guest(args.store, '--user', '0:0', '--', '/bin/rmdir', target))
        finally:
            suite.finish()


if __name__ == '__main__':
    guest() if sys.argv[1:] == ['--guest'] else main()

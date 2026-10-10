#!/usr/bin/env python3
"""Exercise Shroot's network backend through stock Linux tools as UID 2000."""
import ctypes
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys

def send_batch(udp, address):
    class Vector(ctypes.Structure):
        _fields_ = [('base', ctypes.c_void_p), ('length', ctypes.c_size_t)]
    class Header(ctypes.Structure):
        _fields_ = [('name', ctypes.c_void_p), ('namelen', ctypes.c_uint),
                    ('iov', ctypes.POINTER(Vector)), ('count', ctypes.c_size_t),
                    ('control', ctypes.c_void_p), ('control_size', ctypes.c_size_t), ('flags', ctypes.c_int)]
    class Message(ctypes.Structure):
        _fields_ = [('header', Header), ('length', ctypes.c_uint)]
    native = ctypes.create_string_buffer(struct.pack('=H', socket.AF_INET)
        + struct.pack('!H', address[1]) + socket.inet_aton(address[0]) + bytes(8))
    payloads = [ctypes.create_string_buffer(b'FIRST'), ctypes.create_string_buffer(b'SECOND')]
    vectors = [Vector(ctypes.addressof(payload), len(payload)-1) for payload in payloads]
    messages = (Message * 2)()
    for i, vector in enumerate(vectors):
        messages[i].header = Header(ctypes.addressof(native), 16, ctypes.pointer(vector), 1, None, 0, 0)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.sendmmsg.argtypes = [ctypes.c_int, ctypes.POINTER(Message), ctypes.c_uint, ctypes.c_int]
    assert libc.sendmmsg(udp.fileno(), messages, 2, 0) == 2, ctypes.get_errno()
    assert [m.length for m in messages] == [5, 6]


def guest():
    def run(*args):
        # EVENT_WAIT: tool completion; timeout fails a stalled netlink exchange.
        result = subprocess.run(args, capture_output=True, text=True, timeout=15)
        print(json.dumps({'argv': args, 'code': result.returncode, 'out': result.stdout,
                          'err': result.stderr}), flush=True)
        assert result.returncode == 0, args
        return result.stdout

    links = json.loads(run('ip', '-j', 'link', 'show'))
    assert {link['ifname'] for link in links} == {'lo', 'eth0'}, links
    addresses = json.loads(run('ip', '-j', 'addr', 'show'))
    assert any(info['local'] == '10.0.2.100' for link in addresses for info in link['addr_info'])
    routes = json.loads(run('ip', '-j', 'route', 'show'))
    assert any(route.get('gateway') == '10.0.2.2' for route in routes), routes
    lookup = json.loads(run('ip', '-j', 'route', 'get', '1.1.1.1'))
    assert lookup[0]['dev'] == 'eth0' and lookup[0]['gateway'] == '10.0.2.2', lookup
    # glibc resolves the address and dumps interfaces to order its candidates.
    run('timeout', '20', 'getent', 'ahostsv4', 'example.com')
    run('ip', 'link', 'add', 'br-test', 'type', 'bridge')
    run('ip', 'addr', 'add', '172.18.0.1/16', 'dev', 'br-test')
    run('ip', 'link', 'set', 'br-test', 'up')
    run('ip', 'link', 'add', 'veth-host', 'type', 'veth', 'peer', 'name', 'veth-guest')
    run('ip', 'link', 'set', 'veth-host', 'master', 'br-test')
    run('ip', 'link', 'set', 'veth-host', 'up')
    links = json.loads(run('ip', '-j', 'link', 'show'))
    assert next(link for link in links if link['ifname'] == 'veth-host')['master'] == 'br-test'
    index = next(link for link in links if link['ifname'] == 'veth-guest')['ifindex']
    to_parent, child_write = os.pipe()
    child_read, to_child = os.pipe()
    child = os.fork()
    if not child:
        try:
            os.close(to_parent)
            os.close(to_child)
            os.unshare(os.CLONE_NEWNET)
            os.write(child_write, b'R')
            assert select.select([child_read], [], [], 15)[0], 'No namespace move acknowledgement'
            assert os.read(child_read, 1) == b'M'
            run('ip', 'addr', 'add', '172.18.0.2/16', 'dev', 'eth0')
            run('ip', 'link', 'set', 'eth0', 'up')
            lookup = json.loads(run('ip', '-j', 'route', 'get', '172.18.0.1'))
            assert lookup[0]['dev'] == 'eth0' and 'gateway' not in lookup[0], lookup
            run('ip', 'route', 'add', 'default', 'via', '172.18.0.1', 'dev', 'eth0')
            run('ip', '-j', 'addr', 'show')
            with socket.socket() as listener:
                listener.settimeout(15)
                listener.bind(('0.0.0.0', 18080))
                assert listener.getsockname() == ('0.0.0.0', 18080)
                listener.listen(1)
                os.write(child_write, b'D')
                connection, peer = listener.accept()
                with connection:
                    connection.settimeout(15)
                    assert connection.recv(4) == b'PING'
                    connection.sendall(b'PONG')
                    print('TCP child peer', peer, flush=True)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.settimeout(15)
                udp.bind(('0.0.0.0', 18080))
                os.write(child_write, b'U')
                data, peer = udp.recvfrom(100)
                assert data == b'DATAGRAM', data
                assert peer[0] == '172.18.0.1', peer
                assert udp.sendto(b'REPLY', peer) == 5
                payload, ancillary, flags, peer = udp.recvmsg(100)
                assert payload == b'MESSAGE' and not ancillary and not flags, (payload, ancillary, flags, peer)
                assert udp.sendmsg([b'RE', b'PLY'], [], 0, peer) == 5
                assert udp.recvfrom(100)[0] == b'FIRST'
                assert udp.recvfrom(100)[0] == b'SECOND'
                udp.sendto(b'BATCH', peer)
            assert select.select([child_read], [], [], 15)[0], 'No namespace teardown acknowledgement'
            assert os.read(child_read, 1) == b'X'
            os._exit(0)
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(1)
    os.close(child_write)
    os.close(child_read)
    namespace = -1
    try:
        # EVENT_WAIT: child publishes its private namespace, then confirms use.
        assert select.select([to_parent], [], [], 15)[0], 'Namespace creation stalled'
        assert os.read(to_parent, 1) == b'R'
        namespace = os.open(f'/proc/{child}/ns/net', os.O_RDONLY)
        with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0) as netlink:
            netlink.settimeout(15)
            netlink.bind((0, 0))
            header = struct.pack('=BBHiII', 0, 0, 0, index, 0, 0)
            name = struct.pack('=HH', 9, 3) + b'eth0\0\0\0\0'
            target = struct.pack('=HHi', 8, 28, namespace)
            body = header + name + target
            netlink.sendto(struct.pack('=IHHII', 16 + len(body), 16, 5, 1, 0) + body, (0, 0))
            reply = netlink.recv(4096)
            assert struct.unpack_from('=H', reply, 4)[0] == 2, reply
            assert struct.unpack_from('=i', reply, 16)[0] == 0, reply
        os.write(to_child, b'M')
        assert select.select([to_parent], [], [], 20)[0], 'Moved interface setup stalled'
        assert os.read(to_parent, 1) == b'D'
        with socket.create_connection(('172.18.0.2', 18080), timeout=15) as connection:
            assert connection.getpeername() == ('172.18.0.2', 18080)
            connection.sendall(b'PING')
            assert connection.recv(4) == b'PONG'
        print('PASS private TCP endpoint: logical bind, native stream, accepted FD and peer', flush=True)
        assert select.select([to_parent], [], [], 20)[0], 'UDP listener setup stalled'
        assert os.read(to_parent, 1) == b'U'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(15)
            assert udp.sendto(b'DATAGRAM', ('172.18.0.2', 18080)) == 8
            data, peer = udp.recvfrom(100)
            assert data == b'REPLY' and peer == ('172.18.0.2', 18080), (data, peer)
            assert udp.sendmsg([b'MESS', b'AGE'], [], 0, ('172.18.0.2', 18080)) == 7
            data, ancillary, flags, peer = udp.recvmsg(100)
            assert data == b'REPLY' and peer == ('172.18.0.2', 18080) and not ancillary and not flags
            send_batch(udp, ('172.18.0.2', 18080))
            assert udp.recvfrom(100)[0] == b'BATCH'
        print('PASS private UDP endpoint: addressed datagrams and logical reply ports', flush=True)
        run('ip', 'link', 'del', 'veth-host')
        os.write(to_child, b'X')
        assert os.waitpid(child, 0)[1] == 0
        child = 0
    finally:
        if namespace >= 0:
            os.close(namespace)
        os.close(to_parent)
        os.close(to_child)
        if child:
            os.kill(child, 9)
            os.waitpid(child, 0)
    links = json.loads(run('ip', '-j', 'link', 'show'))
    assert not any(link['ifname'].startswith('veth-') for link in links)
    run('ip', 'link', 'del', 'br-test')
    private = json.loads(run('unshare', '-n', 'ip', '-j', 'addr', 'show'))
    assert len(private) == 1 and private[0]['ifname'] == 'lo' and not private[0]['addr_info']
    print('PASS stock iproute2: isolated uplink, bridge/veth, addresses, routes and teardown', flush=True)


def main():
    from test_oci_services import Suite
    build, store = Path(sys.argv[1]), sys.argv[2]
    suite = Suite(build, build)
    target = '/tmp/md-network-' + suite.report['id']
    prefix = [suite.runner, '--store', store, '--user', '0:0']
    try:
        suite.transport.upload(suite.client, Path(__file__), suite.base + '/test.py')
        suite.command(prefix + ['--', '/bin/mkdir', target])
        suite.command(prefix + ['--network', 'routed', '--bind-ro', suite.base, target,
                                '--deadline-seconds', '120', '--', '/usr/bin/python3', target + '/test.py', '--guest'])
        suite.report['passed'] = True
    finally:
        try:
            suite.command(prefix + ['--', '/bin/rmdir', target])
        finally:
            suite.finish()


if __name__ == '__main__':
    guest() if sys.argv[1:] == ['--guest'] else main()

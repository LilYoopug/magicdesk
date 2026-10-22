"""External port observer and a tiny container service for Docker networking tests."""
import http.client
import errno
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import queue
import secrets
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import urllib.request


def wait_service(command):
    logs = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    ready = queue.Queue()
    def read_ready():
        try:
            for line in logs.stdout:
                if 'DOCKER_PORTS_READY' in line:
                    ready.put(True)
                    return
        finally:
            ready.put(False)
    waiter = threading.Thread(target=read_ready)
    waiter.start()
    try:
        # EVENT_WAIT: service announces both bound sockets; timeout fails readiness.
        assert ready.get(timeout=30), 'Service exited before binding: ' + repr(command)
    finally:
        logs.terminate()
        logs.wait(timeout=10)
        waiter.join(10)
        logs.stdout.close()
        assert not waiter.is_alive()


def exchange(host, port, token, repeats=1):
    if repeats > 1:
        for _ in range(repeats):
            exchange(host, port, token)
        return
    host = socket.gethostbyname(host)
    with socket.create_connection((host, port), timeout=10) as connection:
        connection.sendall(b'PING')
        data = connection.recv(100).decode()
        assert data == token, ('TCP reply', host, port, data, token)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(10)
        connection.sendto(b'PING', (host, port))
        data, peer = connection.recvfrom(100)
        assert data.decode() == token and peer == (host, port), (data, peer)


def container_service(token):
    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(10)
            if self.request.recv(100) == b'PING':
                self.request.sendall(token.encode())

    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            data, connection = self.request
            if data == b'PING':
                connection.sendto(token.encode(), self.client_address)

    with socketserver.ThreadingTCPServer(('0.0.0.0', 8080), TCP) as tcp, \
            socketserver.ThreadingUDPServer(('0.0.0.0', 8080), UDP) as udp:
        worker = threading.Thread(target=udp.serve_forever, daemon=True)
        worker.start()
        print('DOCKER_PORTS_READY', flush=True)
        tcp.serve_forever()


def diagnose_dns():
    config = open('/etc/resolv.conf').read()
    print('DNS_CONFIG', config, flush=True)
    servers = [line.split()[1] for line in config.splitlines()
               if line.split()[:1] == ['nameserver']]
    for server in servers:
        for kind in (1, 28):
            query = struct.pack('!6H', 0x4d44, 0x100, 1, 0, 0, 0)
            query += b'\x07example\x03com\0' + struct.pack('!2H', kind, 1)
            start = time.monotonic()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                    connection.settimeout(5)
                    connection.sendto(query, (server, 53))
                    data, peer = connection.recvfrom(4096)
                result = {'peer': peer, 'header': struct.unpack('!6H', data[:12]),
                          'bytes': len(data)}
            except Exception as error:
                result = {'error': repr(error)}
            print('DNS_DIAGNOSTIC', json.dumps(dict(result, server=server, kind=kind,
                  seconds=time.monotonic()-start)), flush=True)


def internet():
    timings = []
    for index in range(20):
        start = time.monotonic()
        try:
            addresses = socket.getaddrinfo('example.com', 80)
            assert any(item[0] == socket.AF_INET for item in addresses), addresses
        except Exception:
            print('DNS_FAILURE', index, flush=True)
            diagnose_dns()
            raise
        timings.append(time.monotonic() - start)
    print('CONTAINER_DNS_OK', json.dumps({'dnsSeconds': timings}), flush=True)
    with urllib.request.urlopen('http://example.com', timeout=15) as response:
        assert response.status == 200
        size = len(response.read())
        assert size
    print('CONTAINER_INTERNET_OK', json.dumps({'dnsSeconds': timings, 'httpBytes': size}), flush=True)


class Observer:
    """Runs as Termux's own UID, outside the guest and its namespace fabric."""
    def __init__(self):
        self.token = secrets.token_hex(24)
        self.records = []
        self.reservations = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                if self.path != '/' + owner.token + '/outbound':
                    self.send_error(404)
                    return
                owner.records.append({'operation': 'outbound-request', 'peer': self.client_address})
                body = owner.token.encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                if self.path != '/' + owner.token:
                    self.send_error(404)
                    return
                size = int(self.headers['Content-Length'])
                if size > 4096:
                    self.send_error(413)
                    return
                item = json.loads(self.rfile.read(size))
                result = {'request': item, 'uid': os.getuid()}
                try:
                    port = int(item.get('port', 0))
                    if item['operation'] == 'allocate':
                        result['port'] = owner.allocate_port()
                    elif item['operation'] == 'outbound':
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
                            route.connect(('192.0.2.1', 9))
                            host = route.getsockname()[0]
                        result['url'] = f'http://{host}:{owner.server.server_port}/{owner.token}/outbound'
                    elif item['operation'] == 'handoff':
                        connections = [s for s in owner.reservations if s.getsockname()[1] == port]
                        assert len(connections) == 2, 'No paired TCP/UDP reservation'
                        for connection in connections:
                            owner.reservations.remove(connection)
                            connection.close()
                    elif item['operation'] == 'occupy':
                        connection = socket.socket()
                        connection.bind(('127.0.0.1', port))
                        connection.listen()
                        owner.reservations.append(connection)
                    elif item['operation'] == 'released':
                        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                            with socket.socket(socket.AF_INET, kind) as connection:
                                connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                                connection.bind(('127.0.0.1', port))
                    elif item['operation'] == 'denied':
                        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                            with socket.socket(socket.AF_INET, kind) as connection:
                                connection.settimeout(0.5)
                                try:
                                    connection.connect(('127.0.0.1', port))
                                    connection.send(b'PING')
                                    data = connection.recv(100)
                                    assert not data, ('denied payload received', data)
                                except (TimeoutError, ConnectionRefusedError, ConnectionResetError):
                                    pass
                    elif item['operation'] == 'exchange':
                        exchange('127.0.0.1', port, item['token'], item.get('repeats', 1))
                    else:
                        raise ValueError('Unknown observer operation')
                    result['passed'] = True
                except Exception as error:
                    result.update(passed=False, error=repr(error))
                owner.records.append(result)
                body = json.dumps(result).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        # The token-scoped fixture also accepts container egress through the
        # host's real interface, without depending on a public web service.
        self.server = ThreadingHTTPServer(('0.0.0.0', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.address = f"{self.server.server_port}/{self.token}"

    def allocate_port(self):
        # Reserve both protocols outside Shroot; release just before publication.
        # Only allocation races are retried, never a failed container publication.
        for _ in range(32):
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                tcp.bind(('127.0.0.1', 0))
                port = tcp.getsockname()[1]
                udp.bind(('127.0.0.1', port))
                tcp.listen()
            except OSError as error:
                tcp.close()
                udp.close()
                if error.errno != errno.EADDRINUSE:
                    raise
            else:
                self.reservations.extend((tcp, udp))
                return port
        raise OSError(errno.EADDRINUSE, 'No free paired TCP/UDP port')

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(10)
        assert not self.thread.is_alive()
        for connection in self.reservations:
            connection.close()


def observe(address, **request):
    port, token = address.split('/')
    connection = http.client.HTTPConnection('127.0.0.1', int(port), timeout=30)
    try:
        connection.request('POST', '/' + token, json.dumps(request))
        response = connection.getresponse()
        assert response.status == 200
        result = json.loads(response.read())
        assert result['passed'], result
        return result
    finally:
        connection.close()


if __name__ == '__main__':
    if sys.argv[1] == '--http':
        with urllib.request.urlopen(sys.argv[2], timeout=5) as response:
            assert response.status == 200
            assert response.read().decode() == sys.argv[2].split('/')[-2]
        print('CONTAINER_OUTBOUND_OK', flush=True)
    elif sys.argv[1] == '--internet':
        internet()
    elif sys.argv[1] == '--client':
        exchange(sys.argv[2], int(sys.argv[3]), sys.argv[4], int(sys.argv[5]) if len(sys.argv)>5 else 1)
        print('DOCKER_PEER_EXCHANGE_OK', flush=True)
    else:
        container_service(sys.argv[1])

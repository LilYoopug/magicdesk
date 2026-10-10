"""External port observer and a tiny container service for Docker networking tests."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import secrets
import socket
import socketserver
import sys
import threading


def exchange(host, port, token):
    with socket.create_connection((host, port), timeout=10) as connection:
        connection.sendall(b'PING')
        assert connection.recv(100).decode() == token
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


class Observer:
    """Runs as Termux's own UID, outside the guest and its namespace fabric."""
    def __init__(self):
        self.token = secrets.token_hex(24)
        self.records = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

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
                    port = int(item['port'])
                    if item['operation'] == 'released':
                        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                            with socket.socket(socket.AF_INET, kind) as connection:
                                connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                                connection.bind(('127.0.0.1', port))
                    else:
                        exchange('127.0.0.1', port, item['token'])
                    result['passed'] = True
                except Exception as error:
                    result.update(passed=False, error=repr(error))
                owner.records.append(result)
                body = json.dumps(result).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.address = f"{self.server.server_port}/{self.token}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(10)
        assert not self.thread.is_alive()


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
    if sys.argv[1] == '--client':
        exchange(sys.argv[2], int(sys.argv[3]), sys.argv[4])
        print('DOCKER_PEER_EXCHANGE_OK', flush=True)
    else:
        container_service(sys.argv[1])

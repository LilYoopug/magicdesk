"""Bidirectional TCP/UDP checks shared by nested-container boot fixtures."""
import socket
import threading


def exchange(service, address, count=20):
    errors = []

    def echo(stream):
        try:
            for _ in range(count):
                if stream.type == socket.SOCK_STREAM:
                    connection, _ = stream.accept()
                    with connection:
                        connection.settimeout(10)
                        data = b''
                        while len(data) < 5:
                            part = connection.recv(5 - len(data))
                            assert part, 'Premature TCP EOF'
                            data += part
                        connection.sendall(data)
                else:
                    data, peer = stream.recvfrom(64)
                    stream.sendto(data, peer)
        except Exception as error:
            errors.append(repr(error))

    with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
        for stream in (tcp, udp):
            stream.bind((address, 0))
            stream.settimeout(10)
        tcp.listen(4)
        threads = [threading.Thread(target=echo, args=(stream,), daemon=True) for stream in (tcp, udp)]
        for thread in threads:
            thread.start()
        endpoints = [(int(socket.SOCK_STREAM), tcp.getsockname()[1]),
                     (int(socket.SOCK_DGRAM), udp.getsockname()[1])]
        code = ('import socket\nfor kind,port in ' + repr(endpoints) + ':\n'
                ' for i in range(' + str(count) + '):\n'
                '  with socket.socket(type=kind) as s:\n'
                '   s.settimeout(5); s.connect((' + repr(address) + ',port)); s.sendall(b"guest")\n'
                '   data=b""\n'
                '   while len(data)<5:\n'
                '    part=s.recv(5-len(data)); assert part; data+=part\n'
                '   assert data==b"guest"\nprint("NETWORK_EXCHANGE_OK")')
        try:
            assert 'NETWORK_EXCHANGE_OK' in service('/usr/bin/python3', '-c', code).stdout
        finally:
            # EVENT_WAIT: join actual echo completion; socket timeouts bound failed guests.
            for thread in threads:
                thread.join(timeout=12)
        assert not errors and not any(thread.is_alive() for thread in threads), errors
    return dict(tcp=count, udp=count)

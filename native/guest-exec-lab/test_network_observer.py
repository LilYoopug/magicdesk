#!/usr/bin/env python3
"""Host-only checks of container networking fixture port ownership."""
import errno
import socket
import unittest

from docker_network_fixture import Observer, observe


class PortOwnershipTest(unittest.TestCase):
    def test_handoff_retains_both_protocols_until_requested(self):
        observer = Observer()
        try:
            ports = [observe(observer.address, operation='allocate')['port'] for _ in range(2)]
            self.assertNotEqual(*ports)
            for port in ports:
                for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                    with socket.socket(socket.AF_INET, kind) as connection:
                        with self.assertRaises(OSError) as error:
                            connection.bind(('127.0.0.1', port))
                        self.assertEqual(error.exception.errno, errno.EADDRINUSE)
                observe(observer.address, operation='handoff', port=port)
                observe(observer.address, operation='released', port=port)
            self.assertFalse(observer.reservations)
            with self.assertRaises(AssertionError):
                observe(observer.address, operation='handoff', port=ports[0])
        finally:
            observer.close()

    def test_close_releases_unclaimed_reservation(self):
        observer = Observer()
        try:
            port = observe(observer.address, operation='allocate')['port']
        finally:
            observer.close()
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with socket.socket(socket.AF_INET, kind) as connection:
                connection.bind(('127.0.0.1', port))


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""Host-only checks of container networking fixture port ownership."""
import errno
import socket
import unittest
import urllib.request

from docker_network_fixture import Observer, observe


class PortOwnershipTest(unittest.TestCase):
    def test_outbound_has_exact_native_reply(self):
        observer = Observer()
        try:
            url = observe(observer.address, operation='outbound')['url']
            with urllib.request.urlopen(url, timeout=5) as response:
                self.assertEqual(response.read().decode(), observer.token)
            self.assertTrue(any(item.get('operation') == 'outbound-request' for item in observer.records))
        finally:
            observer.close()

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

    def test_ipv6_handoff_and_release(self):
        observer = Observer(ipv6_host='0:0:0:0:0:0:0:1')
        try:
            reservation = observe(observer.address, operation='allocate', ipv6=True)
            self.assertEqual(reservation['host'], '::1')
            port = reservation['port']
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                with socket.socket(socket.AF_INET6, kind) as connection:
                    with self.assertRaises(OSError) as error:
                        connection.bind(('::1', port))
                    self.assertEqual(error.exception.errno, errno.EADDRINUSE)
            observe(observer.address, operation='handoff', port=port, ipv6=True)
            observe(observer.address, operation='released', port=port, ipv6=True)
            self.assertFalse(observer.reservations)
            port = observe(observer.address, operation='allocate', ipv6=True)['port']
        finally:
            observer.close()
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with socket.socket(socket.AF_INET6, kind) as connection:
                connection.bind(('::1', port))

    def test_ipv6_observer_rejects_other_families(self):
        with self.assertRaises(ValueError):
            Observer(ipv6_host='127.0.0.1')


if __name__ == '__main__':
    unittest.main()

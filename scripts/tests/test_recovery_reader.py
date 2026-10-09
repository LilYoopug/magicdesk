"""Recovery conversion contracts; no mounts, network or Linux environment needed."""
import io
import stat
import struct
import subprocess
import tarfile
import types
import unittest
from unittest.mock import patch
import zlib
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'install_linux.sh'


class Node:
    subvolume = types.SimpleNamespace(objectid=5)
    uid, gid, mtime_ns, atime_ns = 1000, 1001, 123456789123456789, -500000000

    def __init__(self, inum, mode, data=b'', children=(), link=''):
        self.inum, self.mode, self.data = inum, mode, data
        self.entries, self.link, self.size = children, link, len(data)

    def is_dir(self):
        return stat.S_ISDIR(self.mode)

    def iterdir(self):
        return iter([('.', self), ('..', self), *self.entries])

    def open(self):
        return io.BytesIO(self.data)


class RecoveryReaderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # EVENT_WAIT: read-only script export; timeout rejects a hung shell.
        code = subprocess.check_output(['sh', str(SCRIPT), '--print-recovery-reader'], timeout=10)
        cls.reader = types.ModuleType('recovery_reader')
        exec(compile(code, 'embedded-recovery-reader', 'exec'), cls.reader.__dict__)

    def gpt(self, ranges=((34, 100, 'rootfs-A'),)):
        table = bytearray(128 * 128)
        for i, (start, end, name) in enumerate(ranges):
            table[i * 128] = 1
            struct.pack_into('<QQ', table, i * 128 + 32, start, end)
            encoded = name.encode('utf-16-le')
            table[i * 128 + 56:i * 128 + 56 + len(encoded)] = encoded
        header = bytearray(512)
        header[:8] = b'EFI PART'
        struct.pack_into('<I', header, 12, 92)
        struct.pack_into('<QQ', header, 40, 34, 1000)
        struct.pack_into('<QIII', header, 72, 2, 128, 128, zlib.crc32(table))
        struct.pack_into('<I', header, 16, zlib.crc32(header[:92]))
        return bytes(512) + header + table

    def test_gpt_offsets_and_checksums(self):
        data = self.gpt()
        parts, position = self.reader.partition_table(io.BytesIO(data))
        self.assertEqual((34 * 512, 67 * 512), parts['rootfs-A'])
        self.assertEqual(len(data), position)
        for offset in (512 + 40, 1024 + 70):
            bad = bytearray(data)
            bad[offset] ^= 1
            with self.assertRaisesRegex(ValueError, 'checksum'):
                self.reader.partition_table(io.BytesIO(bad))

    def test_gpt_rejects_overlap_duplicates_and_truncation(self):
        for ranges in (((34, 100, 'rootfs-A'), (90, 110, 'home')),
                       ((34, 100, 'rootfs-A'), (101, 110, 'rootfs-A')),
                       ((10, 100, 'rootfs-A'),)):
            with self.assertRaises(ValueError):
                self.reader.partition_table(io.BytesIO(self.gpt(ranges)))
        with self.assertRaisesRegex(ValueError, 'Truncated'):
            self.reader.partition_table(io.BytesIO(self.gpt()[:-1]))

    def test_tar_preserves_metadata_links_and_factory_defaults(self):
        executable = Node(2, stat.S_IFREG | 0o4751, b'program')
        directory = Node(1, stat.S_IFDIR | 0o750, children=[
            ('first', executable), ('second', executable),
            ('relative', Node(3, stat.S_IFLNK | 0o777, link='first'))])
        fallback = Node(4, stat.S_IFDIR | 0o755, children=[
            ('first', Node(5, stat.S_IFREG | 0o644, b'not copied')),
            ('default', Node(6, stat.S_IFREG | 0o600, b'factory'))])
        output = io.BytesIO()
        with patch.object(self.reader, 'xattrs', return_value=[]):
            with tarfile.open(fileobj=output, mode='w', format=tarfile.PAX_FORMAT) as tar:
                self.reader.export_tree(tar, directory, 'var', fallback)
        output.seek(0)
        with tarfile.open(fileobj=output) as tar:
            first, second = tar.getmember('var/first'), tar.getmember('var/second')
            self.assertEqual((1000, 1001, 0o4751), (first.uid, first.gid, first.mode))
            self.assertEqual('123456789.123456789', first.pax_headers['mtime'])
            self.assertEqual('-0.500000000', first.pax_headers['atime'])
            self.assertTrue(second.islnk())
            self.assertEqual('var/first', second.linkname)
            self.assertEqual(b'program', tar.extractfile(first).read())
            self.assertEqual(b'factory', tar.extractfile('var/default').read())
            self.assertEqual('first', tar.getmember('var/relative').linkname)
            self.assertEqual(5, len(tar.getmembers()))

    def test_storage_policy_is_omitted_but_security_attributes_survive(self):
        n = Node(1, stat.S_IFREG | 0o755)
        acl = struct.pack('<IHHI', 2, 1, 7, 0xffffffff)
        with patch.object(self.reader, 'xattrs', return_value=[
                ('btrfs.compression', b'zstd'), ('security.capability', b'\0\1\2'),
                ('system.posix_acl_access', acl)]):
            info = self.reader.metadata(n, 'program')
        self.assertEqual('AAEC', info.pax_headers['LIBARCHIVE.xattr.security.capability'])
        self.assertEqual('user::rwx', info.pax_headers['SCHILY.acl.access'])
        with patch.object(self.reader, 'xattrs', return_value=[('unknown.attr', b'x')]):
            with self.assertRaisesRegex(ValueError, 'Unsupported image attribute'):
                self.reader.metadata(n, 'program')


if __name__ == '__main__':
    unittest.main()

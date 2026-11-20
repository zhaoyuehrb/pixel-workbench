import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from PIL import Image

import vault


class FileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'original.bin'
        self.output = self.root / 'recovered.bin'
        self.cover = self.root / 'cover.jpg'
        self.hidden = self.root / 'packed.jpg'
        Image.new('RGB', (32, 24), (100, 170, 240)).save(self.cover)
        self.source.write_bytes(bytes(range(256)) * 4)
        self.password = 'test passphrase 🔑'

    def encode(self):
        vault.encode(self.source, self.cover, self.hidden, self.password)

    def assert_no_temporary(self):
        self.assertEqual(list(self.root.glob('.payload-*')), [])

    def test_roundtrip_formats_sizes_and_unchanged_cover(self):
        for image_format, extension in [('JPEG', '.jpg'), ('PNG', '.png')]:
            self.cover = self.root / ('cover' + extension)
            self.hidden = self.root / ('packed' + extension)
            Image.new('RGB', (32, 24), (100, 170, 240)).save(self.cover, format=image_format)
            for size in (0, 1, 256, vault.CHUNK_SIZE - 1, vault.CHUNK_SIZE, vault.CHUNK_SIZE + 1,
                         3 * vault.CHUNK_SIZE + 13):
                with self.subTest(format=image_format, size=size):
                    data = os.urandom(size)
                    self.source.write_bytes(data)
                    original_cover = self.cover.read_bytes()
                    self.encode()
                    with self.hidden.open('rb') as handle:
                        self.assertEqual(handle.read(len(original_cover)), original_cover)
                    self.assertEqual(self.cover.read_bytes(), original_cover)
                    self.assertEqual(self.hidden.stat().st_size, len(original_cover) + size + 60)
                    with Image.open(self.cover) as original, Image.open(self.hidden) as packed:
                        self.assertEqual(packed.format, image_format)
                        self.assertEqual(packed.size, original.size)
                        self.assertEqual(packed.tobytes(), original.tobytes())
                    vault.decode(self.hidden, self.output, self.password)
                    self.assertEqual(self.output.read_bytes(), data)
                    self.assertEqual(self.source.read_bytes(), data)
                    self.hidden.unlink()
                    self.output.unlink()
                    self.assert_no_temporary()

    def test_wrong_or_empty_password_no_output(self):
        self.encode()
        for password in ('wrong password', ''):
            with self.subTest(password=password), self.assertRaises(ValueError):
                vault.decode(self.hidden, self.output, password)
            self.assertFalse(self.output.exists())
            self.assert_no_temporary()
        self.hidden.unlink()
        with self.assertRaisesRegex(ValueError, 'empty'):
            vault.encode(self.source, self.cover, self.hidden, '')
        self.assertFalse(self.hidden.exists())

    def test_modified_input_rejected(self):
        self.encode()
        original = self.hidden.read_bytes()
        positions = (0, self.cover.stat().st_size, len(original) - vault.FOOTER.size - 1,
                     len(original) - vault.FOOTER.size, len(original) - 36, len(original) - 20,
                     len(original) - 8, len(original) - 1)
        for position in positions:
            with self.subTest(position=position):
                corrupted = bytearray(original)
                corrupted[position] ^= 1
                self.hidden.write_bytes(corrupted)
                with self.assertRaises(ValueError):
                    vault.decode(self.hidden, self.output, self.password)
                self.assertFalse(self.output.exists())
                self.assert_no_temporary()

    def test_truncation_trailing_garbage_and_invalid_lengths(self):
        self.encode()
        original = self.hidden.read_bytes()
        variants = [b'', b'x', original[:20], original[:-1], original[:-60], original + b'extra']
        magic, salt, nonce, _ = vault.FOOTER.unpack(original[-vault.FOOTER.size:])
        for length in (0, 15, len(original), 2**64 - 1):
            variants.append(original[:-vault.FOOTER.size] + vault.FOOTER.pack(magic, salt, nonce, length))
        for data in variants:
            with self.subTest(size=len(data)):
                self.hidden.write_bytes(data)
                with self.assertRaises(ValueError):
                    vault.decode(self.hidden, self.output, self.password)
                self.assertFalse(self.output.exists())
                self.assert_no_temporary()
        with self.assertRaisesRegex(ValueError, 'No supported'):
            vault.decode(self.cover, self.output, self.password)

    def test_outputs_never_replace_existing_files_or_inputs(self):
        self.encode()
        for target in (self.source, self.cover, self.hidden):
            before = target.read_bytes()
            with self.subTest(target=target), self.assertRaises(FileExistsError):
                vault.encode(self.source, self.cover, target, self.password)
            self.assertEqual(target.read_bytes(), before)
            with self.assertRaises(FileExistsError):
                vault.decode(self.hidden, target, self.password)
            self.assertEqual(target.read_bytes(), before)
            self.assert_no_temporary()

    def test_dangling_symlink_not_replaced(self):
        self.encode()
        self.output.symlink_to(self.root / 'missing')
        with self.assertRaises(FileExistsError):
            vault.decode(self.hidden, self.output, self.password)
        self.assertTrue(self.output.is_symlink())
        self.assert_no_temporary()

    def test_output_creation_race_preserves_other_file(self):
        self.encode()
        original_link = os.link

        def competing_link(source, target):
            Path(target).write_bytes(b'created by another process')
            return original_link(source, target)

        with patch('vault.os.link', side_effect=competing_link), self.assertRaises(FileExistsError):
            vault.decode(self.hidden, self.output, self.password)
        self.assertEqual(self.output.read_bytes(), b'created by another process')
        self.assert_no_temporary()

    def test_interrupted_writes_leave_no_output(self):
        for failure in (OSError('disk full'), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                with self.assertRaises(type(failure)):
                    with vault.new_output(self.output) as handle:
                        handle.write(b'partial data')
                        raise failure
                self.assertFalse(self.output.exists())
                self.assert_no_temporary()

    def test_invalid_cover_extension_and_size_limit(self):
        with self.assertRaisesRegex(ValueError, 'extension'):
            vault.encode(self.source, self.cover, self.root / 'wrong.png', self.password)
        with patch('vault.MAX_PAYLOAD_SIZE', 10), self.assertRaisesRegex(ValueError, 'limit'):
            self.encode()
        for name, data in [('not-an-image.jpg', b'not an image'), ('unsupported.gif', None)]:
            cover = self.root / name
            if data is None:
                Image.new('RGB', (2, 2)).save(cover)
            else:
                cover.write_bytes(data)
            with self.assertRaises((OSError, ValueError)):
                vault.encode(self.source, cover, self.hidden, self.password)
        self.assertFalse(self.hidden.exists())
        self.assert_no_temporary()

    def test_chunks_reject_truncation(self):
        with self.assertRaisesRegex(ValueError, 'truncated'):
            list(vault.chunks(io.BytesIO(b'short'), 100))

    def test_randomized_output(self):
        self.encode()
        first = self.hidden.read_bytes()
        self.hidden.unlink()
        self.encode()
        self.assertNotEqual(first, self.hidden.read_bytes())
        vault.decode(self.hidden, self.output, self.password)
        self.assertEqual(self.output.read_bytes(), self.source.read_bytes())

    def test_standalone_cli_from_another_directory(self):
        script = self.root / 'vault.py'
        shutil.copy(Path(vault.__file__), script)

        def run(*arguments, passwords):
            return subprocess.run([sys.executable, '-I', str(script), *arguments], cwd=self.root,
                                  input=passwords, text=True, capture_output=True)

        result = run('encode', self.source.name, self.cover.name, self.hidden.name,
                     passwords=self.password + '\n' + self.password + '\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        result = run('decode', self.hidden.name, self.output.name, passwords='wrong\n')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(self.output.exists())
        result = run('decode', self.hidden.name, self.output.name, passwords=self.password + '\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_bytes(), self.source.read_bytes())
        result = run('decode', self.hidden.name, self.output.name, passwords=self.password + '\n')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.hidden.unlink()
        result = run('encode', self.source.name, self.cover.name, self.hidden.name,
                     passwords='one\ntwo\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn('do not match', result.stderr)
        self.assertFalse(self.hidden.exists())
        result = run('decode', 'missing.jpg', 'recovered.bin', passwords='')
        self.assertEqual(result.returncode, 130, result.stderr)
        self.assert_no_temporary()


if __name__ == '__main__':
    unittest.main()

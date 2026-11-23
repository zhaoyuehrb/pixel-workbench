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


class ImageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'input.bin'
        self.image = self.root / 'image.png'
        self.output = self.root / 'output.bin'
        self.password = 'test passphrase'
        self.source.write_bytes(bytes(range(256)) * 4)

    def test_roundtrip_all_modes_and_empty_files(self):
        for channels, mode in vault.MODES.items():
            for data in (b'', bytes(range(256)) + os.urandom(512)):
                with self.subTest(channels=channels, size=len(data)):
                    self.source.write_bytes(data)
                    width, height = vault.encode(self.source, self.image, self.password, channels)
                    self.assertEqual(width * 9, height * 16)
                    with Image.open(self.image) as image:
                        self.assertEqual(image.format, 'PNG')
                        self.assertEqual(image.mode, mode)
                        self.assertTrue(image.tobytes().startswith(vault.MAGIC))
                    vault.decode(self.image, self.output, self.password)
                    self.assertEqual(self.output.read_bytes(), data)
                    self.assertEqual(self.source.read_bytes(), data)
                    self.image.unlink()
                    self.output.unlink()
        self.assertEqual(list(self.root.glob('.payload-*')), [])

    def test_recovery_after_rebuilding_png_from_pixels_only(self):
        original = os.urandom(4096)
        self.source.write_bytes(original)
        for channels in vault.MODES:
            with self.subTest(channels=channels):
                vault.encode(self.source, self.image, self.password, channels, ratio=(4, 3))
                with Image.open(self.image) as image:
                    self.assertEqual(image.width * 3, image.height * 4)
                    rebuilt = Image.frombytes(image.mode, image.size, image.tobytes())
                alternate = self.root / 'rebuilt.png'
                rebuilt.save(alternate, format='PNG', compress_level=0)
                rebuilt.close()
                vault.decode(alternate, self.output, self.password)
                self.assertEqual(self.output.read_bytes(), original)
                self.image.unlink()
                self.output.unlink()

    def test_dimensions_are_exact_and_minimal(self):
        for channels in vault.MODES:
            for ratio in [(16, 9), (4, 3), (1, 1), (32, 18), (9, 16)]:
                horizontal, vertical = vault.aspect(ratio)
                for size in [0, 1, 1024, 1_000_000_000]:
                    with self.subTest(channels=channels, ratio=ratio, size=size):
                        width, height = vault.dimensions(size, channels, ratio)
                        needed = size + vault.HEADER.size + vault.TAG_SIZE
                        self.assertEqual(width * vertical, height * horizontal)
                        self.assertGreaterEqual(width * height * channels, needed)
                        self.assertLess((width - horizontal) * (height - vertical) * channels, needed)
        for ratio in ['0:1', '-1:2', '1:0', 'abc', '1:2:3']:
            with self.assertRaises(ValueError):
                vault.dimensions(1, ratio=ratio)
        for channels in [0, 5, True]:
            with self.assertRaises(ValueError):
                vault.dimensions(1, channels)

    def test_wrong_password_and_changed_pixels_leave_no_output(self):
        vault.encode(self.source, self.image, self.password)
        with self.assertRaisesRegex(ValueError, 'Incorrect passphrase'):
            vault.decode(self.image, self.output, 'wrong password')
        with Image.open(self.image) as image:
            original, mode, size = image.tobytes(), image.mode, image.size
        for position in [0, vault.HEADER.size + 3, len(original) - 1]:
            with self.subTest(position=position):
                modified = bytearray(original)
                modified[position] ^= 1
                damaged = Image.frombytes(mode, size, bytes(modified))
                damaged.save(self.image)
                damaged.close()
                with self.assertRaises(ValueError):
                    vault.decode(self.image, self.output, self.password)
                self.assertFalse(self.output.exists())
        reshaped = Image.frombytes(mode, (size[1], size[0]), original)
        reshaped.save(self.image)
        reshaped.close()
        with self.assertRaisesRegex(ValueError, 'layout'):
            vault.decode(self.image, self.output, self.password)
        self.assertEqual(list(self.root.glob('.payload-*')), [])

    def test_preserve_existing_files_and_reject_invalid_inputs(self):
        vault.encode(self.source, self.image, self.password)
        before = self.image.read_bytes()
        with self.assertRaises(FileExistsError):
            vault.encode(self.source, self.image, self.password)
        self.assertEqual(self.image.read_bytes(), before)
        with self.assertRaises(FileExistsError):
            vault.decode(self.image, self.source, self.password)
        self.assertEqual(self.source.read_bytes(), bytes(range(256)) * 4)
        with self.assertRaisesRegex(ValueError, 'extension'):
            vault.encode(self.source, self.root / 'wrong.jpg', self.password)
        with self.assertRaisesRegex(ValueError, 'empty'):
            vault.encode(self.source, self.root / 'empty.png', '')
        with patch('vault.MAX_PIXELS', 10):
            with self.assertRaisesRegex(ValueError, 'limit'):
                vault.encode(self.source, self.root / 'too-large.png', self.password)
            with self.assertRaisesRegex(ValueError, 'limit'):
                vault.decode(self.image, self.output, self.password)
        self.assertFalse(self.output.exists())
        self.assertFalse((self.root / 'too-large.png').exists())
        self.assertEqual(list(self.root.glob('.payload-*')), [])

    def test_standalone_cli(self):
        shutil.copyfile(vault.__file__, self.root / 'vault.py')

        def run(*arguments, password=''):
            return subprocess.run([sys.executable, '-I', 'vault.py', *arguments], cwd=self.root,
                                  input=password, text=True, capture_output=True)

        result = run('plan', 'input.bin', '--channels', '1', '--ratio', '4:3')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('L:', result.stdout)
        result = run('encode', 'input.bin', 'image.png', '--channels', '3', '--ratio', '4:3',
                     password=self.password + '\n' + self.password + '\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        result = run('decode', 'image.png', 'output.bin', password=self.password + '\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_bytes(), self.source.read_bytes())
        result = run('encode', 'input.bin', 'different.png', password='one\ntwo\n')
        self.assertEqual(result.returncode, 1)
        self.assertFalse((self.root / 'different.png').exists())


if __name__ == '__main__':
    unittest.main()

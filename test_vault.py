import os
from pathlib import Path
import tempfile
import shutil
import subprocess
import sys
import unittest
from PIL import Image
from vault import encode, decode


class VaultTests(unittest.TestCase):
    def test_standalone_from_separate_folder(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            shutil.copy(Path(__file__).with_name('decrypter.py'), root)
            cover, source = root / 'cover.png', root / 'original.bin'
            Image.new('RGB', (128, 128), (100, 170, 240)).save(cover)
            for data in (b'', os.urandom(1024)):
                source.write_bytes(data)
                hidden, output = root / 'input.png', root / 'output.bin'
                encode(source, cover, hidden, 'test passphrase')
                for password, expected in [('wrong', 1), ('test passphrase', 0), ('test passphrase', 1)]:
                    result = subprocess.run(
                        [sys.executable, '-I', 'decrypter.py', 'input.png', 'output.bin'],
                        cwd=root, input=password + '\n', text=True, capture_output=True,
                    )
                    self.assertEqual(result.returncode, expected, result.stderr)
                    if output.exists():
                        self.assertEqual(output.read_bytes(), data)
                    else:
                        self.assertEqual(expected, 1)
                hidden.unlink()
                output.unlink()

    def test_roundtrip_and_rejections(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cover, source, hidden, recovered = [root / n for n in ('cover.png', 'data.bin', 'hidden.png', 'recovered.bin')]
            Image.new('RGB', (128, 128), (100, 170, 240)).save(cover)
            for data in (b'', bytes(range(256)) + os.urandom(1024)):
                source.write_bytes(data)
                encode(source, cover, hidden, 'test passphrase')
                decode(hidden, recovered, 'test passphrase')
                self.assertEqual(recovered.read_bytes(), data)
                with self.assertRaises(FileExistsError):
                    decode(hidden, recovered, 'test passphrase')
                recovered.unlink()
                with self.assertRaisesRegex(ValueError, 'Incorrect passphrase'):
                    decode(hidden, recovered, 'wrong passphrase')
                self.assertFalse(recovered.exists())
                with Image.open(hidden) as image:
                    raw = bytearray(image.tobytes())
                    self.assertLessEqual(max(abs(a-b) for a,b in zip(raw, Image.open(cover).tobytes())), 1)
                    raw[44 * 8] ^= 1
                    Image.frombytes('RGB', image.size, bytes(raw)).save(hidden)
                with self.assertRaisesRegex(ValueError, 'damaged image'):
                    decode(hidden, recovered, 'test passphrase')
                self.assertFalse(recovered.exists())
                hidden.unlink()
            source.write_bytes(os.urandom(7000))
            with self.assertRaisesRegex(ValueError, 'Use a larger photo'):
                encode(source, cover, hidden, 'test passphrase')
            with self.assertRaisesRegex(ValueError, 'No supported'):
                decode(cover, recovered, 'test passphrase')


if __name__ == '__main__':
    unittest.main()

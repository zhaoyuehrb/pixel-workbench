from pathlib import Path
import tempfile
import unittest
from PIL import Image
from covers import TIERS, capacity, choose
from vault import encode


class CoverTests(unittest.TestCase):
    def test_preset_boundaries(self):
        for index, (name, width, height) in enumerate(TIERS):
            limit = capacity(width, height)
            self.assertEqual(choose(limit)[0], name)
            if index + 1 < len(TIERS):
                self.assertEqual(choose(limit + 1)[0], TIERS[index + 1][0])
            else:
                with self.assertRaises(ValueError):
                    choose(limit + 1)

    def test_capacity_matches_encoder(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cover, source = root / 'cover.png', root / 'input.bin'
            Image.new('RGB', (32, 32)).save(cover)
            limit = capacity(32, 32)
            source.write_bytes(b'x' * limit)
            encode(source, cover, root / 'out.png', 'test')
            source.write_bytes(b'x' * (limit + 1))
            with self.assertRaisesRegex(ValueError, 'Use a larger photo'):
                encode(source, cover, root / 'too-large.png', 'test')


if __name__ == '__main__':
    unittest.main()

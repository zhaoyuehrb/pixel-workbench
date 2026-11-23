import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

from PIL import Image

import batch
import vault


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.images = self.root / 'images'
        self.output = self.root / 'restored'
        self.covers = self.root / 'covers'
        self.covers.mkdir()
        Image.new('RGB', (32, 24), (100, 170, 240)).save(self.covers / 'one.jpg')
        Image.new('RGB', (32, 24), (100, 170, 240)).save(self.covers / 'two.png')
        self.password = 'test password'
        self.limit = 2400

    def make(self, name='document.bin', data=None, **kwargs):
        data = os.urandom(10000) if data is None else data
        source = self.root / name
        source.write_bytes(data)
        result = batch.pack(source, self.covers, self.images, self.password,
                            max_bytes=self.limit, **kwargs)
        return result, data

    def restored(self, result):
        return self.output / f'{result["id"]}-{result["name"]}'

    def assert_clean(self):
        self.assertEqual(list(self.root.rglob('.parts-*')), [])
        self.assertEqual(list(self.root.rglob('.payload-*')), [])

    def change_metadata(self, path, change):
        part = batch.read_part(path)
        metadata = dict(part.metadata)
        change(metadata)
        raw = json.dumps(metadata, separators=(',', ':')).encode()
        original = path.read_bytes()
        body = original[:len(original) - batch.FOOTER.size - len(part.raw_metadata)]
        path.write_bytes(body + raw + batch.FOOTER.pack(batch.MAGIC, len(raw)))

    def test_mixed_unordered_renamed_files_and_byte_limits(self):
        first, a = self.make('one.bin')
        second, b = self.make('two.bin', data=os.urandom(7000))
        third, c = self.make('three.bin', data=b'')
        paths = list(self.images.iterdir())
        random.Random(42).shuffle(paths)
        originals = {}
        for cover in self.covers.iterdir():
            with Image.open(cover) as image:
                originals[image.format] = image.tobytes()
        for index, path in enumerate(paths):
            self.assertLessEqual(path.stat().st_size, self.limit)
            with Image.open(path) as image:
                self.assertEqual(image.tobytes(), originals[image.format])
            path.rename(self.images / f'unknown-{index}.data')
        (self.images / 'ordinary.txt').write_text('unrelated')
        shutil.copyfile(self.covers / 'one.jpg', self.images / 'ordinary.jpg')
        groups, issues = batch.scan(self.images)
        self.assertEqual(len(groups), 3)
        self.assertFalse(issues)
        self.assertTrue(all(group.complete for group in groups))
        result = batch.unpack(self.images, self.output, self.password)
        self.assertFalse(result['issues'])
        self.assertEqual(len(result['restored']), 3)
        for packed, data in [(first, a), (second, b), (third, c)]:
            self.assertEqual(self.restored(packed).read_bytes(), data)
        self.assert_clean()

    def test_boundaries_and_single_part(self):
        for size in (0, 1, 512, 1024, 2048, 10000):
            with self.subTest(size=size):
                packed, data = self.make(f'input-{size}.bin', data=os.urandom(size))
                one = self.root / f'set-{size}'
                one.mkdir()
                for path in packed['parts']:
                    shutil.move(path, one / path.name)
                result = batch.unpack(one, self.output, self.password)
                self.assertFalse(result['issues'])
                self.assertEqual(self.restored(packed).read_bytes(), data)
        self.assert_clean()

    def test_missing_parts_do_not_block_other_sets(self):
        broken, _ = self.make('missing.bin')
        ready, data = self.make('ready.bin', data=b'ready')
        broken['parts'][1].unlink()
        result = batch.unpack(self.images, self.output, self.password)
        self.assertEqual(len(result['restored']), 1)
        self.assertTrue(any('missing parts 2' in issue for issue in result['issues']))
        self.assertFalse(self.restored(broken).exists())
        self.assertEqual(self.restored(ready).read_bytes(), data)
        self.assert_clean()

    def test_streaming_across_part_and_buffer_boundaries(self):
        data = os.urandom(5 * vault.CHUNK_SIZE + 19)
        source = self.root / 'large.bin'
        source.write_bytes(data)
        limit = 2 * vault.CHUNK_SIZE
        packed = batch.pack(source, self.covers, self.images, self.password, max_bytes=limit)
        self.assertGreater(len(packed['parts']), 1)
        self.assertTrue(all(path.stat().st_size <= limit for path in packed['parts']))
        result = batch.unpack(self.images, self.output, self.password)
        self.assertFalse(result['issues'])
        self.assertEqual(self.restored(packed).read_bytes(), data)
        self.assert_clean()

    def test_duplicate_copies_and_damaged_duplicate(self):
        packed, data = self.make()
        first = packed['parts'][0]
        duplicate = first.with_name('z-copy.jpg')
        shutil.copyfile(first, duplicate)
        raw = bytearray(first.read_bytes())
        raw[batch.read_part(first).cover_size] ^= 1
        first.write_bytes(raw)
        result = batch.unpack(self.images, self.output, self.password)
        self.assertFalse(result['issues'])
        self.assertEqual(self.restored(packed).read_bytes(), data)
        self.assert_clean()

    def test_same_names_in_different_sets_are_kept_separate(self):
        first, a = self.make(data=b'first')
        second, b = self.make(data=b'second')
        result = batch.unpack(self.images, self.output, self.password)
        self.assertFalse(result['issues'])
        self.assertNotEqual(first['id'], second['id'])
        self.assertEqual(self.restored(first).read_bytes(), a)
        self.assertEqual(self.restored(second).read_bytes(), b)

    def test_existing_output_is_preserved(self):
        packed, _ = self.make()
        self.output.mkdir()
        self.restored(packed).write_bytes(b'keep this')
        result = batch.unpack(self.images, self.output, self.password)
        self.assertFalse(result['restored'])
        self.assertTrue(result['issues'])
        self.assertEqual(self.restored(packed).read_bytes(), b'keep this')
        self.assert_clean()

    def test_wrong_password_does_not_publish_output(self):
        packed, _ = self.make()
        result = batch.unpack(self.images, self.output, 'wrong')
        self.assertFalse(result['restored'])
        self.assertTrue(any('Incorrect passphrase' in issue for issue in result['issues']))
        self.assertFalse(self.restored(packed).exists())
        self.assert_clean()

    def test_changed_parts_are_rejected(self):
        packed, _ = self.make()
        path = packed['parts'][0]
        part = batch.read_part(path)
        original = path.read_bytes()
        for position in (0, part.cover_size, part.cover_size + part.metadata['length']):
            with self.subTest(position=position):
                raw = bytearray(original)
                raw[position] ^= 1
                path.write_bytes(raw)
                result = batch.unpack(self.images, self.output, self.password)
                self.assertTrue(result['issues'])
                self.assertFalse(self.restored(packed).exists())
                self.assert_clean()
        path.write_bytes(original)
        path.write_bytes(original[:-1])
        result = batch.unpack(self.images, self.output, self.password)
        self.assertTrue(result['issues'])
        self.assertFalse(self.restored(packed).exists())

    def test_changed_metadata_is_rejected(self):
        packed, _ = self.make(data=b'test')
        path = packed['parts'][0]
        self.change_metadata(path, lambda meta: meta.update({'name': 'different.bin'}))
        result = batch.unpack(self.images, self.output, self.password)
        self.assertFalse(result['restored'])
        self.assertTrue(result['issues'])
        self.assert_clean()

    def test_conflicting_set_metadata_is_rejected(self):
        packed, _ = self.make()
        self.change_metadata(packed['parts'][0], lambda meta: meta.update({'sha256': '0' * 64}))
        result = batch.unpack(self.images, self.output, self.password)
        self.assertFalse(result['restored'])
        self.assertTrue(any('Conflicting' in issue for issue in result['issues']))
        self.assert_clean()

    def test_unsafe_names_are_rejected(self):
        source = self.root / 'source.bin'
        source.write_bytes(b'test')
        for name in ('../escape.zip', '..', 'C:\\escape.zip', 'CON', 'bad\nname', 'trailing.', 'trailing '):
            with self.subTest(name=name), self.assertRaises(ValueError):
                batch.pack(source, self.covers, self.images, self.password, max_bytes=self.limit, name=name)

    def test_received_path_traversal_is_rejected(self):
        packed, _ = self.make(data=b'test')
        self.change_metadata(packed['parts'][0], lambda meta: meta.update({'name': '../outside.bin'}))
        result = batch.unpack(self.images, self.output, self.password)
        self.assertFalse(result['restored'])
        self.assertTrue(result['issues'])
        self.assertFalse((self.root / 'outside.bin').exists())

    def test_failed_pack_leaves_no_parts(self):
        source = self.root / 'original.bin'
        source.write_bytes(b'unchanged')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            batch.pack(source, self.covers, self.images, self.password,
                       max_bytes=self.limit, sha256='0' * 64)
        self.assertFalse(list(self.images.iterdir()))
        for password, limit in [('', self.limit), (self.password, 10), (self.password, -1)]:
            with self.assertRaises(ValueError):
                batch.pack(source, self.covers, self.images, password, max_bytes=limit)
        self.assert_clean()

    def test_explicit_name_and_checksum(self):
        data = b'test file'
        source = self.root / 'source.bin'
        source.write_bytes(data)
        packed = batch.pack(source, self.covers, self.images, self.password,
                            max_bytes=self.limit, name='renamed.zip', sha256=hashlib.sha256(data).hexdigest())
        result = batch.unpack(self.images, self.output, self.password)
        self.assertFalse(result['issues'])
        self.assertEqual(self.restored(packed).read_bytes(), data)
        self.assertTrue(self.restored(packed).name.endswith('-renamed.zip'))

    def test_cli_on_another_machine_layout(self):
        isolated = self.root / 'isolated'
        isolated.mkdir()
        for module in [vault, batch]:
            shutil.copyfile(module.__file__, isolated / Path(module.__file__).name)
        (isolated / 'input.bin').write_bytes(os.urandom(10000))
        shutil.copyfile(self.covers / 'one.jpg', isolated / 'cover.jpg')

        def run(*arguments, password=''):
            return subprocess.run([sys.executable, 'vault.py', *arguments], cwd=isolated,
                                  input=password, text=True, capture_output=True)

        result = run('pack', 'input.bin', 'cover.jpg', 'incoming', '--max-bytes', str(self.limit),
                     password=self.password + '\n' + self.password + '\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        for index, path in enumerate((isolated / 'incoming').iterdir()):
            path.rename(path.with_name(f'{100 - index}.jpg'))
        result = run('inspect', 'incoming')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('complete', result.stdout)
        result = run('unpack', 'incoming', 'restored', password=self.password + '\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        output = next((isolated / 'restored').iterdir())
        self.assertEqual(output.read_bytes(), (isolated / 'input.bin').read_bytes())
        first = next((isolated / 'incoming').iterdir())
        first.unlink()
        result = run('inspect', 'incoming')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('Missing', result.stderr)


if __name__ == '__main__':
    unittest.main()

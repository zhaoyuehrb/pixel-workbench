"""Local batch utility."""
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import tempfile

from PIL import Image
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from vault import CHUNK_SIZE, MAX_PAYLOAD_SIZE, chunks, derive, new_output

MAGIC = b'PWBSET01'
FOOTER = struct.Struct('>8sI')
TAG_SIZE = 16
MAX_METADATA = 16384
MAX_PARTS = 100000
DEFAULT_MAX_BYTES = 950_000_000
COMMON = ('version', 'id', 'name', 'size', 'sha256', 'count', 'capacity', 'salt', 'prefix')
FIELDS = set(COMMON) | {'index', 'length'}


@dataclass
class Part:
    path: Path
    metadata: dict
    raw_metadata: bytes
    cover_size: int


@dataclass
class Group:
    metadata: dict
    parts: dict = field(default_factory=dict)
    problems: list = field(default_factory=list)

    @property
    def missing(self):
        return [i for i in range(self.metadata['count']) if i not in self.parts]

    @property
    def complete(self):
        return not self.problems and not self.missing


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _name(value):
    if not isinstance(value, str) or not value or len(value.encode('utf-8')) > 180:
        raise ValueError('Invalid file name.')
    if value in {'.', '..'} or value.endswith(('.', ' ')) or re.search(r'[<>:"/\\|?*\x00-\x1f\x7f]', value):
        raise ValueError('Invalid file name.')
    reserved = {'CON', 'PRN', 'AUX', 'NUL'} | {f'{p}{n}' for p in ('COM', 'LPT') for n in range(1, 10)}
    if value.split('.')[0].upper() in reserved:
        raise ValueError('Invalid file name.')
    return value


def _hex(value, length):
    return isinstance(value, str) and re.fullmatch(f'[0-9a-f]{{{length}}}', value) is not None


def _validate(metadata):
    if not isinstance(metadata, dict) or set(metadata) != FIELDS:
        raise ValueError('Invalid set information.')
    if type(metadata['version']) is not int or metadata['version'] != 1:
        raise ValueError('Unsupported version.')
    _name(metadata['name'])
    for key, length in [('id', 32), ('sha256', 64), ('salt', 32), ('prefix', 16)]:
        if not _hex(metadata[key], length):
            raise ValueError(f'Invalid {key}.')
    for key in ('size', 'count', 'capacity', 'index', 'length'):
        if type(metadata[key]) is not int:
            raise ValueError('Invalid set lengths.')
    size, capacity, count, index = (metadata[k] for k in ('size', 'capacity', 'count', 'index'))
    if not 0 <= size <= 2**63 - 1 or not 1 <= capacity <= MAX_PAYLOAD_SIZE:
        raise ValueError('Invalid set lengths.')
    if not 1 <= count <= MAX_PARTS or count != max(1, (size + capacity - 1) // capacity):
        raise ValueError('Invalid part count.')
    if not 0 <= index < count or metadata['length'] != min(capacity, size - index * capacity):
        raise ValueError('Invalid part position.')


def read_part(path):
    path = Path(path)
    with path.open('rb') as handle:
        size = os.fstat(handle.fileno()).st_size
        if size < FOOTER.size:
            return None
        handle.seek(-FOOTER.size, os.SEEK_END)
        tail = handle.read(FOOTER.size)
        if len(tail) != FOOTER.size:
            raise ValueError('Truncated file.')
        magic, length = FOOTER.unpack(tail)
        if magic != MAGIC:
            return None
        if not 1 <= length <= MAX_METADATA or length + FOOTER.size + TAG_SIZE >= size:
            raise ValueError('Invalid set footer.')
        handle.seek(-FOOTER.size - length, os.SEEK_END)
        raw = handle.read(length)
        try:
            metadata = json.loads(raw)
        except (UnicodeError, ValueError, RecursionError):
            raise ValueError('Invalid set information.') from None
        _validate(metadata)
        cover_size = size - FOOTER.size - length - TAG_SIZE - metadata['length']
        if cover_size <= 0:
            raise ValueError('Invalid part length.')
        return Part(path, metadata, raw, cover_size)


def scan(source):
    source = Path(source)
    if not source.exists():
        raise FileNotFoundError(source)
    files = [source] if source.is_file() else sorted(source.rglob('*'))
    groups, issues = {}, []
    for path in files:
        if not path.is_file() or path.is_symlink() or any(p.startswith(('.parts-', '.payload-')) for p in path.parts):
            continue
        try:
            part = read_part(path)
        except (OSError, ValueError) as error:
            issues.append(f'{path}: {error}')
            continue
        if part is None:
            continue
        metadata = part.metadata
        group = groups.setdefault(metadata['id'], Group(metadata))
        if any(group.metadata[key] != metadata[key] for key in COMMON):
            group.problems.append(f'Conflicting set information: {path}')
            continue
        group.parts.setdefault(metadata['index'], []).append(part)
    return [groups[key] for key in sorted(groups)], issues


def _covers(source):
    source = Path(source)
    paths = sorted(p for p in source.iterdir() if p.suffix.lower() in {'.jpg', '.jpeg', '.png'}) if source.is_dir() else [source]
    result = []
    for path in paths:
        with path.open('rb') as handle:
            with Image.open(handle) as image:
                kind = image.format
                image.verify()
            if kind not in {'JPEG', 'PNG'}:
                raise ValueError('Unsupported image format.')
            handle.seek(0)
            digest = hashlib.file_digest(handle, 'sha256').digest()
            result.append((path, path.stat().st_size, '.jpg' if kind == 'JPEG' else '.png', digest))
    if not result:
        raise ValueError('No usable images found.')
    return result


def pack(source, covers, output, password, max_bytes=DEFAULT_MAX_BYTES, name=None, sha256=None, progress=None):
    source, output = Path(source), Path(output)
    if not password:
        raise ValueError('Passphrase must not be empty.')
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError('Invalid byte limit.')
    filename = _name(name if name is not None else source.name)
    images = _covers(covers)
    size = source.stat().st_size
    if not 0 <= size <= 2**63 - 1:
        raise ValueError('Input exceeds the supported size limit.')
    if sha256 is None:
        with source.open('rb') as handle:
            sha256 = hashlib.file_digest(handle, 'sha256').hexdigest()
    if not _hex(sha256, 64):
        raise ValueError('Invalid file checksum.')
    common = {'version': 1, 'id': os.urandom(16).hex(), 'name': filename, 'size': size,
              'sha256': sha256, 'salt': os.urandom(16).hex(), 'prefix': os.urandom(8).hex()}
    template = {**common, 'count': MAX_PARTS, 'capacity': max_bytes, 'index': MAX_PARTS - 1, 'length': max_bytes}
    capacity = min(MAX_PAYLOAD_SIZE, max_bytes - max(x[1] for x in images) - TAG_SIZE - FOOTER.size - len(_json(template)))
    if capacity <= 0:
        raise ValueError('Byte limit is too small for these images.')
    count = max(1, (size + capacity - 1) // capacity)
    if count > MAX_PARTS:
        raise ValueError('Input requires too many parts.')
    common.update({'count': count, 'capacity': capacity})
    key = derive(password, bytes.fromhex(common['salt']))
    output.mkdir(parents=True, exist_ok=True)
    published = []
    with tempfile.TemporaryDirectory(prefix='.parts-', dir=output) as temporary:
        staged = []
        digest = hashlib.sha256()
        done = 0
        try:
            with source.open('rb') as data:
                for index in range(count):
                    cover, cover_size, extension, cover_digest = images[index % len(images)]
                    length = min(capacity, size - done)
                    raw_metadata = _json({**common, 'index': index, 'length': length})
                    if len(raw_metadata) > MAX_METADATA:
                        raise ValueError('Set information is too large.')
                    nonce = bytes.fromhex(common['prefix']) + struct.pack('>I', index)
                    encoder = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
                    encoder.authenticate_additional_data(raw_metadata + cover_digest)
                    path = Path(temporary) / f'{common["id"]}-{index + 1:06d}{extension}'
                    with path.open('xb') as destination, cover.open('rb') as image:
                        actual_cover = hashlib.sha256()
                        for block in chunks(image, cover_size):
                            destination.write(block)
                            actual_cover.update(block)
                        if image.read(1) or actual_cover.digest() != cover_digest:
                            raise ValueError('Image changed while being read.')
                        for block in chunks(data, length):
                            digest.update(block)
                            destination.write(encoder.update(block))
                            done += len(block)
                            if progress:
                                progress(done, size)
                        destination.write(encoder.finalize())
                        destination.write(encoder.tag)
                        destination.write(raw_metadata)
                        destination.write(FOOTER.pack(MAGIC, len(raw_metadata)))
                    if path.stat().st_size > max_bytes:
                        raise ValueError('Output exceeds the byte limit.')
                    staged.append(path)
                if data.read(1) or digest.hexdigest() != sha256:
                    raise ValueError('Input changed while being read or checksum does not match.')
            for path in staged:
                target = output / path.name
                os.link(path, target)
                published.append((path, target))
        except BaseException:
            for staged_path, target in published:
                if target.exists() and os.path.samefile(staged_path, target):
                    target.unlink()
            raise
    return {'id': common['id'], 'name': filename, 'size': size, 'sha256': sha256,
            'parts': [target for _, target in published], 'max_bytes': max_bytes}


def _read(part, key, write):
    metadata = part.metadata
    nonce = bytes.fromhex(metadata['prefix']) + struct.pack('>I', metadata['index'])
    with part.path.open('rb') as image:
        digest = hashlib.sha256()
        for block in chunks(image, part.cover_size):
            digest.update(block)
        image.seek(part.cover_size + metadata['length'])
        tag = image.read(TAG_SIZE)
        decoder = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decoder.authenticate_additional_data(part.raw_metadata + digest.digest())
        image.seek(part.cover_size)
        for block in chunks(image, metadata['length']):
            write(decoder.update(block))
        try:
            write(decoder.finalize())
        except InvalidTag:
            raise ValueError('Incorrect passphrase or damaged part.') from None


def recover(group, password, destination, progress=None):
    if not group.complete:
        raise ValueError('Set is incomplete or has conflicting information.')
    metadata = group.metadata
    key = derive(password, bytes.fromhex(metadata['salt']))
    digest, done = hashlib.sha256(), 0

    def write(block):
        nonlocal done
        written = destination.write(block)
        if written != len(block):
            raise OSError('Incomplete output write.')
        digest.update(block)
        done += len(block)
        if progress:
            progress(done, metadata['size'])

    for index in range(metadata['count']):
        candidates = group.parts[index]
        selected = candidates[0]
        if len(candidates) > 1:
            for candidate in candidates:
                try:
                    _read(candidate, key, lambda block: None)
                    selected = candidate
                    break
                except (OSError, ValueError):
                    pass
            else:
                raise ValueError(f'No valid copy of part {index + 1}.')
        _read(selected, key, write)
    if done != metadata['size'] or digest.hexdigest() != metadata['sha256']:
        raise ValueError('Recovered file checksum does not match.')
    return digest.hexdigest()


def unpack(source, output, password, progress=None):
    groups, issues = scan(source)
    if not groups:
        issues.append('No supported sets found.')
    output = Path(output)
    restored = []
    for group in groups:
        metadata = group.metadata
        if not group.complete:
            issues.extend(group.problems)
            if group.missing:
                issues.append(f'{metadata["name"]} ({metadata["id"]}): missing parts ' + missing_text(group))
            continue
        try:
            output.mkdir(parents=True, exist_ok=True)
            target = output / f'{metadata["id"]}-{metadata["name"]}'
            with new_output(target) as destination:
                recover(group, password, destination, progress)
            restored.append({'id': metadata['id'], 'name': metadata['name'], 'output': str(target), 'sha256': metadata['sha256']})
        except (OSError, ValueError) as error:
            issues.append(f'{metadata["name"]} ({metadata["id"]}): {error}')
    return {'restored': restored, 'issues': issues}


def missing_text(group):
    numbers = [index + 1 for index in group.missing]
    ranges = []
    for number in numbers:
        if ranges and number == ranges[-1][1] + 1:
            ranges[-1][1] = number
        else:
            ranges.append([number, number])
    return ', '.join(str(start) if start == end else f'{start}-{end}' for start, end in ranges)

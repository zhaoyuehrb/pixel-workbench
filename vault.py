#!/usr/bin/env python3
"""Local image utility."""
import argparse
from contextlib import contextmanager
import getpass
from math import gcd, isqrt
import os
from pathlib import Path
import struct
import sys
import tempfile
import warnings

from PIL import Image
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b'PWRAST01'
VERSION = 1
HEADER = struct.Struct('>8sBBII16s12sQ')
MODES = {1: 'L', 2: 'LA', 3: 'RGB', 4: 'RGBA'}
TAG_SIZE = 16
CHUNK_SIZE = 1024 * 1024
MAX_PIXELS = Image.MAX_IMAGE_PIXELS
MAX_PAYLOAD_SIZE = (1 << 36) - 32


def derive(password, salt):
    if not password:
        raise ValueError('Passphrase must not be empty.')
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode('utf-8'))


def aspect(value):
    try:
        if isinstance(value, str):
            fields = value.split(':')
            if len(fields) != 2:
                raise ValueError
            width, height = (int(field) for field in fields)
        else:
            width, height = value
        if type(width) is not int or type(height) is not int or width <= 0 or height <= 0:
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError('Ratio must contain two positive integers, such as 16:9.') from None
    divisor = gcd(width, height)
    return width // divisor, height // divisor


def dimensions(size, channels=3, ratio=(16, 9)):
    if type(size) is not int or not 0 <= size <= MAX_PAYLOAD_SIZE:
        raise ValueError('Input exceeds the supported size limit.')
    if type(channels) is not int or channels not in MODES:
        raise ValueError('Channel count must be 1, 2, 3, or 4.')
    horizontal, vertical = aspect(ratio)
    required = (size + HEADER.size + TAG_SIZE + channels - 1) // channels
    units = (required + horizontal * vertical - 1) // (horizontal * vertical)
    scale = isqrt(units - 1) + 1
    width, height = horizontal * scale, vertical * scale
    if width > 2**31 - 1 or height > 2**31 - 1:
        raise ValueError('Dimensions exceed the supported image size.')
    return width, height


def chunks(handle, count):
    while count:
        block = handle.read(min(count, CHUNK_SIZE))
        if not block:
            raise ValueError('Input was truncated or changed while being read.')
        count -= len(block)
        yield block


@contextmanager
def new_output(path):
    path = Path(path)
    if os.path.lexists(path):
        raise FileExistsError(f'Output already exists: {path}')
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.payload-', delete=False) as handle:
        temporary = Path(handle.name)
        try:
            yield handle
            handle.close()
            os.link(temporary, path)
        finally:
            handle.close()
            temporary.unlink(missing_ok=True)


def encode(source, output, password, channels=3, ratio=(16, 9)):
    output = Path(output)
    if os.path.lexists(output):
        raise FileExistsError(f'Output already exists: {output}')
    if output.suffix.lower() != '.png':
        raise ValueError('Output must use the .png extension.')
    if not password:
        raise ValueError('Passphrase must not be empty.')
    with open(source, 'rb') as data:
        before = os.fstat(data.fileno())
        size = before.st_size
        width, height = dimensions(size, channels, ratio)
        if width * height > MAX_PIXELS:
            raise ValueError(f'Resolution exceeds the supported limit of {MAX_PIXELS:,} pixels.')
        salt, nonce = os.urandom(16), os.urandom(12)
        header = HEADER.pack(MAGIC, VERSION, channels, width, height, salt, nonce, size)
        encoder = Cipher(algorithms.AES(derive(password, salt)), modes.GCM(nonce)).encryptor()
        encoder.authenticate_additional_data(header)
        raw = bytearray(width * height * channels)
        raw[:HEADER.size] = header
        position = HEADER.size
        for block in chunks(data, size):
            result = encoder.update(block)
            raw[position:position + len(result)] = result
            position += len(result)
        final = encoder.finalize()
        raw[position:position + len(final)] = final
        position += len(final)
        raw[position:position + TAG_SIZE] = encoder.tag
        after = os.fstat(data.fileno())
        if data.read(1) or after.st_size != size or after.st_mtime_ns != before.st_mtime_ns:
            raise ValueError('Input changed while being read.')
    image = Image.frombytes(MODES[channels], (width, height), bytes(raw))
    try:
        with new_output(output) as destination:
            image.save(destination, format='PNG', compress_level=6)
    finally:
        image.close()
    return width, height


def decode(source, output, password):
    if os.path.lexists(output):
        raise FileExistsError(f'Output already exists: {output}')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            with Image.open(source) as image:
                if image.format != 'PNG' or image.mode not in MODES.values():
                    raise ValueError('Unsupported image format or mode.')
                width, height = image.size
                if width * height > MAX_PIXELS:
                    raise ValueError(f'Resolution exceeds the supported limit of {MAX_PIXELS:,} pixels.')
                channels = len(image.getbands())
                if width * height * channels < HEADER.size + TAG_SIZE:
                    raise ValueError('No supported data found.')
                raw = image.tobytes()
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise ValueError('Resolution exceeds the supported pixel limit.') from None
    header = raw[:HEADER.size]
    magic, version, stored_channels, stored_width, stored_height, salt, nonce, size = HEADER.unpack(header)
    if magic != MAGIC or version != VERSION:
        raise ValueError('No supported data found.')
    if (stored_channels, stored_width, stored_height) != (channels, width, height):
        raise ValueError('Image layout does not match.')
    end = HEADER.size + size
    if size > MAX_PAYLOAD_SIZE or end + TAG_SIZE > len(raw):
        raise ValueError('Invalid data length.')
    if any(memoryview(raw)[end + TAG_SIZE:]):
        raise ValueError('Invalid image padding.')
    key = derive(password, salt)
    decoder = Cipher(algorithms.AES(key), modes.GCM(nonce, raw[end:end + TAG_SIZE])).decryptor()
    decoder.authenticate_additional_data(header)
    with new_output(output) as destination:
        position = HEADER.size
        while position < end:
            stop = min(position + CHUNK_SIZE, end)
            destination.write(decoder.update(memoryview(raw)[position:stop]))
            position = stop
        try:
            destination.write(decoder.finalize())
        except InvalidTag:
            raise ValueError('Incorrect passphrase or damaged image.') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    enc = commands.add_parser('encode', help='Create an image.')
    enc.add_argument('file', type=Path)
    enc.add_argument('output', type=Path)
    enc.add_argument('--channels', type=int, choices=MODES, default=3)
    enc.add_argument('--ratio', type=aspect, default=(16, 9))
    dec = commands.add_parser('decode', help='Restore a file.')
    dec.add_argument('image', type=Path)
    dec.add_argument('output', type=Path)
    plan = commands.add_parser('plan', help='Show dimensions.')
    plan.add_argument('file', type=Path)
    plan.add_argument('--channels', type=int, choices=MODES, default=3)
    plan.add_argument('--ratio', type=aspect, default=(16, 9))
    args = parser.parse_args()
    try:
        if args.command == 'plan':
            size = args.file.stat().st_size
            width, height = dimensions(size, args.channels, args.ratio)
            print(f'{MODES[args.channels]}: {width} x {height}')
            print(f'Input: {size:,} bytes; capacity: {width * height * args.channels - HEADER.size - TAG_SIZE:,} bytes')
            if width * height > MAX_PIXELS:
                print(f'Above the supported limit of {MAX_PIXELS:,} pixels.')
            return 0
        password = getpass.getpass('Passphrase: ')
        if args.command == 'encode':
            if password != getpass.getpass('Confirm passphrase: '):
                raise ValueError('Passphrases do not match.')
            width, height = encode(args.file, args.output, password, args.channels, args.ratio)
            print(f'Saved {args.output} ({width} x {height}, {MODES[args.channels]})')
        else:
            decode(args.image, args.output, password)
            print(f'Saved {args.output}')
    except (OSError, ValueError) as error:
        print(f'Error: {error}', file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print('\nCancelled.', file=sys.stderr)
        return 130
    return 0


if __name__ == '__main__':
    sys.exit(main())

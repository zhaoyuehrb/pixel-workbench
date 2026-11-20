#!/usr/bin/env python3
"""Local file utility."""
import argparse
from contextlib import contextmanager
import getpass
import hashlib
import os
from pathlib import Path
import struct
import sys
import tempfile

from PIL import Image
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b'PWPAYL01'
FOOTER = struct.Struct('>8s16s12sQ')
TAG_SIZE = 16
CHUNK_SIZE = 1024 * 1024
MAX_PAYLOAD_SIZE = (1 << 36) - 32


def derive(password, salt):
    if not password:
        raise ValueError('Passphrase must not be empty.')
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode('utf-8'))


def chunks(handle, count):
    """Read exactly count bytes in bounded chunks; reject truncated inputs."""
    while count:
        block = handle.read(min(count, CHUNK_SIZE))
        if not block:
            raise ValueError('Input was truncated or changed while being read.')
        count -= len(block)
        yield block


@contextmanager
def new_output(path):
    """Publish a completed file atomically without replacing an existing path."""
    path = Path(path)
    if os.path.lexists(path):
        raise FileExistsError(f'Output already exists: {path}')
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.payload-', delete=False) as handle:
        temporary = Path(handle.name)
        try:
            yield handle
            handle.close()
            # Linking is atomic and refuses to replace files or dangling symlinks.
            os.link(temporary, path)
        finally:
            handle.close()
            temporary.unlink(missing_ok=True)


def encode(source, cover, output, password):
    output = Path(output)
    if os.path.lexists(output):
        raise FileExistsError(f'Output already exists: {output}')
    with open(source, 'rb') as payload, open(cover, 'rb') as image:
        with Image.open(image) as check:
            image_format = check.format
            check.verify()
        extensions = {'JPEG': {'.jpg', '.jpeg'}, 'PNG': {'.png'}}
        if image_format not in extensions:
            raise ValueError('Cover must be a JPEG or PNG image.')
        if output.suffix.lower() not in extensions[image_format]:
            raise ValueError('Output extension must match the cover image format (.jpg/.jpeg or .png).')
        image.seek(0)
        size = os.fstat(payload.fileno()).st_size
        if size > MAX_PAYLOAD_SIZE:
            raise ValueError('Input exceeds the supported size limit.')
        salt, nonce = os.urandom(16), os.urandom(12)
        footer = FOOTER.pack(MAGIC, salt, nonce, size + TAG_SIZE)
        encryptor = Cipher(algorithms.AES(derive(password, salt)), modes.GCM(nonce)).encryptor()
        with new_output(output) as destination:
            digest = hashlib.sha256()
            for block in chunks(image, os.fstat(image.fileno()).st_size):
                digest.update(block)
                destination.write(block)
            if image.read(1):
                raise ValueError('Cover changed while being read.')
            encryptor.authenticate_additional_data(footer + digest.digest())
            for block in chunks(payload, size):
                destination.write(encryptor.update(block))
            if payload.read(1):
                raise ValueError('Payload changed while being read.')
            destination.write(encryptor.finalize())
            destination.write(encryptor.tag)
            destination.write(footer)


def decode(source, output, password):
    with open(source, 'rb') as image:
        total = os.fstat(image.fileno()).st_size
        if total < FOOTER.size + TAG_SIZE:
            raise ValueError('No supported data found.')
        image.seek(-FOOTER.size, os.SEEK_END)
        footer = image.read(FOOTER.size)
        if len(footer) != FOOTER.size:
            raise ValueError('Truncated file.')
        magic, salt, nonce, length = FOOTER.unpack(footer)
        if magic != MAGIC:
            raise ValueError('No supported data found.')
        cover_size = total - FOOTER.size - length
        if length < TAG_SIZE or cover_size <= 0 or length - TAG_SIZE > MAX_PAYLOAD_SIZE:
            raise ValueError('Invalid file length or truncated file.')
        image.seek(total - FOOTER.size - TAG_SIZE)
        tag = image.read(TAG_SIZE)
        decryptor = Cipher(algorithms.AES(derive(password, salt)), modes.GCM(nonce, tag)).decryptor()
        image.seek(0)
        digest = hashlib.sha256()
        for block in chunks(image, cover_size):
            digest.update(block)
        decryptor.authenticate_additional_data(footer + digest.digest())
        with new_output(output) as destination:
            for block in chunks(image, length - TAG_SIZE):
                destination.write(decryptor.update(block))
            try:
                destination.write(decryptor.finalize())
            except InvalidTag:
                raise ValueError('Incorrect passphrase or damaged file.') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    enc = commands.add_parser('encode', help='Process a file.')
    enc.add_argument('file', type=Path)
    enc.add_argument('cover', type=Path)
    enc.add_argument('output', type=Path)
    dec = commands.add_parser('decode', help='Restore a file.')
    dec.add_argument('image', type=Path)
    dec.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        password = getpass.getpass('Passphrase: ')
        if args.command == 'encode':
            if password != getpass.getpass('Confirm passphrase: '):
                raise ValueError('Passphrases do not match.')
            encode(args.file, args.cover, args.output, password)
        else:
            decode(args.image, args.output, password)
    except (OSError, ValueError) as error:
        print(f'Error: {error}', file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print('\nCancelled.', file=sys.stderr)
        return 130
    print(f'Saved {args.output}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

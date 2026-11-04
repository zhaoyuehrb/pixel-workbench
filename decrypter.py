#!/usr/bin/env python3
"""Standalone image reader. Requires Python 3.9+, Pillow, and cryptography.

Setup: python -m pip install Pillow cryptography
Usage: python decrypter.py input.png output.bin
No other project files or original cover image are required.
"""
import argparse
import getpass
from pathlib import Path
import struct
import sys

try:
    from PIL import Image
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:
    sys.exit('Missing dependencies. Run: python -m pip install Pillow cryptography')

MAGIC = b'IMGVLT01'
HEADER = 44  # magic, salt (16), nonce (12), ciphertext length (8)


def derive(password, salt):
    if not password:
        raise ValueError('Passphrase must not be empty.')
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode('utf-8'))


def pixels(path):
    with Image.open(path) as source:
        image = source.convert('RGB')
    return image, bytearray(image.tobytes())


def extract(raw, count, offset=0):
    if (offset + count) * 8 > len(raw):
        raise ValueError('Image is too small or the payload is damaged.')
    result = bytearray(count)
    for i in range(count):
        for j in range(8):
            result[i] = (result[i] << 1) | (raw[(offset + i) * 8 + j] & 1)
    return bytes(result)


def decode(source, output, password):
    _, raw = pixels(source)
    header = extract(raw, HEADER)
    if header[:8] != MAGIC:
        raise ValueError('No supported Image Vault payload found.')
    salt, nonce = header[8:24], header[24:36]
    length = struct.unpack('>Q', header[36:44])[0]
    if length < 16:
        raise ValueError('Invalid payload length.')
    ciphertext = extract(raw, length, HEADER)
    try:
        data = AESGCM(derive(password, salt)).decrypt(nonce, ciphertext, header)
    except InvalidTag:
        raise ValueError('Incorrect passphrase or damaged image.') from None
    with open(output, 'xb') as handle:
        handle.write(data)


def main():
    parser = argparse.ArgumentParser(description='Standalone image reader.')
    parser.add_argument('image', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        password = getpass.getpass('Passphrase: ')
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

"""Encrypt arbitrary file bytes into a cover image's RGB least significant bits."""
import argparse
import getpass
import os
from pathlib import Path
import struct
import sys

from PIL import Image
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

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


def encode(source, cover, output, password):
    if Path(output).suffix.lower() != '.png':
        raise ValueError('Output must use the .png extension.')
    image, raw = pixels(cover)
    size = Path(source).stat().st_size
    capacity = len(raw) // 8 - HEADER - 16
    if size > capacity:
        raise ValueError(f'File is {size:,} bytes; this cover fits {max(0, capacity):,} bytes. Use a larger photo.')
    data = Path(source).read_bytes()
    salt, nonce = os.urandom(16), os.urandom(12)
    header = MAGIC + salt + nonce + struct.pack('>Q', len(data) + 16)
    ciphertext = AESGCM(derive(password, salt)).encrypt(nonce, data, header)
    payload = header + ciphertext
    for i, value in enumerate(payload):
        for j in range(8):
            at = i * 8 + j
            raw[at] = (raw[at] & 254) | ((value >> (7 - j)) & 1)
    result = Image.frombytes('RGB', image.size, bytes(raw))
    with open(output, 'xb') as handle:
        result.save(handle, format='PNG')


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
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    enc = commands.add_parser('encode', help='Encrypt a file into a cover photo; output must be PNG.')
    enc.add_argument('file', type=Path)
    enc.add_argument('cover', type=Path)
    enc.add_argument('output', type=Path)
    dec = commands.add_parser('decode', help='Recover original bytes from an encoded PNG.')
    dec.add_argument('image', type=Path)
    dec.add_argument('output', type=Path)
    args = parser.parse_args()
    password = getpass.getpass('Passphrase: ')
    try:
        if args.command == 'encode':
            if password != getpass.getpass('Confirm passphrase: '):
                raise ValueError('Passphrases do not match.')
            encode(args.file, args.cover, args.output, password)
        else:
            decode(args.image, args.output, password)
        print(f'Saved {args.output}')
    except (OSError, ValueError) as error:
        print(f'Error: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

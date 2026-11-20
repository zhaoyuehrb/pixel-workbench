# Pixel Workbench — payload mode

This independent `payload-mode` branch appends an encrypted file directly to a JPEG or PNG cover. The original image bytes and pixels are unchanged. The file stays viewable as an image in viewers that accept trailing data, and `vault.py decode` recovers the exact original payload bytes. The pixel-based implementation remains on `main`; its encoded images use a different format.

## Setup

Python 3.11+:

```sh
python -m pip install -r requirements.txt
```

Or use Conda:

```sh
conda env create -f environment.yml
conda activate payload-vault
```

## Encode and decode

```sh
python vault.py encode /path/to/file.mp4 covers/mountain-reflection.jpg packed.jpg
python vault.py decode packed.jpg recovered.mp4
```

Both commands prompt for a passphrase; encoding also asks for confirmation. Use any payload file type. Choose an output image extension that matches the cover (`.jpg`/`.jpeg` for JPEG, `.png` for PNG). Existing output files, including input files, are never overwritten. Failed operations remove their temporary files.

Three 1920 × 1080 landscape wallpapers are included in [`covers/`](covers/README.md). Any of them works for any supported payload size; a larger cover does not increase capacity. To restore missing sample wallpapers:

```sh
python covers.py download
```

Copy `vault.py` to another machine with the same Python dependencies to encode or decode there. No other project files or original cover are needed to decode. Run `python vault.py --help` for command help.

## File format and limits

```text
[original cover bytes][encrypted payload][16-byte GCM tag][44-byte footer]
```

Output size is exactly **cover size + payload size + 60 bytes**. Files are streamed in 1 MiB chunks instead of loading the payload into memory. Payloads can exceed the cover size; the [per-file AES-GCM limit](https://csrc.nist.gov/pubs/sp/800/38/d/final) is 64 GiB minus 32 bytes, with available disk space and filesystem limits also applying. Encoding and decoding use a temporary file beside the output and publish it with an atomic hard link, so the output filesystem must support hard links (such as NTFS, ext4, or APFS).

Encryption uses AES-256-GCM with a random 16-byte salt and 12-byte nonce, with the key derived using scrypt (`N=32768`, `r=8`, `p=1`). The big-endian footer (`>8s16s12sQ`) stores magic `PWPAYL01`, salt, nonce, and encrypted payload length including the tag. GCM authenticates the footer followed by the SHA-256 digest of the complete original cover as additional data. Wrong passwords or changes to the cover, payload, tag, or footer are rejected before publishing the decoded file. The original payload filename is not stored; choose it when decoding.

Transfer the resulting image as an **original file**. Image editors and services that resize, recompress, strip trailing data, or re-save images can remove the payload. Appended data is detectable; encryption protects its contents.

## Tests

```sh
python -m unittest -v
```

# Pixel Workbench

Personal image utility. Runs locally with Python 3.11.

## Setup

```sh
conda env create -f environment.yml
conda activate image-vault
```

## Command reference

```sh
python vault.py --help
```

## Image presets

See [the size guide](covers/README.md) for dimensions and limits.

```sh
python covers.py download
python covers.py plan /path/to/input.mp4
```

## Standalone utility

Copy `decrypter.py` to the target machine. No other project files are needed.
Requires Python 3.9+ and the following packages (Conda is optional there):

```sh
python -m pip install Pillow cryptography
python decrypter.py input.png output.bin
```

The passphrase is prompted interactively. Existing output files are preserved.

## Tests

```sh
python -m unittest -v
```

## Environment updates

```sh
conda env update -f environment.yml --prune
```

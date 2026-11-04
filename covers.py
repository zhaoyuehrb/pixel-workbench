"""Prepare local image presets and choose a suitable size."""
import argparse
import csv
import io
import json
from pathlib import Path
import urllib.request

from PIL import Image, ImageOps

ROOT = Path(__file__).resolve().parent / 'covers'
TIERS = [
    ('480p', 854, 480), ('720p', 1280, 720),
    ('1080p', 1920, 1080), ('1440p', 2560, 1440),
    ('2160p', 3840, 2160), ('24mp', 6000, 4000),
]
SOURCES = [
    ('alpine-lake', '12699620', 'Dominik Perau', 'https://www.pexels.com/photo/beautiful-landscape-of-a-mountain-lake-12699620/'),
    ('mountain-reflection', '346529', 'Bri Schneiter', 'https://www.pexels.com/photo/calm-body-of-lake-between-mountains-346529/'),
    ('interlaken', '2618992', 'R. Fera', 'https://www.pexels.com/photo/scenic-view-of-lake-during-daytime-2618992/'),
]


def capacity(width, height):
    return width * height * 3 // 8 - 60


def choose(size):
    for name, width, height in TIERS:
        if size <= capacity(width, height):
            return name, width, height
    raise ValueError('File exceeds the largest preset (8,999,940 bytes). Use a larger original or reduce the input size.')


def download():
    ROOT.mkdir(exist_ok=True)
    rows = []
    for name, photo_id, author, page in SOURCES:
        url = f'https://images.pexels.com/photos/{photo_id}/pexels-photo-{photo_id}.jpeg'
        original = ROOT / 'originals' / f'{name}.jpg'
        original.parent.mkdir(exist_ok=True)
        if not original.exists():
            request = urllib.request.Request(url, headers={'User-Agent': 'PixelWorkbench/1.0'})
            with urllib.request.urlopen(request, timeout=90) as response:
                data = response.read()
            with Image.open(io.BytesIO(data)) as check:
                check.verify()
            original.write_bytes(data)
        with Image.open(original) as opened:
            image = ImageOps.exif_transpose(opened).convert('RGB')
        for tier, width, height in TIERS:
            if image.width < width or image.height < height:
                raise ValueError(f'{name} is too small for {tier}; no upscaling is performed.')
            output = ROOT / tier / f'{name}.jpg'
            output.parent.mkdir(exist_ok=True)
            if not output.exists():
                resized = ImageOps.fit(image, (width, height), method=Image.Resampling.LANCZOS)
                resized.save(output, quality=92, optimize=True)
            with Image.open(output) as check:
                if check.size != (width, height):
                    raise ValueError(f'Unexpected dimensions: {output}')
            rows.append({'path': output.relative_to(ROOT).as_posix(), 'width': width, 'height': height,
                         'capacity_bytes': capacity(width, height), 'jpeg_bytes': output.stat().st_size,
                         'author': author, 'source': page})
            print(f'{tier}: {name}')
    with (ROOT / 'catalog.csv').open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (ROOT / 'sources.json').write_text(json.dumps([
        {'name': name, 'author': author, 'page': page, 'photo_id': photo_id, 'license': 'https://www.pexels.com/license/'}
        for name, photo_id, author, page in SOURCES
    ], indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('download', help='Download three photos and prepare six presets each.')
    plan = commands.add_parser('plan', help='Choose the smallest preset for a file.')
    plan.add_argument('file', type=Path)
    args = parser.parse_args()
    try:
        if args.command == 'download':
            download()
        else:
            size = args.file.stat().st_size
            tier, width, height = choose(size)
            print(f'Input: {size:,} bytes')
            print(f'Smallest preset: {tier} ({width} x {height})')
            print(f'Capacity: {capacity(width, height):,} bytes')
            files = sorted((ROOT / tier).glob('*.jpg'))
            if not files:
                print('Prepare covers first: python covers.py download')
            for path in files:
                print(f'Cover: {path}')
    except (OSError, ValueError) as error:
        parser.exit(1, f'Error: {error}\n')


if __name__ == '__main__':
    main()

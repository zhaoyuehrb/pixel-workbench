"""Download the sample 1080p wallpapers listed in covers/sources.json."""
import argparse
import csv
import io
import json
from pathlib import Path
import urllib.request

from PIL import Image

ROOT = Path(__file__).resolve().parent / 'covers'


def download():
    rows = []
    for source in json.loads((ROOT / 'sources.json').read_text(encoding='utf-8')):
        output = ROOT / f'{source["name"]}.jpg'
        if not output.exists():
            request = urllib.request.Request(source['download_url'], headers={'User-Agent': 'PixelWorkbench/1.0'})
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read()
            with Image.open(io.BytesIO(data)) as check:
                if check.format != 'JPEG' or check.size != (1920, 1080):
                    raise ValueError(f'Unexpected wallpaper format or dimensions: {output}')
                check.verify()
            with output.open('xb') as handle:
                handle.write(data)
        with Image.open(output) as check:
            width, height = check.size
            check.verify()
        rows.append({'path': output.name, 'width': width, 'height': height,
                     'jpeg_bytes': output.stat().st_size, 'author': source['author'], 'source': source['page']})
        print(f'Cover: {output}')
    with (ROOT / 'catalog.csv').open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['download'])
    parser.parse_args()
    try:
        download()
    except (OSError, ValueError) as error:
        parser.exit(1, f'Error: {error}\n')


if __name__ == '__main__':
    main()

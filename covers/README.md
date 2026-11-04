# Image presets

Three photos per size, prepared from Pexels originals. Source credits and links are in `sources.json`; measured dimensions, JPG sizes, and byte capacities are in `catalog.csv`.

## Size guide

“720p” means 1280 × 720 pixels, not a 720-pixel width. MB below uses 1,000,000 bytes.

| Preset | Dimensions | Maximum input bytes | Approximate MB |
|---|---|---:|---:|
| 480p | 854 × 480 | 153,660 | 0.154 |
| 720p | 1280 × 720 | 345,540 | 0.346 |
| 1080p | 1920 × 1080 | 777,540 | 0.778 |
| 1440p | 2560 × 1440 | 1,382,340 | 1.382 |
| 2160p / 4K | 3840 × 2160 | 3,110,340 | 3.110 |
| 24mp | 6000 × 4000 | 8,999,940 | 9.000 |

Choose the first row whose capacity is at least your input file's exact byte size. The 60-byte overhead is already deducted; no additional margin is required. A 300 KB file fits 720p; a 500 KB file needs 1080p; a 2.5 MB file needs 2160p; a 5 MB file needs 24mp. Videos are evaluated by bytes, regardless of duration or resolution.

From the project directory:

```sh
conda activate image-vault
python covers.py plan /path/to/input.mp4
```

The planner prints the smallest suitable preset and its three cover paths. Use any of those paths in your existing command. It reports an error if the input exceeds the largest preset. This does not modify your input or cover.

## Output size

These are input capacities, not promised PNG output sizes. JPG download sizes do not predict output PNG size. The encoded PNG depends on image detail, input size, and PNG compression. Choosing the smallest fitting preset generally reduces output size, but a different photo can compress better. A smaller preset does not guarantee the smallest PNG across all photos.

RGB pixel data before PNG compression is width × height × 3 bytes: 2.76 MB at 720p, 6.22 MB at 1080p, 24.88 MB at 2160p, and 72 MB at 24mp. These are reference sizes, not exact output sizes or strict upper limits. The current tool has no maximum-output-bytes setting.

## Files and regeneration

```sh
python covers.py download
```

This downloads three originals and creates three JPEG covers at each of six sizes (18 covers). Resizing uses center cropping to the specified aspect ratio, with no upscaling. Existing images are reused; delete an affected image to regenerate it. Original and prepared photos stay local and are excluded from Git. The downloader, size guide, catalog, and source credits can be tracked.

Always resize a cover before using it. Preserve the resulting PNG's pixels after processing. Reducing or recompressing the input video before processing can let you use a smaller preset; zipping an already compressed video usually saves little.

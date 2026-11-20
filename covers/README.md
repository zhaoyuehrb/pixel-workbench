# Sample wallpapers

Three 1920 × 1080 JPEG landscape wallpapers are included in this branch:

| File | Photographer | Source |
|---|---|---|
| `alpine-lake.jpg` | Dominik Perau | [Pexels](https://www.pexels.com/photo/beautiful-landscape-of-a-mountain-lake-12699620/) |
| `mountain-reflection.jpg` | Bri Schneiter | [Pexels](https://www.pexels.com/photo/calm-body-of-lake-between-mountains-346529/) |
| `interlaken.jpg` | R. Fera | [Pexels](https://www.pexels.com/photo/scenic-view-of-lake-during-daytime-2618992/) |

Downloaded and cropped through the Pexels image CDN. See the [Pexels license](https://www.pexels.com/license/), `sources.json` for exact download URLs, and `catalog.csv` for dimensions and file sizes. These are sample covers for the utility.

To restore missing samples:

```sh
python covers.py download
```

Existing samples are reused. Delete a sample to download it again.

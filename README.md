# Arc2Lite

<p align="center">
<img src="https://github.com/stark4n6/Arc2Lite/blob/main/assets/Arc2Lite.png" width="300" height="300">
</p>
A simple script to read the contents of a zip/tar/gz archive or a forensic disk image and extract metadata to a SQLite DB.

## Disk images and E01 acquisitions

A raw disk image, a split image, and an EnCase/EWF `.E01` acquisition are read
the same way an archive is. Point Arc2Lite at one and the files inside its
volumes land in `file_listing` beside everything else, so every query you
already run against an Arc2Lite database works against an image too.

```
python arc2lite.py -i evidence.E01 -o C:\reports
python arc2lite.py -i disk.001 -o C:\reports
python arc2lite.py -i C:\images -o C:\reports -r
```

Nothing is extracted and no file's content is read. Only the directory trees
are walked, and the image is never written to.

| acquisition | entries | time |
| --- | ---: | ---: |
| 7.4 GB Windows E01 | 156,894 | 5.9 s |
| 32 GB macOS E01, two partitions | 625,553 | 19.2 s |

An NTFS volume is read from one sequential pass over its `$MFT` and an APFS one
from one pass over its catalog, rather than by reading an index per directory.
That is qnxprobe's `walk_all()`, and it is where most of the time went before:
the same two acquisitions took 8.7 s and 155.0 s when the listing walked the
directory tree, and the rows it produces are identical.

Filesystems read: QNX6, QNX4, ETFS, EFS, ext2/3/4, F2FS, FAT32, exFAT, NTFS,
HFS+, APFS, and QNX IFS boot images. Each volume is identified by its own
on-disk structure rather than by a partition type byte.

Two files do the reading, both vendored in `vendor/` and both pure standard
library, so this adds nothing to install:

- [qnxprobe](https://github.com/abrignoni/qnxprobe) finds the partitions,
  identifies each volume and walks its directory tree.
- [ewfprobe](https://github.com/abrignoni/ewfprobe) presents an `.E01` set as
  one seekable stream, so an acquisition reads exactly like a raw image.

### What an image adds to the database

`file_listing` is unchanged and takes one row per entry, with `entry_path` as
`<volume>/<path>`. The volume name carries the partition's LBA, so two volumes
cannot collide. Four tables sit beside it:

| table | what is in it |
| --- | --- |
| `image_metadata` | geometry, segment names, and for an E01 the case number, examiner, acquisition date and software, and the MD5 and SHA-1 the acquisition recorded |
| `image_volumes` | one row per volume found, walked or not, with its offset, size, filesystem and counts |
| `image_entries` | whether an entry is a file, a directory, a symlink or a device node, and what its dates mean |
| `image_deleted_files` | deleted directory entries that still name a file, from NTFS, FAT32 and exFAT, with whether the content is still recoverable |

### About the dates

A date is written only when the filesystem recorded one. Where a filesystem
keeps no created or accessed time this reader can reach, the column is left
empty rather than filled from the modified time, so a date in an image row is
always a date the volume actually holds.

`image_entries.time_basis` says what a row's dates mean:

- `utc`, the filesystem stores an instant and it is rendered as ISO 8601 in
  UTC. NTFS, ext, F2FS, HFS+, APFS, QNX and the rest.
- `stored reading`, FAT32 and exFAT store a wall clock and no zone. The writer
  converted it with whatever offset it held at the time of writing, which the
  volume does not record, so there is no correct conversion to UTC. The
  reading is carried through as the text it is and no zone is put on it.

One database can hold both. A Mac acquisition has a FAT32 EFI partition beside
its APFS container, and the two are labelled separately.

### On hashing

`-ha` hashes the file you hand in, which for a set of segments is its first
segment. That is a different question from the hash of the acquired disk, and
an E01 records its own MD5 and SHA-1 over the whole disk at acquisition time.
Those are in `image_metadata.acquisition_md5` and `acquisition_sha1`.

## UPDATE 2026-09-18:
CSV export option, requested by Andrew Rathbun via DFIR Discord (Issue #2).

Pass `-c`/`--csv` on the command line, or tick "Also export to CSV" in the
GUI, and every table in a database is also written out as its own CSV file,
in a `<database name>_csv` folder beside it. This runs for each archive's
own database as well as the run's `Arc2Lite_Master_Log.db`, so both a
file_listing.csv (plus archive_metadata.csv, and the image_* tables
for a disk image) and a processing_log.csv come out of a run made with
-c. Nothing changes when the flag is left off: the databases are still
the only output, as before.

## UPDATE 2026-03-18:
GUI and CLI have been combined into one script. If no switches are supplied it will run the GUI.

Other updates include:
- Hashing for archives
- Recursive processing for folders of archives
- Fallback timestamps if extended attributes aren't found
- High level metadata about archive in each SQLite DB

## UPDATE 2025-04-18:
GUI added, mostly thanks to Gemini!
<p align="center">
<img src="https://github.com/user-attachments/assets/1df34425-1c4a-463f-8328-137f122df687">
</p>

## UPDATE 2025-04-15:
Because making original names is hard, this is the final form, Arc2Lite.

## UPDATE 2025-04-14: 
With v0.0.4 this now handles ZIP and TAR and folder paths, so the script has been renamed to FileWalker (how original).

## Command Line Switches
```
usage: arc2lite.py [-h] -i INPUT -o OUTPUT [-r] [-ha {md5,sha1,sha256}]

options:
  -c, --csv             Also export each database table and metadata report from disk images to CSV, alongside
                        the SQLite database
  -h, --help            show this help message and exit
  -i, --input INPUT     ZIP/TAR/GZ archive, raw disk image, .E01 acquisition,
                        or a folder of them
  -o, --output OUTPUT   Path for the export report
  -r, --recursive       Recursively scan folder for archives
  -ha, --hash {md5,sha1,sha256}
                        Optional hashing options
```

## Tests

```
python -m unittest discover -s tests -v
```

Nineteen tests covering the image path, with small filesystems built for the
purpose in `tests/fixtures`. Run on Python 3.9, 3.10, 3.12 and 3.14. One of
them stands the vendored reader beside those fixtures and runs its own
self-test, so a bad re-vendor fails here rather than quietly later.

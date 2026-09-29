# Arc2Lite

<p align="center">
<img src="https://github.com/stark4n6/Arc2Lite/blob/main/assets/Arc2Lite.png" width="300" height="300">
</p>
A simple script to read the contents of a zip/tar/gz/xz archive or a forensic disk image and extract metadata to a SQLite DB.

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
are walked, and the image is never written to. The one exception is
`-sig`/`--check-signatures`, which you opt into: it reads a small header from
each file to check its type (see the 2026-09-27 update below), and still
writes nothing to the image.

An encrypted image (an encrypted Apple disk image, an encrypted AFF, or an
acquisition FTK Imager encrypted with AD encryption) opens only with its password
or with the private key of a certificate it is sealed to, and Arc2Lite takes
neither. Under a name Arc2Lite reads as an image (`.E01`, a raw image name, or
the first file of a numbered set) it is still listed: `image_metadata` gets a row
whose note says it was not read. A BitLocker volume inside an image is listed in
`image_volumes` with a note saying why it was not read.

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

## UPDATE 2026-09-29:

Signature/extension mismatch detection: flags a file whose extension doesn't match what its own bytes actually are (a `.jpg` that's really a renamed `.zip`, say) -- the kind of thing a hidden or relabeled file shows up as.

- `-sig`/`--check-signatures` on the command line, or the "Check file signatures" checkbox in the GUI, checks every file's header against a small built-in table of common types (images, documents, archives, executables, and a few more) and records anything that disagrees with the extension in a new `signature_mismatches` table -- `entry_path`, `file_extension`, `expected_type`, `detected_type`.
- Works for archives and disk images alike. An extension the table has no expectation for is never flagged, so it catches real mismatches rather than guessing at every extension that exists.
- It's opt-in. For an archive the cost is small, since reading a file's header is already how the archive library works. For a disk image it's real: each file needs a seek and a read on top of the metadata-only walk, so a large image takes measurably longer with `-sig` on. Whether that's worth it is the examiner's call, so it's off by default.
- `signature_mismatches` exists in every database either way (empty when `-sig` isn't used, just as `image_deleted_files` is empty on a volume with nothing recovered), so it gets its own CSV automatically whenever `-e`/`--export` includes `csv`.

## UPDATE 2026-09-25:

Bodyfile/timeline export and CSV export, both driven by one `-e`/`--export` switch.

- `-e`/`--export` on the command line, or the SQLite/CSV/Timeline checkboxes in the GUI, picks one or more formats to leave on disk: `sqlite` (the default, unchanged from before), `csv`, and/or `timeline`. Combine them freely, e.g. `-e sqlite csv timeline`, or `-e csv timeline` with no database kept at all.
- `csv` writes every table in a database out as its own CSV file, in a `<database name>_csv` folder beside it, for each archive's own database as well as the run's `Arc2Lite_Master_Log.db` -- a `file_listing.csv` (plus `archive_metadata.csv`, and the `image_*` tables for a disk image) and a `processing_log.csv`.
- `timeline` writes a `<database name>.body` file -- a Sleuth Kit/mactime bodyfile, for loading into `mactime`, Plaso, Timesketch or anything else that reads that format -- beside each archive's or image's own database. It's scoped to per-archive/image databases only: the run's `Arc2Lite_Master_Log.db` has no `file_listing` of its own to draw a timeline from, so it never gets a `.body`, no matter which formats are chosen. Fields Arc2Lite doesn't track (MD5, inode, UID, GID, and change time) are written as `0`. A FAT/exFAT "stored reading" (see "About the dates" above) is read as the literal digits it was written with, not converted through the host machine's timezone, so the same evidence produces the same bodyfile no matter where Arc2Lite runs.
- `sqlite` keeps the `.db` file; leaving it out of the choices removes the `.db` afterward, once whatever other formats were chosen have been written from it. The database is always built internally regardless of choice -- that's what gives `file_listing` its per-path dedup -- `csv` and `timeline` just read from it and then it's cleaned up if `sqlite` wasn't kept.

Requested by Andrew Rathbun via DFIR Discord (Issue #2).

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
                   [-e {sqlite,csv,timeline} [{sqlite,csv,timeline} ...]]
                   [-sig]

options:
  -h, --help            show this help message and exit
  -i, --input INPUT     ZIP/TAR/GZ/XZ archive, raw disk image, .E01
                        acquisition, or a folder of them
  -o, --output OUTPUT   Path for the export report
  -r, --recursive       Recursively scan folder for archives
  -ha, --hash {md5,sha1,sha256}
                        Optional hashing options
  -e, --export {sqlite,csv,timeline} [{sqlite,csv,timeline} ...]
                        One or more export formats for the results: 'sqlite'
                        (default), 'csv', and/or 'timeline' (a Sleuth
                        Kit/mactime bodyfile). Combine as needed, e.g.
                        -e sqlite csv timeline. 'timeline' only ever applies
                        to an archive's or image's own database, never the
                        master log.
  -sig, --check-signatures
                        Flag files whose extension doesn't match their
                        actual file type (e.g. a .jpg that's really a
                        renamed .zip). Reads a small header from every file,
                        including within disk images, so it costs real time
                        on a large input -- opt in with this flag.
```

## Tests

```
python -m unittest discover -s tests -v
```

Twenty-five tests covering the image path, with small filesystems built for the
purpose in `tests/fixtures`; twelve covering apply_export_choice() and the
CSV writer; thirteen covering the bodyfile writer and its date parsing;
nine covering -e/--export end to end, across every combination of
sqlite/csv/timeline; and seventeen covering signature/extension mismatch
detection, in archives, in disk images, and in isolation. Run on Python 3.9,
3.10, 3.12 and 3.14. One of the image-path tests stands the vendored reader
beside those fixtures and runs its own self-test, so a bad re-vendor fails
here rather than quietly later.
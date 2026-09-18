"""Disk image and EnCase/EWF acquisition input for Arc2Lite.

Arc2Lite reads an archive and writes what is inside it to SQLite. A forensic
disk image holds the same thing behind a filesystem instead of behind a zip
central directory, so it is indexed the same way and lands in the same tables.

A raw image (``.img``, ``.dd``, ``.raw``, ``.bin``, or a numbered ``.001``
segment set) and an EnCase/EWF acquisition (``.E01`` and its segments) are read
in place, with no mounting and no administrator rights, through the two readers
vendored in ``vendor/``: qnxprobe finds the partitions, identifies each volume
by its own on-disk structure rather than by a partition type byte, and walks
its directory tree; ewfprobe presents an ``.E01`` set as one seekable stream so
qnxprobe reads it exactly as it reads a raw file. Both are pure standard
library, so Arc2Lite still installs nothing to gain this.

Nothing is extracted and no file's content is read. Only the directory trees
are walked, which is why a 250 GiB acquisition lists in seconds.

Filesystems qnxprobe walks: QNX6, QNX4, ETFS, EFS, ext2/3/4, F2FS, FAT32,
exFAT, NTFS, HFS+, APFS and QNX IFS boot images.

Where the rows go
-----------------
``file_listing`` takes one row per entry, exactly as an archive does, so every
query that already works against an Arc2Lite database works against an image.
Each ``entry_path`` is ``<volume>/<path>``, the volume being the name qnxprobe
gives that partition (``p3_lba239616_basic_data_partition``, ``lba0``): the
partition's LBA is in it, so two volumes cannot collide.

Four tables are added beside it, and nothing already there is changed:

``image_metadata``      the acquisition: geometry, segments, and for an E01
                        the tool that made it and the hashes it recorded.
``image_volumes``       one row per partition or volume found, walked or not,
                        with its offset, size, filesystem and counts.
``image_entries``       what ``file_listing`` has no column for: whether an
                        entry is a file, a directory, a symlink or a device
                        node, what its dates mean, and the dates as the
                        filesystem stored them.
``image_deleted_files`` deleted directory entries that still name a file, from
                        the filesystems that keep them (NTFS, FAT32, exFAT).

Dates
-----
A date is only written into ``file_listing`` when the filesystem recorded one.
Where a filesystem keeps no created or accessed time that this reader can
reach, the column is left empty rather than filled with the modified time, so
a date in an image row is always a date the volume actually holds.

Two kinds of date reach these tables and ``image_entries.time_basis`` says
which a row carries:

``utc``             the filesystem stores an instant, counted from a fixed
                    epoch, and it is rendered as ISO 8601 in UTC. NTFS, ext,
                    F2FS, HFS+, APFS, QNX and the rest.
``stored reading``  FAT32 and exFAT store a wall-clock reading and no zone.
                    The writer converted it with whatever offset it held at
                    the time of writing, which the volume does not record, so
                    there is no correct conversion to UTC. The reading is
                    carried through as the text it is and no zone is put on it.

Only NTFS and F2FS expose all three dates through this reader; every other
filesystem gives the modified time alone, and FAT32 and exFAT give all three
as readings. ``image_volumes.time_basis`` says which applies per volume.
"""

import datetime
import json
import os
import sys

# The vendored qnxprobe reaches its EWF reader with a bare ``import ewfprobe``,
# falling back to a sys.path insert of its own directory. Importing the
# vendored copy through the package first and registering it under the bare
# name makes that fallback unnecessary, which matters in the frozen build,
# where the vendored files are modules of the bundle rather than files on a
# path.
from vendor import ewfprobe as _ewfprobe          # noqa: E402  (order matters)
sys.modules.setdefault("ewfprobe", _ewfprobe)
from vendor import qnxprobe                       # noqa: E402

ewfprobe = _ewfprobe

# What a raw disk image is conventionally called. An extension here and
# nowhere else names a disk image and nothing else, so a file carrying one is
# indexed as an image whatever is inside it: an image whose filesystem this
# reader cannot name is still worth a row saying so.
RAW_IMAGE_SUFFIXES = (".img", ".dd", ".raw")

# Extensions a disk image shares with other things: ".bin", given to firmware
# and to game data as readily as to a disk, and the numbered extension of a
# split set, which is also the first volume of a split archive and the tail of
# a rotated log. A file carrying one is claimed only when the reader finds a
# volume in it, so a folder sweep does not report every ".bin" it passes as a
# disk image.
AMBIGUOUS_SUFFIXES = (".bin",)


def _maybe_an_image_name(lowered):
    """True when this name is one a disk image is sometimes given.

    Every numbered extension is here, not only ".001": a set written from
    ".000" has its first segment there, and a set is joined from its first
    segment, so a rule that only knew ".001" would skip such a set entirely
    while looking as though it had handled it.
    """
    if lowered.endswith(AMBIGUOUS_SUFFIXES):
        return True
    _stem, dot, suffix = lowered.rpartition(".")
    return bool(dot and suffix.isascii() and suffix.isdigit())

FILESYSTEMS = ("QNX6, QNX4, ETFS, EFS, ext2/3/4, F2FS, FAT32, exFAT, NTFS, "
               "HFS+, APFS, QNX IFS")

READER = f"qnxprobe {qnxprobe.QNXPROBE_VERSION} / ewfprobe {ewfprobe.__version__}"

_S_IFMT = 0o170000
_S_IFDIR = 0o040000
_S_IFREG = 0o100000
_S_IFLNK = 0o120000

UTC = "utc"
READING = "stored reading"


# --------------------------------------------------------------- detection

def detect(file_path):
    """``"E01"``, ``"RAW"``, or None when this file is not an image to index.

    A later segment of a split set returns None: the set is indexed once, from
    its first segment, which the reader joins the rest onto. A file with an
    image extension that holds no volume this reader recognises also returns
    None, so a folder sweep does not claim every ``.bin`` it meets.
    """
    try:
        if not os.path.isfile(file_path) or os.path.getsize(file_path) < 512:
            return None
    except OSError:
        return None

    if ewfprobe.is_ewf(file_path):
        # An EWF signature names a forensic acquisition and nothing else, so
        # it is claimed whatever filesystem is inside. Every segment carries
        # the signature, so the extension is what says which one is the first;
        # ewfprobe joins the rest onto it.
        return "E01" if file_path.lower().endswith(".e01") else None

    lowered = file_path.lower()
    named_image = lowered.endswith(RAW_IMAGE_SUFFIXES)
    if not named_image and not _maybe_an_image_name(lowered):
        return None
    try:
        segments = qnxprobe.split_segments(file_path)
    except qnxprobe.SplitImageError:
        # A set with a hole in it, or numbered inconsistently. Reported as an
        # image so index_image() records why it could not be read, rather than
        # passing silently as an ordinary file.
        return "RAW" if named_image else None
    if segments and os.path.abspath(file_path) != os.path.abspath(segments[0]):
        return None
    if named_image:
        return "RAW"
    return "RAW" if _holds_a_volume(file_path, segments) else None


def _holds_a_volume(file_path, segments):
    """True when the reader finds at least one volume it can name in here."""
    try:
        fh = qnxprobe.open_image(file_path, segments or None)
    except Exception:                                # pylint: disable=broad-except
        return False
    try:
        for vol in qnxprobe.volumes(fh, qnxprobe.image_size(fh)):
            if vol.get("walker") is not None or vol["kind"] != "not recognised":
                return True
        return False
    except Exception:                                # pylint: disable=broad-except
        return False
    finally:
        try:
            fh.close()
        except Exception:                            # pylint: disable=broad-except
            pass


# ------------------------------------------------------------------- dates

def format_instant(value):
    """An epoch second as ISO 8601 in UTC, or '' when the volume held none.

    Unlike the archive path's formatter this keeps a date before 1980. A zip
    cannot store one and a filesystem can, so discarding it here would throw
    away a real recorded date.
    """
    if not value:
        return ""
    try:
        return datetime.datetime.fromtimestamp(
            float(value), datetime.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def _reading(times, *keys):
    """The first of these readings the filesystem stored, as its own text."""
    if not times:
        return ""
    for key in keys:
        value = times.get(key)
        if value:
            return str(value)
    return ""


# ------------------------------------------------------------------ schema

# image_metadata's columns, in order, so the table and the row that goes into
# it are built from one list and cannot drift apart.
_IMAGE_METADATA_COLUMNS = (
    ("source_file_name", "TEXT"), ("source_full_path", "TEXT"),
    ("image_type", "TEXT"), ("media_size_bytes", "INTEGER"),
    ("sector_size", "INTEGER"), ("sector_count", "INTEGER"),
    ("segment_count", "INTEGER"), ("segments", "TEXT"),
    # What an EnCase/EWF acquisition recorded about its own making. Empty for a
    # raw image, which records nothing about itself. acquisition_date is kept
    # as the acquisition wrote it: EWF stores a local reading with no zone, so
    # there is no correct conversion to UTC.
    ("case_number", "TEXT"), ("evidence_number", "TEXT"), ("examiner", "TEXT"),
    ("description", "TEXT"), ("acquisition_notes", "TEXT"),
    ("acquisition_date", "TEXT"), ("acquisition_software", "TEXT"),
    ("acquisition_os", "TEXT"),
    # The hashes the acquisition itself recorded, over the whole acquired disk.
    # Arc2Lite's own --hash covers the file handed in, which for a set of
    # segments is its first segment, so the two answer different questions.
    ("acquisition_md5", "TEXT"), ("acquisition_sha1", "TEXT"),
    ("acquisition_metadata", "TEXT"),
    ("reader", "TEXT"), ("volumes_found", "INTEGER"),
    ("volumes_walked", "INTEGER"), ("extraction_timestamp", "TEXT"),
    ("note", "TEXT"),
)


def write_image_metadata(cursor, **fields):
    """One image_metadata row, named by column rather than by position."""
    unknown = set(fields) - {n for n, _t in _IMAGE_METADATA_COLUMNS}
    assert not unknown, f"no such image_metadata column: {sorted(unknown)}"
    row = [fields.get(name) for name, _t in _IMAGE_METADATA_COLUMNS]
    cursor.execute(
        f"INSERT INTO image_metadata VALUES ({','.join('?' * len(row))})", row)


def setup_image_db(cursor):
    """Create the image tables. file_listing and archive_metadata are the
    archive path's and are left exactly as they are."""
    cursor.execute(f'''CREATE TABLE IF NOT EXISTS image_metadata
        ({", ".join(n + " " + t for n, t in _IMAGE_METADATA_COLUMNS)})''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS image_volumes (
        volume_name TEXT COLLATE NOCASE PRIMARY KEY, partition_label TEXT,
        lba INTEGER, byte_offset INTEGER, size_bytes INTEGER, filesystem TEXT,
        detail TEXT, missing_past_end INTEGER, walked INTEGER, time_basis TEXT,
        file_count INTEGER, dir_count INTEGER, other_count INTEGER,
        deleted_count INTEGER, dropped_duplicate_paths INTEGER, note TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS image_entries (
        entry_path TEXT COLLATE NOCASE PRIMARY KEY, volume_name TEXT,
        entry_type TEXT, time_basis TEXT, node TEXT,
        recorded_created TEXT, recorded_modified TEXT, recorded_accessed TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS image_deleted_files (
        volume_name TEXT, file_name TEXT, file_extension TEXT,
        parent_path TEXT, parent_id TEXT, entry_type TEXT, size INTEGER,
        recoverable INTEGER, reason TEXT, contiguity_assumed INTEGER,
        in_deleted_directory INTEGER, identifier TEXT, time_basis TEXT,
        created_date TEXT, modified_date TEXT, accessed_date TEXT)''')
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_img_entry_vol ON image_entries (volume_name);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_img_entry_type ON image_entries (entry_type);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_img_del_vol ON image_deleted_files (volume_name);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_img_del_name ON image_deleted_files (file_name);")


# -------------------------------------------------------------------- walk

def walk_volume(walker):
    """Every entry in this volume, directories included.

    Yields ``(path, node, entry_type, size, mtime, reading)``. ``entry_type``
    is ``file``, ``dir``, ``link`` or ``special``; ``size`` is None for
    anything that holds no data stream of its own; ``reading`` is the dates as
    stored, for the filesystems that keep a zone-less reading, and None for
    the rest.

    The walk itself is qnxprobe's ``walk_all()``, which reads an NTFS volume
    from one pass over its $MFT and an APFS one from one pass over its catalog
    rather than reading an index per directory. All this adds is the name for
    what each entry turned out to be, which ``file_listing`` has no column for
    and ``image_entries`` does. ``test_disk_image.py`` asserts the files this
    yields are exactly the ones qnxprobe's ``collect()`` reports, and that is
    the tree-order walk, so the fast route cannot drift away from it without
    the test saying so.
    """
    for path, node, mode, size, mtime, recorded in qnxprobe.walk_all(walker):
        fmt = mode & _S_IFMT
        if fmt == _S_IFDIR:
            yield (path, node, "dir", None, mtime, recorded)
        elif fmt == _S_IFREG:
            yield (path, node, "file", size, mtime, recorded)
        elif fmt == _S_IFLNK:
            yield (path, node, "link", None, mtime, recorded)
        else:
            yield (path, node, "special", None, mtime, recorded)


# ------------------------------------------------------------------ volumes

def _index_volume(cursor, vol, update):
    """Walk one volume into file_listing and image_entries. Returns its counts."""
    walker = vol["walker"]
    volume = vol["name"]
    basis = READING if hasattr(walker, "listdir_records") else UTC
    has_stamps = hasattr(walker, "stamps")
    counts = {"file": 0, "dir": 0, "other": 0, "dropped": 0}
    # Seeded with the root so a file deleted from the top of the volume
    # resolves to the volume rather than to nothing.
    root = walker.root
    dir_paths = {root[0] if isinstance(root, tuple) else root: ""}
    listed = 0

    for path, node, kind, size, mtime, recorded in walk_volume(walker):
        entry_path = f"{volume}/{path}"
        if kind == "dir":
            dir_paths[node[0] if isinstance(node, tuple) else node] = path

        if basis is READING:
            created = _reading(recorded, "created")
            modified = _reading(recorded, "modified")
            accessed = _reading(recorded, "accessed", "accessed date")
        else:
            created = accessed = ""
            modified = format_instant(mtime)
            if has_stamps:
                born, _mod, seen_at = walker.stamps(node)
                created, accessed = format_instant(born), format_instant(seen_at)

        # is_file carries the archive path's meaning: 1 for anything that is
        # not a directory. image_entries.entry_type says what it really is.
        cursor.execute("INSERT OR IGNORE INTO file_listing VALUES (?,?,?,?,?,?,?,?,?)",
                       (os.path.basename(path), os.path.splitext(path)[1], entry_path,
                        created, modified, accessed,
                        0 if kind == "dir" else 1, size, None))
        if cursor.rowcount:
            cursor.execute("INSERT OR IGNORE INTO image_entries VALUES (?,?,?,?,?,?,?,?)",
                           (entry_path, volume, kind, basis, json.dumps(node),
                            created, modified, accessed))
            counts["file" if kind == "file" else "dir" if kind == "dir" else "other"] += 1
        else:
            # Two paths in one volume that differ only in case fold onto one
            # NOCASE key. Counted rather than dropped in silence.
            counts["dropped"] += 1

        listed += 1
        if listed % 20000 == 0:
            update(f"      [{volume}] {listed:,} entries listed\n", replace_last=True)

    return counts, dir_paths, basis


def _index_deleted(cursor, vol, dir_paths, update):
    """Deleted directory entries that still name a file, where the filesystem
    keeps them. NTFS frees the MFT record and leaves it intact; FAT32 and
    exFAT overwrite the first byte of the entry and free the clusters."""
    walker = vol["walker"]
    volume = vol["name"]
    if not hasattr(walker, "deleted_files"):
        return 0
    ntfs = vol["kind"] == "ntfs"
    try:
        entries = list(walker.deleted_files())
    except Exception as exc:                         # pylint: disable=broad-except
        update(f"      [{volume}] deleted entries not read: {exc}\n")
        return 0

    rows = []
    for e in entries:
        # A path under the volume, the same shape as entry_path, so the two
        # join. Empty when the parent was itself deleted and so never walked.
        where = dir_paths.get(e.parent)
        parent = "" if where is None else (f"{volume}/{where}" if where else volume)
        ext = os.path.splitext(e.name)[1]
        if ntfs:
            rows.append((volume, e.name, ext, parent, str(e.parent),
                         "dir" if e.is_dir else "file", e.size,
                         1 if e.recoverable else 0, e.reason or "", 0, 0,
                         f"MFT record {e.record}", UTC,
                         format_instant(e.created), format_instant(e.modified),
                         format_instant(e.accessed)))
        else:
            rows.append((volume, e.name, ext, parent, str(e.parent),
                         "dir" if e.is_dir else "file", e.size,
                         1 if e.recoverable else 0, e.reason or "",
                         1 if e.assumed_contiguous else 0,
                         1 if e.in_deleted_dir else 0,
                         f"first cluster {e.first_cluster}", READING,
                         _reading(e.times, "created"),
                         _reading(e.times, "modified"),
                         _reading(e.times, "accessed", "accessed date")))
    cursor.executemany(
        "INSERT INTO image_deleted_files VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    return len(rows)


# --------------------------------------------------------------- top level

# The EWF header fields worth their own column, and the column each lands in.
# Anything else the acquisition wrote is kept whole in acquisition_metadata.
_EWF_FIELDS = (("case_number", "case_number"),
               ("evidence_number", "evidence_number"),
               ("examiner", "examiner"),
               ("description", "description"),
               ("notes", "acquisition_notes"),
               ("acquisition_date", "acquisition_date"),
               ("acquiry_software_version", "acquisition_software"),
               ("operating_system", "acquisition_os"))


def _acquisition(file_path, fh):
    """What this image records about its own making, as image_metadata fields.

    A raw image records nothing about itself, so only its segment names come
    back. An EWF acquisition records a good deal, and every field is carried
    through as the acquisition wrote it; nothing is composed or reformatted.
    """
    info = {"sector_size": None, "sector_count": None, "segment_count": 1,
            "segments": json.dumps([os.path.basename(file_path)])}
    if not isinstance(fh, ewfprobe.EwfImage):
        segments = getattr(fh, "paths", None) or getattr(fh, "segments", None)
        if segments:
            names = [os.path.basename(str(p)) for p in segments]
            info["segment_count"] = len(names)
            info["segments"] = json.dumps(names)
        return info
    d = fh.info()
    stored = {k.lower(): v for k, v in (d.get("stored_hashes") or {}).items()}
    meta = d.get("metadata") or {}
    info.update(sector_size=d.get("sector_size"), sector_count=d.get("sector_count"),
                segment_count=d.get("segment_count"),
                segments=json.dumps([os.path.basename(p) for p in d.get("segments", [])]),
                acquisition_md5=stored.get("md5", ""),
                acquisition_sha1=stored.get("sha1", ""),
                acquisition_metadata=json.dumps(meta) if meta else "")
    for key, column in _EWF_FIELDS:
        info[column] = meta.get(key, "")
    return info


def index_image(file_path, cursor, image_type, update):
    """Walk every volume in this image into the cursor's database.

    ``update(text, replace_last=False)`` is Arc2Lite's own log callback, so
    progress reads the same in the terminal and in the window.
    """
    setup_image_db(cursor)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    name = os.path.basename(file_path)

    try:
        segments = qnxprobe.split_segments(file_path) if image_type == "RAW" else None
    except qnxprobe.SplitImageError as exc:
        write_image_metadata(cursor, source_file_name=name, source_full_path=file_path,
                             image_type=image_type, segments="[]", reader=READER,
                             volumes_found=0, volumes_walked=0,
                             extraction_timestamp=now, note=str(exc))
        update(f"    [!] {name}: {exc}\n")
        return {"volumes": 0, "walked": 0, "entries": 0, "deleted": 0}

    try:
        fh = qnxprobe.open_image(file_path, segments or None)
    except Exception as exc:                         # pylint: disable=broad-except
        write_image_metadata(cursor, source_file_name=name, source_full_path=file_path,
                             image_type=image_type, segments="[]", reader=READER,
                             volumes_found=0, volumes_walked=0,
                             extraction_timestamp=now, note=f"could not open: {exc}")
        update(f"    [!] {name}: could not open: {exc}\n")
        return {"volumes": 0, "walked": 0, "entries": 0, "deleted": 0}

    totals = {"volumes": 0, "walked": 0, "entries": 0, "deleted": 0}
    try:
        media_size = qnxprobe.image_size(fh)
        acq = _acquisition(file_path, fh)
        vols = qnxprobe.volumes(fh, media_size)
        totals["volumes"] = len(vols)
        for vol in vols:
            walker = vol.get("walker")
            basis, counts = "", {"file": 0, "dir": 0, "other": 0, "dropped": 0}
            deleted = 0
            note = vol.get("note", "") or ""
            if walker is None:
                update(f"    [{vol['name'] or vol['label']}] {vol['kind']}: {note or 'not walked'}\n")
            else:
                update(f"    [{vol['name']}] {vol['kind']} at LBA {vol['lba']:,}\n")
                try:
                    counts, dir_paths, basis = _index_volume(cursor, vol, update)
                    deleted = _index_deleted(cursor, vol, dir_paths, update)
                    totals["walked"] += 1
                except Exception as exc:             # pylint: disable=broad-except
                    note = f"walk stopped: {exc}"
                    update(f"    [!] {vol['name']}: {note}\n")
                update(f"      {counts['file']:,} files, {counts['dir']:,} directories, "
                       f"{counts['other']:,} other, {deleted:,} deleted entries\n")
            totals["entries"] += counts["file"] + counts["dir"] + counts["other"]
            totals["deleted"] += deleted
            cursor.execute("INSERT OR REPLACE INTO image_volumes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (vol["name"] or vol["label"], vol["label"], vol["lba"],
                            vol["base"], vol["size"], vol["kind"], vol.get("detail", ""),
                            vol.get("missing_past_end", 0), 1 if walker is not None else 0,
                            basis, counts["file"], counts["dir"], counts["other"],
                            deleted, counts["dropped"], note))
        write_image_metadata(cursor, source_file_name=name, source_full_path=file_path,
                             image_type=image_type, media_size_bytes=media_size,
                             reader=READER, volumes_found=totals["volumes"],
                             volumes_walked=totals["walked"], extraction_timestamp=now,
                             note="", **acq)
    finally:
        try:
            fh.close()
        except Exception:                            # pylint: disable=broad-except
            pass
    return totals

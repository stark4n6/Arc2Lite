"""Tests for disk image and EnCase/EWF input.

Run from the repository root:

    python3 -m unittest discover -s tests -v

The fixtures beside this file are small filesystems built for the purpose. Each
is gzipped in the repository and decompressed into a temporary directory for the
run, so nothing here writes into the checkout.
"""

import gzip
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import arc2lite                                   # noqa: E402
import disk_image                                 # noqa: E402
from vendor import qnxprobe                       # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

# Each fixture, and what it is here to prove.
#   ntfs   real instants, all three dates, and deleted MFT records
#   fat32  a zone-less wall-clock reading, and deleted directory entries
#   exfat  the same, plus a deleted file inside a deleted directory
#   ext4   an instant for modified and nothing for created or accessed
RAW_FIXTURES = ("ntfs-fixture", "fat32-deleted", "exfat-deleted", "ext4-sparse")
E01_FIXTURE = "encase6-fast.E01"


def _stage(tmp, stem):
    """Decompress one fixture into tmp and return its path."""
    src = os.path.join(FIXTURES, stem + ".img.gz")
    dest = os.path.join(tmp, stem + ".img")
    with gzip.open(src, "rb") as fin, open(dest, "wb") as fout:
        shutil.copyfileobj(fin, fout)
    return dest


def _index(tmp, image_path):
    """Index one image into a fresh database and return the connection."""
    itype = disk_image.detect(image_path)
    db = sqlite3.connect(os.path.join(tmp, os.path.basename(image_path) + ".db"))
    cur = db.cursor()
    arc2lite.setup_db(cur)
    disk_image.index_image(image_path, cur, itype, lambda *a, **k: None)
    db.commit()
    return db


class WalkAgreesWithTheReader(unittest.TestCase):
    """walk_volume() keeps the directories qnxprobe's collect() drops, and
    reports exactly the same files. collect() is the reader's own tested walk,
    so it is the instrument this is measured against rather than a second
    opinion of my own."""

    def test_same_files_as_collect(self):
        with tempfile.TemporaryDirectory() as tmp:
            for stem in RAW_FIXTURES:
                image = _stage(tmp, stem)
                fh = qnxprobe.open_image(image)
                try:
                    vols = [v for v in qnxprobe.volumes(fh, qnxprobe.image_size(fh))
                            if v.get("walker")]
                    self.assertTrue(vols, f"{stem}: no walkable volume")
                    for vol in vols:
                        walker = vol["walker"]
                        theirs = {p for p, _n, size, _m
                                  in qnxprobe.collect(walker, walker.root)
                                  if size is not None}
                        mine = {p for p, _n, kind, _s, _m, _r
                                in disk_image.walk_volume(walker) if kind == "file"}
                        self.assertEqual(mine, theirs, f"{stem}/{vol['name']}")
                finally:
                    fh.close()

    def test_directories_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = _stage(tmp, "ntfs-fixture")
            fh = qnxprobe.open_image(image)
            try:
                vol = next(v for v in qnxprobe.volumes(fh, qnxprobe.image_size(fh))
                           if v.get("walker"))
                kinds = [k for _p, _n, k, _s, _m, _r
                         in disk_image.walk_volume(vol["walker"])]
                self.assertIn("dir", kinds)
                self.assertIn("file", kinds)
            finally:
                fh.close()


class DatesSayWhatTheyAre(unittest.TestCase):

    def test_fat_carries_the_reading_and_no_zone(self):
        """FAT32 and exFAT store a wall clock the writer converted with an
        offset the volume does not record, so no instant can be made from it.
        The reading is carried through as text and nothing puts a zone on it."""
        with tempfile.TemporaryDirectory() as tmp:
            for stem in ("fat32-deleted", "exfat-deleted"):
                db = _index(tmp, _stage(tmp, stem))
                rows = db.execute(
                    "SELECT f.created_date, f.modified_date, f.accessed_date, e.time_basis "
                    "FROM file_listing f JOIN image_entries e USING(entry_path)").fetchall()
                self.assertTrue(rows, stem)
                for created, modified, accessed, basis in rows:
                    self.assertEqual(basis, disk_image.READING, stem)
                    for value in (created, modified, accessed):
                        self.assertNotIn("+00:00", value or "", stem)
                        self.assertNotIn("T", value or "", stem)
                db.close()

    def test_ntfs_carries_three_instants(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = _index(tmp, _stage(tmp, "ntfs-fixture"))
            created, modified, accessed, basis = db.execute(
                "SELECT f.created_date, f.modified_date, f.accessed_date, e.time_basis "
                "FROM file_listing f JOIN image_entries e USING(entry_path) "
                "WHERE f.file_name = 'ads.txt'").fetchone()
            self.assertEqual(basis, disk_image.UTC)
            for value in (created, modified, accessed):
                self.assertTrue(value.endswith("+00:00"), value)
            db.close()

    def test_a_date_the_volume_does_not_hold_is_left_empty(self):
        """ext keeps a modified time this reader can reach and no created time,
        so the created column is empty. It is never filled from the modified
        time, which would put a date in the report the volume never recorded."""
        with tempfile.TemporaryDirectory() as tmp:
            db = _index(tmp, _stage(tmp, "ext4-sparse"))
            rows = db.execute(
                "SELECT created_date, modified_date, accessed_date FROM file_listing").fetchall()
            self.assertTrue(rows)
            for created, modified, accessed in rows:
                self.assertEqual(created, "")
                self.assertEqual(accessed, "")
                self.assertTrue(modified.endswith("+00:00"), modified)
            db.close()

    def test_a_date_before_1980_survives(self):
        """The archive path drops anything a zip cannot store. A filesystem can
        store it, so the image path keeps it."""
        self.assertEqual(disk_image.format_instant(1), "1970-01-01T00:00:01+00:00")
        self.assertEqual(disk_image.format_instant(0), "")
        self.assertEqual(disk_image.format_instant(None), "")


class Detection(unittest.TestCase):

    def test_later_segments_of_a_split_set_are_not_indexed_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            whole = _stage(tmp, "fat32-deleted")
            with open(whole, "rb") as fh:
                data = fh.read()
            os.remove(whole)
            half = len(data) // 2
            for i, chunk in enumerate((data[:half], data[half:]), start=1):
                with open(os.path.join(tmp, f"split.{i:03d}"), "wb") as fh:
                    fh.write(chunk)
            self.assertEqual(disk_image.detect(os.path.join(tmp, "split.001")), "RAW")
            self.assertIsNone(disk_image.detect(os.path.join(tmp, "split.002")))

    def test_a_set_numbered_from_zero_is_found_at_its_first_segment(self):
        """Some writers number a split set from .000. The set is joined from
        whichever segment is first, so a rule that only knew .001 would pass
        over the whole set while looking as though it had handled it."""
        with tempfile.TemporaryDirectory() as tmp:
            whole = _stage(tmp, "fat32-deleted")
            with open(whole, "rb") as fh:
                data = fh.read()
            os.remove(whole)
            half = len(data) // 2
            for i, chunk in enumerate((data[:half], data[half:])):
                with open(os.path.join(tmp, f"zeroed.{i:03d}"), "wb") as fh:
                    fh.write(chunk)
            self.assertEqual(disk_image.detect(os.path.join(tmp, "zeroed.000")), "RAW")
            self.assertIsNone(disk_image.detect(os.path.join(tmp, "zeroed.001")))

    def test_only_the_first_ewf_segment_is_indexed(self):
        path = os.path.join(FIXTURES, E01_FIXTURE)
        self.assertEqual(disk_image.detect(path), "E01")
        with tempfile.TemporaryDirectory() as tmp:
            later = os.path.join(tmp, "copy.E02")
            shutil.copyfile(path, later)
            self.assertIsNone(disk_image.detect(later))

    def test_a_bin_holding_no_volume_is_not_claimed(self):
        """.bin is given to firmware as readily as to a disk, so it is claimed
        only when the reader finds a volume in it."""
        with tempfile.TemporaryDirectory() as tmp:
            noise = os.path.join(tmp, "firmware.bin")
            with open(noise, "wb") as fh:
                fh.write(b"\xa5" * 4096)
            self.assertIsNone(disk_image.detect(noise))

    def test_an_archive_is_still_an_archive(self):
        """The image check runs after the archive checks, so adding it cannot
        change what Arc2Lite makes of a zip, a tar or a gz."""
        with tempfile.TemporaryDirectory() as tmp:
            import zipfile
            path = os.path.join(tmp, "a.zip")
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("inside.txt", "x" * 1024)
            self.assertEqual(arc2lite.get_forensic_type(path), "ZIP")


class TheTablesBesideFileListing(unittest.TestCase):

    def test_file_listing_keeps_its_shape(self):
        """Existing Arc2Lite databases are read by column position as well as
        by name. Image rows go into the table as it already is."""
        with tempfile.TemporaryDirectory() as tmp:
            db = _index(tmp, _stage(tmp, "ntfs-fixture"))
            names = [c[1] for c in db.execute("PRAGMA table_info(file_listing)")]
            self.assertEqual(names, [
                "file_name", "file_extension", "entry_path", "created_date",
                "modified_date", "accessed_date", "is_file", "size", "comp_size"])
            db.close()

    def test_every_listed_entry_has_a_row_saying_what_it_is(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = _index(tmp, _stage(tmp, "ntfs-fixture"))
            listed = db.execute("SELECT count(*) FROM file_listing").fetchone()[0]
            described = db.execute("SELECT count(*) FROM image_entries").fetchone()[0]
            orphans = db.execute(
                "SELECT count(*) FROM file_listing WHERE entry_path NOT IN "
                "(SELECT entry_path FROM image_entries)").fetchone()[0]
            self.assertEqual(listed, described)
            self.assertEqual(orphans, 0)
            db.close()

    def test_the_volume_row_counts_what_was_listed(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = _index(tmp, _stage(tmp, "ntfs-fixture"))
            name, files, dirs, other, basis, walked = db.execute(
                "SELECT volume_name, file_count, dir_count, other_count, time_basis, walked "
                "FROM image_volumes").fetchone()
            self.assertEqual(walked, 1)
            self.assertEqual(basis, disk_image.UTC)
            for kind, expected in (("file", files), ("dir", dirs)):
                got = db.execute("SELECT count(*) FROM image_entries WHERE entry_type=?",
                                 (kind,)).fetchone()[0]
                self.assertEqual(got, expected, kind)
            self.assertEqual(
                files + dirs + other,
                db.execute("SELECT count(*) FROM image_entries").fetchone()[0])
            self.assertTrue(db.execute(
                "SELECT count(*) FROM file_listing WHERE entry_path LIKE ?",
                (name + "/%",)).fetchone()[0])
            db.close()

    def test_an_e01_records_what_the_acquisition_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = _index(tmp, os.path.join(FIXTURES, E01_FIXTURE))
            row = dict(zip([c[0] for c in db.execute(
                "SELECT * FROM image_metadata LIMIT 0").description],
                db.execute("SELECT * FROM image_metadata").fetchone()))
            self.assertEqual(row["image_type"], "E01")
            self.assertEqual(len(row["acquisition_md5"]), 32)
            self.assertEqual(len(row["acquisition_sha1"]), 40)
            self.assertTrue(row["media_size_bytes"] > 0)
            self.assertEqual(json.loads(row["segments"]), [E01_FIXTURE])
            # the acquisition's own reading of when it ran, kept as it wrote it
            self.assertNotIn("+00:00", row["acquisition_date"])
            db.close()


class DeletedEntries(unittest.TestCase):

    def test_ntfs_deleted_records_carry_instants_and_a_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = _index(tmp, _stage(tmp, "ntfs-fixture"))
            rows = db.execute(
                "SELECT file_name, parent_path, identifier, time_basis, modified_date, "
                "recoverable FROM image_deleted_files").fetchall()
            self.assertTrue(rows)
            for name, parent, ident, basis, modified, recoverable in rows:
                self.assertEqual(basis, disk_image.UTC)
                self.assertTrue(ident.startswith("MFT record "))
                self.assertIn(recoverable, (0, 1))
                if modified:
                    self.assertTrue(modified.endswith("+00:00"))
            # a file deleted from the top of the volume names the volume, not ''
            top = [p for _n, p, _i, _b, _m, _r in rows if p]
            self.assertTrue(top, "no deleted entry resolved to a parent")
            db.close()

    def test_a_file_deleted_inside_a_deleted_directory_says_so(self):
        """Its parent was deleted too, so the parent was never walked and no
        path can be resolved for it. The flag is what says why, rather than the
        empty path being left to explain itself."""
        with tempfile.TemporaryDirectory() as tmp:
            db = _index(tmp, _stage(tmp, "exfat-deleted"))
            orphans = db.execute(
                "SELECT count(*) FROM image_deleted_files "
                "WHERE in_deleted_directory = 1 AND parent_path = ''").fetchone()[0]
            self.assertTrue(orphans)
            db.close()


if __name__ == "__main__":
    unittest.main()

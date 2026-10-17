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
import re
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import arc2lite                                   # noqa: E402
import disk_image                                 # noqa: E402
from vendor import qnxprobe                       # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

# Each fixture, and what it is here to prove.
#   ntfs   real instants, all three dates, and deleted MFT records
#   apfs   a container of several volumes, reached in one pass over its tree
#   fat32  a zone-less wall-clock reading, and deleted directory entries
#   exfat  the same, plus a deleted file inside a deleted directory
#   ext4   an instant for modified and nothing for created or accessed
#   fat16, fat12  FAT with a 16-bit and a 12-bit table and a fixed root, as macOS
#          wrote them
#   tfat16 the layout of Windows CE's transaction-safe FAT: 2,048-byte sectors,
#          the TFAT16 type string, and every file under one root folder. macOS
#          wrote it and qnxprobe's builder set the boot sector, so it stands in
#          for the layout, not for Windows CE's driver
#   ntfs-windows  a volume Windows 11 wrote: sparse files, NTFS compression,
#          overlay (WOF) compression and cloud placeholders, beside
#          ntfs-windows.known.tsv, which is what Windows reported for each file
#
# The .sha256 files beside them are the listings the vendored reader's own
# self-test compares its walk against, and they are here so that check runs
# rather than skipping when this repository's copy of the reader is tested.
RAW_FIXTURES = ("ntfs-fixture", "apfs-fixture", "fat32-deleted", "exfat-deleted",
                "ext4-sparse", "ntfs-windows", "fat16-fixture", "tfat16-fixture",
                "fat12-fixture")
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

    def test_no_path_is_reported_twice(self):
        """A path reported twice is a row that loses to INSERT OR IGNORE, and
        the set comparison above cannot see it because a set collapses it.

        The NTFS fixture holds eight extension records that carry a copy of
        their base record's $FILE_NAME, which is exactly what produces this
        when a reader counts them as files of their own.
        """
        with tempfile.TemporaryDirectory() as tmp:
            for stem in RAW_FIXTURES:
                image = _stage(tmp, stem)
                fh = qnxprobe.open_image(image)
                try:
                    for vol in qnxprobe.volumes(fh, qnxprobe.image_size(fh)):
                        if not vol.get("walker"):
                            continue
                        paths = [p for p, _n, _k, _s, _m, _r
                                 in disk_image.walk_volume(vol["walker"])]
                        dupes = [p for p in set(paths) if paths.count(p) > 1]
                        self.assertEqual(dupes, [], f"{stem}/{vol['name']}")
                finally:
                    fh.close()
                db = _index(tmp, image)
                dropped = db.execute(
                    "SELECT sum(dropped_duplicate_paths) FROM image_volumes").fetchone()[0]
                self.assertEqual(dropped, 0, stem)
                db.close()

    def test_the_vendored_reader_passes_its_own_self_test(self):
        """The readers in vendor/ are copies, and their own tests are where
        they are proven: they reach code this repository's fixtures cannot,
        such as the DOS 8.3 names a Windows volume is full of and neither
        fixture here carries. Running it is what catches a bad re-vendor.
        """
        import subprocess
        vendored = os.path.abspath(os.path.join(os.path.dirname(FIXTURES), os.pardir,
                                                "vendor", "qnxprobe.py"))
        # Its fixture checks look for tests/fixtures beside itself, and in
        # vendor/ there are none, so it would skip exactly the comparisons that
        # matter. Standing it in a directory with this repository's fixtures
        # under that name runs them, which means the vendored reader is proven
        # against the same images the tests above use.
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copyfile(vendored, os.path.join(tmp, "qnxprobe.py"))
            shutil.copyfile(os.path.join(os.path.dirname(vendored), "ewfprobe.py"),
                            os.path.join(tmp, "ewfprobe.py"))
            shutil.copytree(FIXTURES, os.path.join(tmp, "tests", "fixtures"))
            r = subprocess.run([sys.executable, os.path.join(tmp, "qnxprobe.py"),
                                "--self-test"],
                               capture_output=True, text=True, timeout=900)
        self.assertEqual(r.returncode, 0, r.stdout[-4000:])
        self.assertIn("SELF-TEST PASSED", r.stdout)
        # the checks that need no fixture, and the ones that need ours
        self.assertIn("$FILE_NAME: its 8.3 twin is dropped", r.stdout)
        self.assertIn("walk_all() reports exactly what a walk of the directory "
                      "tree reports", r.stdout)
        # the count, not just the sentence: a check whose verdict was removed
        # still prints its headline
        got = re.search(r"entries over (\d+) volume\(s\), (\d+) disagreement", r.stdout)
        self.assertIsNotNone(got, r.stdout[-3000:])
        self.assertGreater(int(got.group(1)), 0)
        self.assertEqual(int(got.group(2)), 0)
        # and the ones that need the volume Windows wrote
        self.assertIn("the cloud placeholders Windows would not read are refused",
                      r.stdout)
        self.assertIn("(3 of 3 refused, 3 placeholders)", r.stdout)
        self.assertIn("[PASS] an NTFS-compressed file with a unit that stops at a zero "
                      "chunk header reads at its full length", r.stdout)
        # and the ones that need the FAT16 and FAT12 volumes
        self.assertIn("[PASS] every file of the FAT16 volume a driver wrote reads back",
                      r.stdout)
        self.assertIn("[PASS] every file of the TFAT16 volume a driver wrote reads back",
                      r.stdout)
        self.assertIn("[PASS] every file of the FAT12 volume a driver wrote reads back",
                      r.stdout)
        self.assertNotIn("[FAIL]", r.stdout)

    def test_a_volume_windows_wrote_lists_every_file_at_the_length_windows_gave(self):
        """Sparse files, compressed files and a cloud provider's online-only
        placeholders are all listed, each at the length Windows reported. A
        placeholder's content is not in the image, and its row is still there:
        the listing says the file existed, with its size and dates."""
        known = {}
        with open(os.path.join(FIXTURES, "ntfs-windows.known.tsv"),
                  encoding="utf-8", newline="") as fh:
            for line in fh:
                if line.startswith("#") or not line.strip():
                    continue
                path, length, _attrs, _on_disk, _sha, windows = line.rstrip("\n").split("\t")
                known[path] = (int(length), windows)
        self.assertEqual(len(known), 35)
        refused = {p for p, (_n, windows) in known.items() if windows == "refused"}
        self.assertEqual(len(refused), 3)
        with tempfile.TemporaryDirectory() as tmp:
            db = _index(tmp, _stage(tmp, "ntfs-windows"))
            listed = {path.split("/", 1)[1]: size for path, size in db.execute(
                "SELECT entry_path, size FROM file_listing WHERE is_file = 1")}
            db.close()
        self.assertEqual({p: listed.get(p) for p in known},
                         {p: length for p, (length, _w) in known.items()})

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


class EncryptedImages(unittest.TestCase):
    """An encrypted image opens only with its password, or with the private key of
    a certificate it is sealed to, and Arc2Lite takes neither. Under a name Arc2Lite
    reads as an image it is listed with a note saying so, instead of being passed
    over. The header says an image is encrypted, so these files are a header and
    filler; which key opens one is the reader's answer, and it is stood in for
    below where the test is about the wording."""

    AD_HEADER = b"ADCRYPT\x00"          # FTK Imager AD encryption
    DMG_HEADER = b"encrcdsa"            # an encrypted Apple disk image

    def _write(self, tmp, name, head):
        path = os.path.join(tmp, name)
        with open(path, "wb") as fh:
            fh.write(head + os.urandom(4096))
        return path

    def _note(self, tmp, path):
        db = _index(tmp, path)
        try:
            (note, found), = db.execute("SELECT note, volumes_found FROM image_metadata")
            self.assertEqual(found, 0)
            self.assertEqual(db.execute("SELECT count(*) FROM file_listing").fetchone()[0], 0)
            return note
        finally:
            db.close()

    def test_an_ad_encrypted_e01_is_listed_as_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self._write(tmp, "case.E01", self.AD_HEADER)
            later = self._write(tmp, "case.E02", b"")
            self.assertEqual(disk_image.detect(first), "E01")
            self.assertIsNone(disk_image.detect(later))
            note = self._note(tmp, first)
            self.assertIn("AD encryption", note)
            self.assertIn("not read", note)

    def test_an_ad_encrypted_raw_set_is_listed_once_from_its_first_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self._write(tmp, "set.001", self.AD_HEADER)
            later = self._write(tmp, "set.002", b"")
            self.assertEqual(disk_image.detect(first), "RAW")
            self.assertIsNone(disk_image.detect(later))
            self.assertIn("not read", self._note(tmp, first))

    def test_an_encrypted_apple_image_under_an_image_name_says_how_to_read_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "locked.img", self.DMG_HEADER)
            self.assertEqual(disk_image.detect(path), "RAW")
            note = self._note(tmp, path)
            self.assertIn("not read", note)
            self.assertIn("hdiutil convert", note)

    def test_an_image_sealed_to_a_certificate_names_its_private_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "sealed.E01", self.AD_HEADER)
            with mock.patch.object(qnxprobe, "needs_password", return_value=False), \
                    mock.patch.object(qnxprobe, "needs_private_key", return_value=True):
                self.assertEqual(disk_image.detect(path), "E01")
                note = self._note(tmp, path)
            self.assertIn("the private key of a certificate it is sealed to", note)
            self.assertNotIn("its password", note)

    def test_an_encrypted_set_is_listed_when_the_reader_cannot_say_what_opens_it(self):
        """Without the optional pycryptodome package, which Arc2Lite does not
        install, the reader cannot tell a password from a private key, and says
        neither is needed. The header still says the set is encrypted."""
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "case.E01", self.AD_HEADER)
            with mock.patch.object(qnxprobe, "needs_password", return_value=False), \
                    mock.patch.object(qnxprobe, "needs_private_key", return_value=False):
                self.assertEqual(disk_image.detect(path), "E01")
                note = self._note(tmp, path)
            self.assertIn("its password or the private key", note)
            self.assertIn("not read", note)

    def test_an_e01_that_is_neither_ewf_nor_encrypted_is_not_claimed(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(disk_image.detect(self._write(tmp, "notes.E01", b"")))


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



class LogicalVolumes(unittest.TestCase):
    """The LVM2 fixture qnxprobe's own tests use (written by lvm2 in an Ubuntu
    VM; tools/make_lvm_fixtures.sh there): logical volumes that are one run of
    extents, split into runs, striped, and RAID1, on two physical volumes."""

    def test_every_file_lvm_wrote_is_listed_under_its_logical_volume(self):
        want = set()
        with open(os.path.join(FIXTURES, "lvm-fixture.sha256"), encoding="utf-8") as f:
            for line in f:
                lv, rel = line.rstrip("\n").split("  ", 1)[1].split("/", 1)
                want.add((f"LVM fixvg/{lv}", rel))
        with tempfile.TemporaryDirectory() as tmp:
            db = _index(tmp, _stage(tmp, "lvm-fixture"))
            got = set(db.execute(
                "SELECT v.partition_label, substr(f.entry_path, length(v.volume_name) + 2) "
                "FROM file_listing f JOIN image_volumes v "
                "ON f.entry_path LIKE v.volume_name || '/%' WHERE f.is_file = 1"))
            db.close()
        self.assertEqual(got, want)

    def test_a_volume_read_through_a_map_has_no_offset_and_names_its_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = _index(tmp, _stage(tmp, "lvm-fixture"))
            rows = {r[0]: r[1:] for r in db.execute(
                "SELECT partition_label, lba, byte_offset, walked, detail FROM image_volumes "
                "WHERE partition_label IN ('LVM fixvg/data', 'LVM fixvg/striped', 'LVM fixvg/root')")}
            db.close()
        for label in ("LVM fixvg/data", "LVM fixvg/striped"):
            lba, offset, walked, detail = rows[label]
            self.assertEqual((lba, offset, walked), (None, None, 1), label)
            self.assertIn("runs: [", detail, label)
        lba, offset, walked, detail = rows["LVM fixvg/root"]
        self.assertEqual((lba, offset, walked), (4096, 4096 * 512, 1))
        self.assertNotIn("runs:", detail)

    def test_a_luks_container_is_listed_as_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = _index(tmp, _stage(tmp, "luks1-cbc"))
            rows = db.execute("SELECT filesystem, walked, note FROM image_volumes").fetchall()
            entries = db.execute("SELECT count(*) FROM image_entries").fetchone()[0]
            db.close()
        self.assertEqual([(r[0], r[1]) for r in rows], [("luks", 0)])
        self.assertIn("LUKS-encrypted and not read", rows[0][2])
        self.assertEqual(entries, 0)


class XfsBtrfsRefsAndRaidMembers(unittest.TestCase):
    """qnxprobe's own fixtures for the readers 1.68 to 1.71 add, under their
    names there: xfs-v5-4kn (mkfs.xfs from a source tree, with that tree's
    listing and hashes in its .known.json.gz), btrfs-zlib (mkfs.btrfs from a
    source tree, btrfs.src.sha256 hashed from it), refs-fixture (the bytes
    the reader reads of a volume Windows 11 wrote, with what Windows reported
    in its .known.tsv.gz), and md-r1-0 and md-ddf-0, one member each of an md
    RAID1 array and of a RAID5 array with DDF metadata, which mdadm wrote."""

    def _listed_files(self, db):
        return {r[0].split("/", 1)[1] for r in db.execute(
            "SELECT entry_path FROM file_listing WHERE is_file = 1")}

    def test_every_file_of_an_xfs_volume_is_listed(self):
        with gzip.open(os.path.join(FIXTURES, "xfs-v5-4kn.known.json.gz"), "rt",
                       encoding="utf-8") as f:
            known = json.load(f)["entries"]
        with tempfile.TemporaryDirectory() as tmp:
            db = _index(tmp, _stage(tmp, "xfs-v5-4kn"))
            entries = {r[0].split("/", 1)[1]: r[1] for r in db.execute(
                "SELECT entry_path, entry_type FROM image_entries")}
            row = db.execute("SELECT filesystem, walked, note FROM image_volumes").fetchall()
            db.close()
        self.assertEqual(row, [("xfs", 1, "")])
        want = {e["path"]: e["type"] for e in known}
        self.assertEqual(len(want), 146)
        self.assertEqual({p: {"file": "file", "dir": "dir", "symlink": "link"}.get(t, "special")
                          for p, t in want.items()}, entries)

    def test_every_file_of_a_btrfs_volume_is_listed(self):
        with open(os.path.join(FIXTURES, "btrfs.src.sha256"), encoding="utf-8") as f:
            want = {line.rstrip("\n").split("  ", 1)[1] for line in f if line.strip()}
        with tempfile.TemporaryDirectory() as tmp:
            db = _index(tmp, _stage(tmp, "btrfs-zlib"))
            entries = {r[0].split("/", 1)[1] for r in db.execute(
                "SELECT entry_path FROM image_entries WHERE entry_type = 'file'")}
            row = db.execute("SELECT filesystem, walked FROM image_volumes").fetchall()
            db.close()
        self.assertEqual(row, [("btrfs", 1)])
        self.assertEqual(len(want), 572)
        self.assertEqual(entries, want)

    def test_damage_the_reader_records_while_walking_is_in_the_volume_note(self):
        """An XFS inode that fails its CRC is skipped by the reader while the
        volume is walked, after volumes() wrote the note; the note says so."""
        with gzip.open(os.path.join(FIXTURES, "xfs-v5-4kn.img.gz"), "rb") as f:
            data = bytearray(f.read())
        walker = qnxprobe.XfsWalker(qnxprobe._XfsPatchedImage(bytes(data)), 0)
        hello = next(n for p, n, *_r in qnxprobe.walk_all(walker) if p == "hello.txt")
        data[walker.inode_offset(hello) + 60] ^= 0x01
        with tempfile.TemporaryDirectory() as tmp:
            image = os.path.join(tmp, "xfs-damaged.img")
            with open(image, "wb") as f:
                f.write(bytes(data))
            db = _index(tmp, image)
            note = db.execute("SELECT note FROM image_volumes").fetchone()[0]
            listed = self._listed_files(db)
            db.close()
        self.assertNotIn("hello.txt", listed)
        self.assertIn("1 damaged structure(s) recorded and skipped", note)
        self.assertIn("fails its CRC", note)

    def test_every_file_of_a_refs_volume_is_listed_and_its_handle_stored(self):
        """A ReFS file's handle holds its name as stored (bytes); the walk used
        to stop at the first file because JSON has no type for bytes."""
        with gzip.open(os.path.join(FIXTURES, "refs-fixture.bin.gz"), "rb") as f:
            image = qnxprobe._RefsSparseImage(f.read())
        with gzip.open(os.path.join(FIXTURES, "refs-fixture.known.tsv.gz"), "rt",
                       encoding="utf-8") as f:
            lines = f.read().splitlines()
        head = lines[0].split("\t")
        known = [dict(zip(head, line.split("\t"))) for line in lines[1:]]
        db = sqlite3.connect(":memory:")
        cur = db.cursor()
        arc2lite.setup_db(cur)
        disk_image.setup_image_db(cur)
        vol = {"name": "refs", "kind": "refs", "walker": qnxprobe.RefsWalker(image, 0)}
        counts, _dirs, basis = disk_image._index_volume(cur, vol, lambda *a, **k: None)
        files = {r[0].split("/", 1)[1] for r in db.execute(
            "SELECT entry_path FROM image_entries WHERE entry_type = 'file'")}
        nodes = [json.loads(r[0]) for r in db.execute("SELECT node FROM image_entries")]
        db.close()
        want = {k["path"] for k in known if k["kind"] == "file"}
        self.assertEqual(basis, disk_image.UTC)
        self.assertEqual(len(want), 2544)
        self.assertEqual({p for p in files if not p.startswith("System Volume Information")},
                         want)
        self.assertEqual(counts["file"], len(files))
        self.assertTrue(any(isinstance(n, list) for n in nodes))

    def test_one_raid_member_alone_is_listed_as_not_walked(self):
        with tempfile.TemporaryDirectory() as tmp:
            md = _index(tmp, _stage(tmp, "md-r1-0"))
            md_rows = md.execute("SELECT filesystem, walked, note FROM image_volumes").fetchall()
            md_entries = md.execute("SELECT count(*) FROM file_listing").fetchone()[0]
            md.close()
            ddf = _index(tmp, _stage(tmp, "md-ddf-0"))
            ddf_rows = ddf.execute("SELECT filesystem, walked, note FROM image_volumes").fetchall()
            ddf.close()
        self.assertEqual(md_rows, [("linux md member", 0, disk_image.MD_MEMBER_NOTE)])
        self.assertEqual(md_entries, 0)
        self.assertEqual([(r[0], r[1]) for r in ddf_rows], [("raid member", 0)])
        self.assertIn("a member of a DDF RAID set, whose array is not assembled here",
                      ddf_rows[0][2])

if __name__ == "__main__":
    unittest.main()

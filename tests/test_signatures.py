"""Tests for -sig/--check-signatures (and the GUI's matching "Check file
signatures" checkbox): detect_signature_family()/check_signature() in
isolation, then wired into the ZIP/TAR archive path (process_archive_logic())
and the disk-image path (disk_image._index_volume()/_read_header()).

Run from the repository root:

    python3 -m unittest discover -s tests -v
"""

import gzip
import os
import shutil
import sqlite3
import sys
import tarfile
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import arc2lite                                   # noqa: E402
import disk_image                                 # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _stage(tmp, stem):
    src = os.path.join(FIXTURES, stem + ".img.gz")
    dest = os.path.join(tmp, stem + ".img")
    with gzip.open(src, "rb") as fin, open(dest, "wb") as fout:
        shutil.copyfileobj(fin, fout)
    return dest


class DetectsTheSignatureFamily(unittest.TestCase):

    def test_recognised_headers(self):
        cases = [
            (b"\xFF\xD8\xFF\xE0\x00\x10JFIF", "jpeg"),
            (b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR", "png"),
            (b"GIF89a" + b"\x00" * 10, "gif"),
            (b"BM" + b"\x00" * 10, "bmp"),
            (b"%PDF-1.7\n", "pdf"),
            (b"PK\x03\x04" + b"\x00" * 20, "zip_container"),
            (b"7z\xBC\xAF\x27\x1C\x00\x04", "7z"),
            (b"\x1f\x8b\x08\x00", "gzip"),
            (b"BZh91AY", "bzip2"),
            (b"\xfd7zXZ\x00\x00", "xz"),
            (b"\x00" * 257 + b"ustar\x0000", "tar"),
            (b"MZ\x90\x00", "exe"),
            (b"\x7fELF\x02\x01\x01", "elf"),
            (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "ole_document"),
            (b"SQLite format 3\x00", "sqlite"),
            (b"{\\rtf1\\ansi", "rtf"),
            (b"RIFF\x00\x00\x00\x00WAVEfmt ", "riff"),
        ]
        for header, expected in cases:
            self.assertEqual(arc2lite.detect_signature_family(header), expected, header[:8])

    def test_unrecognised_header_is_none(self):
        self.assertIsNone(arc2lite.detect_signature_family(b"not a real header at all"))
        self.assertIsNone(arc2lite.detect_signature_family(b""))


class ChecksOneEntrysSignature(unittest.TestCase):

    def test_matching_extension_is_not_a_mismatch(self):
        self.assertIsNone(arc2lite.check_signature("photo.jpg", b"\xFF\xD8\xFF\xE0"))
        self.assertIsNone(arc2lite.check_signature("archive.zip", b"PK\x03\x04"))

    def test_mismatched_extension_reports_both_sides(self):
        # A .jpg that's actually a PNG under the hood.
        self.assertEqual(
            arc2lite.check_signature("photo.jpg", b"\x89PNG\r\n\x1a\n"),
            ("jpeg", "png"))

    def test_content_matching_no_known_family_is_unknown(self):
        self.assertEqual(
            arc2lite.check_signature("notes.pdf", b"just plain text, not a pdf"),
            ("pdf", "unknown"))

    def test_untracked_extension_is_never_flagged(self):
        # .xyz isn't in _EXTENSION_FAMILY, so there's nothing to compare
        # against, regardless of what the bytes actually are.
        self.assertIsNone(arc2lite.check_signature("mystery.xyz", b"\x89PNG\r\n\x1a\n"))

    def test_empty_header_is_never_flagged(self):
        # A 0-byte file, or one _read_header() couldn't read.
        self.assertIsNone(arc2lite.check_signature("photo.jpg", b""))

    def test_case_insensitive_extension(self):
        self.assertEqual(
            arc2lite.check_signature("PHOTO.JPG", b"\x89PNG\r\n\x1a\n"),
            ("jpeg", "png"))


class FlagsMismatchesInsideAnArchive(unittest.TestCase):
    """process_archive_logic()'s ZIP and TAR branches, with -sig on."""

    def _zip_with_a_renamed_file(self, tmp):
        zip_path = os.path.join(tmp, "evidence.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            # A real signature that doesn't match its extension.
            zf.writestr("photo.jpg", b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
            # A correctly-named file beside it, so the good file is proven
            # not to also get flagged.
            zf.writestr("readme.txt", "hi there " * 20)
        return zip_path

    def test_zip_entry_mismatch_is_recorded_only_when_asked_for(self):
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = self._zip_with_a_renamed_file(tmp)

            db_path = arc2lite.process_archive_logic(
                zip_path, tmp, 1, "ZIP", None, None, check_signatures=True)

            conn = sqlite3.connect(db_path)
            try:
                rows = conn.execute(
                    "SELECT entry_path, file_extension, expected_type, detected_type "
                    "FROM signature_mismatches").fetchall()
            finally:
                conn.close()
            self.assertEqual(rows, [("photo.jpg", ".jpg", "jpeg", "png")])

    def test_opt_out_by_default_records_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = self._zip_with_a_renamed_file(tmp)

            db_path = arc2lite.process_archive_logic(zip_path, tmp, 1, "ZIP", None, None)

            conn = sqlite3.connect(db_path)
            try:
                rows = conn.execute("SELECT * FROM signature_mismatches").fetchall()
            finally:
                conn.close()
            self.assertEqual(rows, [])

    def test_tar_entry_mismatch_is_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            tar_path = os.path.join(tmp, "evidence.tar")
            payload = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
            with tarfile.open(tar_path, "w") as tf:
                import io
                info = tarfile.TarInfo(name="photo.jpg")
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))

            db_path = arc2lite.process_archive_logic(
                tar_path, tmp, 1, "TAR", None, None, check_signatures=True)

            conn = sqlite3.connect(db_path)
            try:
                rows = conn.execute(
                    "SELECT entry_path, expected_type, detected_type "
                    "FROM signature_mismatches").fetchall()
            finally:
                conn.close()
            self.assertEqual(rows, [("photo.jpg", "jpeg", "png")])


class ReadsAFilesHeaderFromAnImage(unittest.TestCase):
    """disk_image._read_header(), against a fake walker so this doesn't need
    a real filesystem -- read_file() is a generator across every reader in
    qnxprobe, so this is what proves the draining/joining is correct."""

    class _FakeWalker:
        def __init__(self, chunks=None, raises=False):
            self._chunks = chunks if chunks is not None else [b"abc", b"def"]
            self._raises = raises

        def read_file(self, node, size):
            if self._raises:
                raise RuntimeError("unreadable")
            sent = 0
            for chunk in self._chunks:
                if sent >= size:
                    return
                yield chunk[:size - sent]
                sent += len(chunk)

    def test_joins_chunks_up_to_the_requested_size(self):
        walker = self._FakeWalker([b"abc", b"defgh"])
        self.assertEqual(disk_image._read_header(walker, "node", 100, 6), b"abcdef")

    def test_zero_or_missing_size_reads_nothing(self):
        walker = self._FakeWalker()
        self.assertEqual(disk_image._read_header(walker, "node", 0, 64), b"")
        self.assertEqual(disk_image._read_header(walker, "node", None, 64), b"")

    def test_an_unreadable_file_is_none_not_empty(self):
        # None (couldn't read) must stay distinguishable from b"" (really
        # empty), since check_signature() treats an empty header as
        # "nothing to flag" -- an unreadable file should be skipped instead,
        # not silently treated as a 0-byte file.
        walker = self._FakeWalker(raises=True)
        self.assertIsNone(disk_image._read_header(walker, "node", 100, 64))


class FlagsMismatchesInsideADiskImage(unittest.TestCase):
    """index_image()/_index_volume() actually calling a check_signatures
    callback against a real fixture image, end to end."""

    def test_every_real_file_gets_a_non_empty_header(self):
        # Doesn't require the fixture to contain any real mismatch: this
        # proves the header-reading plumbing (index_image -> _index_volume
        # -> _read_header -> the callback) actually delivers real bytes read
        # from the volume, for every file the walk reports.
        seen = []

        def spy(entry_path, header):
            seen.append((entry_path, header))
            return None

        with tempfile.TemporaryDirectory() as tmp:
            image = _stage(tmp, "fat32-deleted")
            db_path = os.path.join(tmp, "listing.db")
            conn = sqlite3.connect(db_path)
            try:
                cursor = conn.cursor()
                arc2lite.setup_db(cursor)
                disk_image.index_image(image, cursor, "RAW", lambda *a, **k: None,
                                        check_signatures=spy)
                conn.commit()
            finally:
                conn.close()

        self.assertTrue(seen, "check_signatures callback was never called")
        for entry_path, header in seen:
            self.assertIsInstance(header, (bytes, bytearray))
            self.assertTrue(len(header) > 0, entry_path)

    def test_a_flagged_mismatch_lands_in_the_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = _stage(tmp, "fat32-deleted")
            db_path = os.path.join(tmp, "listing.db")
            conn = sqlite3.connect(db_path)
            try:
                cursor = conn.cursor()
                arc2lite.setup_db(cursor)
                # A stub standing in for arc2lite.check_signature: flag the
                # very first file it's asked about, so this doesn't depend
                # on the fixture actually containing a real mismatch.
                flagged = {}
                def stub(entry_path, header):
                    if not flagged:
                        flagged["path"] = entry_path
                        return ("jpeg", "unknown")
                    return None
                disk_image.index_image(image, cursor, "RAW", lambda *a, **k: None,
                                        check_signatures=stub)
                conn.commit()
                rows = cursor.execute(
                    "SELECT entry_path, expected_type, detected_type "
                    "FROM signature_mismatches").fetchall()
            finally:
                conn.close()

            self.assertEqual(rows, [(flagged["path"], "jpeg", "unknown")])

    def test_no_callback_means_no_reads_and_nothing_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = _stage(tmp, "fat32-deleted")
            db_path = os.path.join(tmp, "listing.db")
            conn = sqlite3.connect(db_path)
            try:
                cursor = conn.cursor()
                arc2lite.setup_db(cursor)
                disk_image.index_image(image, cursor, "RAW", lambda *a, **k: None)
                conn.commit()
                rows = cursor.execute("SELECT * FROM signature_mismatches").fetchall()
            finally:
                conn.close()
            self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
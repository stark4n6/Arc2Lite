"""Tests for apply_export_choice() -- what -e/--export (and the GUI's
matching SQLite/CSV/Timeline checkboxes) calls per database -- and the CSV
writer underneath it, export_tables_to_csv().

See tests/test_export_switch.py for -e/--export exercised end to end
through run_cli(), and tests/test_timeline.py for the bodyfile writer
apply_export_choice() calls when 'timeline' is chosen.

Run from the repository root:

    python3 -m unittest discover -s tests -v
"""

import csv
import os
import sqlite3
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import arc2lite                                   # noqa: E402


def _build_db(db_path):
    """A small file_listing/archive_metadata database, the same shape
    process_archive_logic() produces for one archive."""
    # Closed explicitly rather than left to "with sqlite3.connect() as conn:"
    # (which only commits, never closes): on Windows a lingering open handle
    # keeps the file locked, and the temp-dir cleanup below then fails.
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        arc2lite.setup_db(cursor)
        cursor.execute(
            "INSERT INTO file_listing VALUES (?,?,?,?,?,?,?,?,?)",
            ("readme.txt", ".txt", "docs/readme.txt", "", "2024-01-01T00:00:00+00:00",
             None, 1, 42, 42))
        cursor.execute(
            "INSERT INTO file_listing VALUES (?,?,?,?,?,?,?,?,?)",
            ("docs", "", "docs", "", "", "", 0, None, None))
        cursor.execute(
            "INSERT INTO archive_metadata VALUES (?,?,?,?,?,?,?)",
            ("evidence.zip", "/tmp/evidence.zip", "ZIP", 1024, "md5", "d41d8cd98f00b204e9800998ecf8427e",
             "2024-01-01T00:00:00+00:00"))
        conn.commit()
    finally:
        conn.close()


class ExportsEveryTableToItsOwnCsv(unittest.TestCase):

    def test_csv_folder_and_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "1-evidence.zip_file_listing.db")
            _build_db(db_path)

            written = arc2lite.export_tables_to_csv(db_path)

            csv_dir = os.path.join(tmp, "1-evidence.zip_file_listing_csv")
            self.assertEqual(
                sorted(written),
                # signature_mismatches is always in setup_db()'s schema (see
                # check_signature()), so it always gets its own CSV here too,
                # empty or not -- the same way archive_metadata's CSV exists
                # whether or not a hash was ever requested.
                sorted(os.path.join(csv_dir, f) for f in
                       ("archive_metadata.csv", "file_listing.csv", "signature_mismatches.csv")))
            for path in written:
                self.assertTrue(os.path.isfile(path))

    def test_csv_rows_match_the_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "listing.db")
            _build_db(db_path)

            arc2lite.export_tables_to_csv(db_path)
            csv_path = os.path.join(tmp, "listing_csv", "file_listing.csv")

            conn = sqlite3.connect(db_path)
            try:
                cursor = conn.execute(
                    "SELECT * FROM file_listing ORDER BY entry_path")
                expected_headers = [d[0] for d in cursor.description]
                # sqlite3 hands back None for a NULL column; the CSV module
                # writes that as an empty field, same as every other empty
                # string column here, so both are compared as ''.
                expected_rows = [
                    ['' if v is None else str(v) for v in row]
                    for row in cursor.fetchall()]
            finally:
                conn.close()

            with open(csv_path, newline='', encoding='utf-8') as f:
                reader = csv.reader(f)
                actual_headers = next(reader)
                actual_rows = list(reader)

            self.assertEqual(actual_headers, expected_headers)
            self.assertEqual(sorted(actual_rows), sorted(expected_rows))

    def test_no_csv_folder_left_behind_without_the_flag(self):
        """export_tables_to_csv() is opt-in: process_archive_logic() on its
        own (what runs regardless of --export) must not create a *_csv
        folder itself. Only apply_export_choice(), called from the CLI/GUI
        layer, decides whether to call export_tables_to_csv()."""
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = os.path.join(tmp, "evidence.zip")
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("docs/readme.txt", "hello")

            db_path = arc2lite.process_archive_logic(zip_path, tmp, 1, "ZIP", None, None)

            self.assertIsNotNone(db_path)
            self.assertFalse(os.path.isdir(f"{db_path[:-3]}_csv"))


class AppliesTheExportChoiceToOneDatabase(unittest.TestCase):
    """apply_export_choice() is what -e/--export (and the GUI's SQLite/CSV/
    Timeline checkboxes) actually calls per database, with export as a
    collection of one or more of 'sqlite', 'csv', 'timeline'. Anything other
    than 'sqlite' alone has to build the .db first and remove it afterward
    rather than skip it, because file_listing's INSERT OR IGNORE dedup (see
    test_disk_image.WalkAgreesWithTheReader) only happens through the
    database."""

    def test_sqlite_leaves_the_database_untouched_and_writes_nothing_else(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "listing.db")
            _build_db(db_path)

            arc2lite.apply_export_choice(db_path, ["sqlite"])

            self.assertTrue(os.path.isfile(db_path))
            self.assertFalse(os.path.isdir(os.path.join(tmp, "listing_csv")))
            self.assertFalse(os.path.exists(os.path.join(tmp, "listing.body")))

    def test_csv_writes_csvs_then_removes_the_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "listing.db")
            _build_db(db_path)

            arc2lite.apply_export_choice(db_path, ["csv"])

            self.assertFalse(os.path.exists(db_path))
            csv_dir = os.path.join(tmp, "listing_csv")
            self.assertTrue(os.path.isfile(os.path.join(csv_dir, "file_listing.csv")))
            self.assertTrue(os.path.isfile(os.path.join(csv_dir, "archive_metadata.csv")))

    def test_sqlite_and_csv_keeps_the_database_and_writes_csvs(self):
        # The old boolean flag's "both" -- now just two choices together.
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "listing.db")
            _build_db(db_path)

            arc2lite.apply_export_choice(db_path, ["sqlite", "csv"])

            self.assertTrue(os.path.isfile(db_path))
            csv_dir = os.path.join(tmp, "listing_csv")
            self.assertTrue(os.path.isfile(os.path.join(csv_dir, "file_listing.csv")))
            self.assertTrue(os.path.isfile(os.path.join(csv_dir, "archive_metadata.csv")))

    def test_timeline_writes_a_bodyfile_then_removes_the_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "listing.db")
            _build_db(db_path)

            arc2lite.apply_export_choice(db_path, ["timeline"])

            self.assertFalse(os.path.exists(db_path))
            self.assertTrue(os.path.isfile(os.path.join(tmp, "listing.body")))
            self.assertFalse(os.path.isdir(os.path.join(tmp, "listing_csv")))

    def test_every_choice_together_keeps_the_database_and_writes_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "listing.db")
            _build_db(db_path)

            arc2lite.apply_export_choice(db_path, ["sqlite", "csv", "timeline"])

            self.assertTrue(os.path.isfile(db_path))
            self.assertTrue(os.path.isfile(os.path.join(tmp, "listing.body")))
            csv_dir = os.path.join(tmp, "listing_csv")
            self.assertTrue(os.path.isfile(os.path.join(csv_dir, "file_listing.csv")))

    def test_csv_and_timeline_without_sqlite_still_removes_the_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "listing.db")
            _build_db(db_path)

            arc2lite.apply_export_choice(db_path, ["csv", "timeline"])

            self.assertFalse(os.path.exists(db_path))
            self.assertTrue(os.path.isfile(os.path.join(tmp, "listing.body")))
            self.assertTrue(os.path.isfile(os.path.join(tmp, "listing_csv", "file_listing.csv")))

    def test_an_empty_or_missing_choice_defaults_to_sqlite(self):
        # run_cli()'s own argparse won't allow an empty -e/--export (nargs="+"
        # requires at least one value), but apply_export_choice() is called
        # directly by the GUI too, so it defends against an empty list or
        # None the same way the CLI's default already does.
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "listing.db")
            _build_db(db_path)

            arc2lite.apply_export_choice(db_path, [])

            self.assertTrue(os.path.isfile(db_path))
            self.assertFalse(os.path.isdir(os.path.join(tmp, "listing_csv")))
            self.assertFalse(os.path.exists(os.path.join(tmp, "listing.body")))


if __name__ == "__main__":
    unittest.main()

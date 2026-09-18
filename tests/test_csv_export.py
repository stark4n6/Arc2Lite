"""Tests for the CSV export option (-c/--csv, and the GUI's matching
checkbox), both of which call arc2lite.export_tables_to_csv().

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
                sorted(os.path.join(csv_dir, f) for f in
                       ("archive_metadata.csv", "file_listing.csv")))
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
        own (what runs whether or not -c/--csv was passed) must not create a
        *_csv folder itself. Only the CLI/GUI layer decides to call
        export_tables_to_csv() afterwards."""
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = os.path.join(tmp, "evidence.zip")
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("docs/readme.txt", "hello")

            db_path = arc2lite.process_archive_logic(zip_path, tmp, 1, "ZIP", None, None)

            self.assertIsNotNone(db_path)
            self.assertFalse(os.path.isdir(f"{db_path[:-3]}_csv"))


if __name__ == "__main__":
    unittest.main()

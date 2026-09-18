"""Tests for the export format switch (-e/--export {sqlite,csv,both}, and
the GUI's matching SQLite/CSV/Both selector), and the CSV writer underneath
it, export_tables_to_csv().

Run from the repository root:

    python3 -m unittest discover -s tests -v
"""

import argparse
import contextlib
import csv
import io
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
    Both selector) actually calls per database. 'csv' has to build the .db
    first and remove it afterward rather than skip it, because file_listing's
    INSERT OR IGNORE dedup (see test_disk_image.WalkAgreesWithTheReader) only
    happens through the database."""

    def test_sqlite_leaves_the_database_untouched_and_writes_no_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "listing.db")
            _build_db(db_path)

            arc2lite.apply_export_choice(db_path, "sqlite")

            self.assertTrue(os.path.isfile(db_path))
            self.assertFalse(os.path.isdir(os.path.join(tmp, "listing_csv")))

    def test_csv_writes_csvs_then_removes_the_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "listing.db")
            _build_db(db_path)

            arc2lite.apply_export_choice(db_path, "csv")

            self.assertFalse(os.path.exists(db_path))
            csv_dir = os.path.join(tmp, "listing_csv")
            self.assertTrue(os.path.isfile(os.path.join(csv_dir, "file_listing.csv")))
            self.assertTrue(os.path.isfile(os.path.join(csv_dir, "archive_metadata.csv")))

    def test_both_keeps_the_database_and_writes_csvs(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "listing.db")
            _build_db(db_path)

            arc2lite.apply_export_choice(db_path, "both")

            self.assertTrue(os.path.isfile(db_path))
            csv_dir = os.path.join(tmp, "listing_csv")
            self.assertTrue(os.path.isfile(os.path.join(csv_dir, "file_listing.csv")))
            self.assertTrue(os.path.isfile(os.path.join(csv_dir, "archive_metadata.csv")))


def _run_cli_quietly(**overrides):
    """run_cli() prints its progress to stdout; every test below only cares
    about what ends up on disk, so its output is captured and discarded."""
    args = argparse.Namespace(input=None, output=None, recursive=False, hash=None, export="sqlite")
    for k, v in overrides.items():
        setattr(args, k, v)
    with contextlib.redirect_stdout(io.StringIO()):
        arc2lite.run_cli(args)


class TheExportSwitchEndToEnd(unittest.TestCase):
    """-e/--export as a user on the command line actually sees it: one zip
    in, run_cli() end to end, check what landed in the output folder."""

    def _sample_zip(self, tmp):
        zip_path = os.path.join(tmp, "sample.zip")
        # get_forensic_type() ignores anything under 512 bytes (too small to
        # be worth sniffing), so this needs real bulk, not just a valid zip.
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("hello.txt", "hi there " * 100)
        return zip_path

    def _out_root(self, out_dir):
        # run_cli() names the run folder itself (Arc2Lite_Out_<timestamp>);
        # there's exactly one and it was just created, so take it as given.
        return os.path.join(out_dir, os.listdir(out_dir)[0])

    def test_sqlite_is_the_default_and_produces_no_csv_anywhere(self):
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = self._sample_zip(tmp)
            out_dir = os.path.join(tmp, "out")
            os.makedirs(out_dir)

            _run_cli_quietly(input=zip_path, output=out_dir)

            out_root = self._out_root(out_dir)
            produced = os.listdir(out_root)
            self.assertTrue(any(f.endswith(".db") for f in produced))
            self.assertFalse(any(f.endswith("_csv") for f in produced))

    def test_csv_leaves_only_csvs_for_both_the_archive_and_the_master_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = self._sample_zip(tmp)
            out_dir = os.path.join(tmp, "out")
            os.makedirs(out_dir)

            _run_cli_quietly(input=zip_path, output=out_dir, export="csv")

            out_root = self._out_root(out_dir)
            produced = os.listdir(out_root)
            self.assertFalse(any(f.endswith(".db") for f in produced),
                              f"a .db file survived csv-only mode: {produced}")
            self.assertIn("Arc2Lite_Master_Log_csv", produced)
            self.assertTrue(os.path.isfile(
                os.path.join(out_root, "Arc2Lite_Master_Log_csv", "processing_log.csv")))
            archive_csv_dirs = [f for f in produced if f.endswith("_file_listing_csv")]
            self.assertEqual(len(archive_csv_dirs), 1)
            self.assertTrue(os.path.isfile(
                os.path.join(out_root, archive_csv_dirs[0], "file_listing.csv")))

    def test_both_keeps_every_database_alongside_its_csvs(self):
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = self._sample_zip(tmp)
            out_dir = os.path.join(tmp, "out")
            os.makedirs(out_dir)

            _run_cli_quietly(input=zip_path, output=out_dir, export="both")

            out_root = self._out_root(out_dir)
            produced = os.listdir(out_root)
            self.assertTrue(any(f.endswith(".db") for f in produced))
            self.assertTrue(any(f.endswith("_csv") for f in produced))
            self.assertIn("Arc2Lite_Master_Log.db", produced)
            self.assertIn("Arc2Lite_Master_Log_csv", produced)


if __name__ == "__main__":
    unittest.main()

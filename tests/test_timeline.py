"""Tests for the bodyfile writer, export_bodyfile() / _reading_to_epoch(),
which -e/--export's 'timeline' choice (and the GUI's matching Timeline
checkbox) calls through apply_export_choice().

See tests/test_export_switch.py for 'timeline' exercised end to end through
run_cli(), and tests/test_csv_export.py for apply_export_choice() itself.

Run from the repository root:

    python3 -m unittest discover -s tests -v
"""

import os
import sqlite3
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import arc2lite                                   # noqa: E402


def _build_db(db_path, rows=None):
    """A file_listing/archive_metadata database, the same shape
    process_archive_logic() produces for one archive. `rows` overrides the
    default file_listing rows when a test needs specific date strings."""
    if rows is None:
        rows = [
            ("readme.txt", ".txt", "docs/readme.txt", "2024-01-02T03:04:05+00:00",
             "2024-01-03T04:05:06+00:00", "2024-01-04T05:06:07+00:00", 1, 42, 42),
            ("docs", "", "docs", "", "", "", 0, None, None),
        ]
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        arc2lite.setup_db(cursor)
        for row in rows:
            cursor.execute("INSERT INTO file_listing VALUES (?,?,?,?,?,?,?,?,?)", row)
        cursor.execute(
            "INSERT INTO archive_metadata VALUES (?,?,?,?,?,?,?)",
            ("evidence.zip", "/tmp/evidence.zip", "ZIP", 1024, "md5", "d41d8cd98f00b204e9800998ecf8427e",
             "2024-01-01T00:00:00+00:00"))
        conn.commit()
    finally:
        conn.close()


def _parse_body(path):
    with open(path, encoding="utf-8") as f:
        return [line.rstrip("\n").split("|") for line in f]


class ReadingToEpoch(unittest.TestCase):
    """_reading_to_epoch() is what makes the bodyfile's atime/mtime/crtime
    columns correct. It has to handle every shape file_listing's date
    columns actually take (see arc2lite.py's docstring for the full list),
    without depending on the host machine's timezone."""

    def test_empty_string_is_zero(self):
        self.assertEqual(arc2lite._reading_to_epoch(""), 0)
        self.assertEqual(arc2lite._reading_to_epoch(None), 0)

    def test_full_iso8601_instant_with_utc_offset(self):
        # format_ts()/format_instant()'s own shape.
        self.assertEqual(
            arc2lite._reading_to_epoch("2024-01-01T00:00:00+00:00"), 1704067200)

    def test_iso8601_instant_with_nonzero_offset(self):
        # 1704067200 is 2024-01-01T00:00:00 UTC; +05:00 local means the UTC
        # instant is five hours earlier.
        self.assertEqual(
            arc2lite._reading_to_epoch("2024-01-01T05:00:00+05:00"), 1704067200)
        self.assertEqual(
            arc2lite._reading_to_epoch("2023-12-31T19:00:00-05:00"), 1704067200)

    def test_fat_exfat_zoneless_stored_reading(self):
        # vendor/qnxprobe.py's _dos_stamp()/_exfat_stamp(): space-separated,
        # no offset, sometimes hundredths. This is a zone-less wall-clock
        # reading (see README's "About the dates"), so it must be read as
        # those literal digits and not shifted by whatever timezone the
        # host happens to be in.
        self.assertEqual(
            arc2lite._reading_to_epoch("2024-01-01 00:00:00"), 1704067200)
        self.assertEqual(
            arc2lite._reading_to_epoch("2024-01-01 00:00:00.50"), 1704067200)

    def test_fat_zoneless_reading_ignores_host_timezone(self):
        # Same reading, but with the process's local timezone changed away
        # from UTC, to prove the result doesn't move with it.
        if not hasattr(time, "tzset"):
            self.skipTest("time.tzset() is POSIX-only")
        old_tz = os.environ.get("TZ")
        try:
            os.environ["TZ"] = "America/New_York"
            time.tzset()
            self.assertEqual(
                arc2lite._reading_to_epoch("2024-01-01 00:00:00.50"), 1704067200)
        finally:
            if old_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old_tz
            time.tzset()

    def test_fat_date_only_reading(self):
        # vendor/qnxprobe.py's _dos_date(): no time component at all.
        self.assertEqual(arc2lite._reading_to_epoch("2024-01-01"), 1704067200)

    def test_garbage_is_zero(self):
        self.assertEqual(arc2lite._reading_to_epoch("not a date"), 0)


class ExportsFileListingToABodyfile(unittest.TestCase):

    def test_one_line_per_row_with_eleven_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "1-evidence.zip_file_listing.db")
            _build_db(db_path)

            body_path = arc2lite.export_bodyfile(db_path)

            self.assertEqual(body_path, os.path.join(tmp, "1-evidence.zip_file_listing.body"))
            lines = _parse_body(body_path)
            self.assertEqual(len(lines), 2)
            for fields in lines:
                self.assertEqual(len(fields), 11)

    def test_field_mapping_for_a_file_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "listing.db")
            _build_db(db_path)

            body_path = arc2lite.export_bodyfile(db_path)
            lines = {fields[1]: fields for fields in _parse_body(body_path)}
            md5, name, inode, mode, uid, gid, size, atime, mtime, ctime, crtime = \
                lines["docs/readme.txt"]

            self.assertEqual(md5, "0")
            self.assertEqual(inode, "0")
            self.assertEqual(mode, "r/rrwxrwxrwx")
            self.assertEqual(uid, "0")
            self.assertEqual(gid, "0")
            self.assertEqual(size, "42")
            self.assertEqual(atime, str(arc2lite._reading_to_epoch("2024-01-04T05:06:07+00:00")))
            self.assertEqual(mtime, str(arc2lite._reading_to_epoch("2024-01-03T04:05:06+00:00")))
            self.assertEqual(ctime, "0")
            self.assertEqual(crtime, str(arc2lite._reading_to_epoch("2024-01-02T03:04:05+00:00")))

    def test_field_mapping_for_a_directory_row_with_no_dates_or_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "listing.db")
            _build_db(db_path)

            body_path = arc2lite.export_bodyfile(db_path)
            lines = {fields[1]: fields for fields in _parse_body(body_path)}
            fields = lines["docs"]

            self.assertEqual(fields[3], "d/drwxrwxrwx")   # mode
            self.assertEqual(fields[6], "0")               # size, NULL -> 0
            self.assertEqual(fields[7], "0")                # atime, empty -> 0
            self.assertEqual(fields[8], "0")                # mtime, empty -> 0
            self.assertEqual(fields[10], "0")               # crtime, empty -> 0

    def test_backslashes_become_forward_slashes_and_pipes_are_escaped(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "listing.db")
            _build_db(db_path, rows=[
                ("odd|name.txt", ".txt", r"docs\odd|name.txt", "", "", "", 1, 1, 1),
            ])

            body_path = arc2lite.export_bodyfile(db_path)
            fields = _parse_body(body_path)[0]

            self.assertEqual(fields[1], "docs/odd_name.txt")

    def test_returns_none_when_file_listing_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "listing.db")
            _build_db(db_path, rows=[])

            self.assertIsNone(arc2lite.export_bodyfile(db_path))
            self.assertFalse(os.path.exists(os.path.join(tmp, "listing.body")))

    def test_returns_none_when_there_is_no_file_listing_table(self):
        # The shape of the master log's database: a processing_log table,
        # no file_listing at all. This is also what keeps apply_export_choice()
        # from needing a special case to scope 'timeline' to per-archive/
        # image databases -- calling export_bodyfile() on the master log is
        # simply a no-op.
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "Arc2Lite_Master_Log.db")
            conn = sqlite3.connect(db_path)
            try:
                conn.execute("CREATE TABLE processing_log (input_path TEXT)")
                conn.commit()
            finally:
                conn.close()

            self.assertIsNone(arc2lite.export_bodyfile(db_path))
            self.assertFalse(os.path.exists(os.path.join(tmp, "Arc2Lite_Master_Log.body")))


if __name__ == "__main__":
    unittest.main()
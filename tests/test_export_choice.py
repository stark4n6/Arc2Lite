"""End-to-end tests for -e/--export as a user on the command line actually
sees it: one zip in, run_cli() end to end, check what landed in the output
folder, across every combination of its 'sqlite'/'csv'/'timeline' choices.

See tests/test_csv_export.py for apply_export_choice() and the CSV writer
in isolation, and tests/test_timeline.py for the bodyfile writer and its
date parsing in isolation.

Run from the repository root:

    python3 -m unittest discover -s tests -v
"""

import argparse
import contextlib
import io
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import arc2lite                                   # noqa: E402


def _run_cli_quietly(**overrides):
    """run_cli() prints its progress to stdout; every test below only cares
    about what ends up on disk, so its output is captured and discarded."""
    args = argparse.Namespace(input=None, output=None, recursive=False, hash=None,
                               export=["sqlite"], check_signatures=False)
    for k, v in overrides.items():
        setattr(args, k, v)
    with contextlib.redirect_stdout(io.StringIO()):
        arc2lite.run_cli(args)


class TheExportSwitchEndToEnd(unittest.TestCase):

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

    def _run(self, tmp, **overrides):
        zip_path = self._sample_zip(tmp)
        out_dir = os.path.join(tmp, "out")
        os.makedirs(out_dir)
        _run_cli_quietly(input=zip_path, output=out_dir, **overrides)
        return os.listdir(self._out_root(out_dir))

    def test_sqlite_is_the_default_and_produces_no_csv_or_bodyfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            produced = self._run(tmp)

            self.assertTrue(any(f.endswith(".db") for f in produced))
            self.assertFalse(any(f.endswith("_csv") for f in produced))
            self.assertFalse(any(f.endswith(".body") for f in produced))

    def test_csv_leaves_only_csvs_for_both_the_archive_and_the_master_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            produced = self._run(tmp, export=["csv"])

            self.assertFalse(any(f.endswith(".db") for f in produced),
                              f"a .db file survived csv-only mode: {produced}")
            self.assertIn("Arc2Lite_Master_Log_csv", produced)
            archive_csv_dirs = [f for f in produced if f.endswith("_file_listing_csv")]
            self.assertEqual(len(archive_csv_dirs), 1)

    def test_sqlite_and_csv_keeps_every_database_alongside_its_csvs(self):
        with tempfile.TemporaryDirectory() as tmp:
            produced = self._run(tmp, export=["sqlite", "csv"])

            self.assertIn("Arc2Lite_Master_Log.db", produced)
            self.assertIn("Arc2Lite_Master_Log_csv", produced)
            self.assertTrue(any(f.endswith("_file_listing.db") for f in produced))
            self.assertTrue(any(f.endswith("_file_listing_csv") for f in produced))

    def test_timeline_alone_writes_a_bodyfile_and_removes_the_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            produced = self._run(tmp, export=["timeline"])

            self.assertFalse(any(f.endswith(".db") for f in produced), produced)
            self.assertFalse(any(f.endswith("_csv") for f in produced), produced)
            body_files = [f for f in produced if f.endswith(".body")]
            self.assertEqual(len(body_files), 1, produced)
            self.assertTrue(body_files[0].endswith("_file_listing.body"))

    def test_timeline_is_always_scoped_to_the_archive_not_the_master_log(self):
        # Every combination that includes 'timeline' should produce exactly
        # one .body file (the archive's), never one for Arc2Lite_Master_Log.
        with tempfile.TemporaryDirectory() as tmp:
            produced = self._run(tmp, export=["sqlite", "csv", "timeline"])

            body_files = [f for f in produced if f.endswith(".body")]
            self.assertEqual(len(body_files), 1, produced)
            self.assertNotIn("Arc2Lite_Master_Log.body", produced)

    def test_sqlite_and_timeline_keeps_the_database_and_writes_a_bodyfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            produced = self._run(tmp, export=["sqlite", "timeline"])

            self.assertTrue(any(f.endswith("_file_listing.db") for f in produced))
            self.assertTrue(any(f.endswith(".body") for f in produced))
            self.assertFalse(any(f.endswith("_csv") for f in produced))

    def test_csv_and_timeline_without_sqlite_removes_the_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            produced = self._run(tmp, export=["csv", "timeline"])

            self.assertFalse(any(f.endswith(".db") for f in produced), produced)
            self.assertTrue(any(f.endswith("_csv") for f in produced))
            self.assertTrue(any(f.endswith(".body") for f in produced))

    def test_every_choice_together_keeps_everything(self):
        with tempfile.TemporaryDirectory() as tmp:
            produced = self._run(tmp, export=["sqlite", "csv", "timeline"])

            self.assertIn("Arc2Lite_Master_Log.db", produced)
            self.assertIn("Arc2Lite_Master_Log_csv", produced)
            self.assertTrue(any(f.endswith("_file_listing.db") for f in produced))
            self.assertTrue(any(f.endswith("_file_listing_csv") for f in produced))
            self.assertTrue(any(f.endswith(".body") for f in produced))


class TheArgumentParserAcceptsMultipleExportValues(unittest.TestCase):
    """-e/--export is nargs="+": one flag, one or more values, any order."""

    def _parser(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-i", "--input", required=True)
        parser.add_argument("-o", "--output", required=True)
        parser.add_argument("-r", "--recursive", action="store_true")
        parser.add_argument("-ha", "--hash", choices=["md5", "sha1", "sha256"])
        parser.add_argument("-e", "--export", nargs="+", choices=["sqlite", "csv", "timeline"],
                             default=["sqlite"])
        return parser

    def test_default_is_sqlite_only(self):
        args = self._parser().parse_args(["-i", "in", "-o", "out"])
        self.assertEqual(args.export, ["sqlite"])

    def test_multiple_values_are_collected_in_order_given(self):
        args = self._parser().parse_args(
            ["-i", "in", "-o", "out", "-e", "csv", "timeline"])
        self.assertEqual(args.export, ["csv", "timeline"])

    def test_an_unknown_value_is_rejected(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                self._parser().parse_args(["-i", "in", "-o", "out", "-e", "both"])


if __name__ == "__main__":
    unittest.main()
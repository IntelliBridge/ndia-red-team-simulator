"""Tests for the fs->pg migration CLI surface.

The full migration is exercised under integration; this suite covers the
shape of the CLI output formatting and the empty-source-dir happy path
that the v0.3.1 F5 fix was about.
"""

import argparse
import io
import tempfile
import unittest
from contextlib import redirect_stdout

from redsim.cli.migrate import cmd_migrate
from redsim.migrate.fs_to_pg import MigrationSummary


class TestSummaryFormatting(unittest.TestCase):
    """v0.3.1 F5 — cmd_migrate previously called ``summary.items()``;
    ``MigrationSummary`` only exposes ``to_dict()``. The bug raised
    AttributeError instead of printing the summary."""

    def test_empty_source_dir_does_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = argparse.Namespace(
                direction="fs->pg",
                source=tmp,
                project="default",
                db_url=None,
                dry_run=True,
            )

            # No runs/ dir under tmp — migration returns a summary with one
            # entry in `failures` ("no runs dir at ...").
            buf = io.StringIO()
            with redirect_stdout(buf):
                try:
                    cmd_migrate(args, config=None)
                except SystemExit as exc:
                    # cmd_migrate is expected to exit; 1 because failures
                    # contains an entry, but the formatting completes first.
                    self.assertIn(exc.code, (0, 1))
            output = buf.getvalue()
            self.assertIn("runs_imported", output)
            self.assertIn("findings_imported", output)
            self.assertIn("audit_events_reanchored", output)

    def test_to_dict_returns_summary_fields(self):
        summary = MigrationSummary(
            runs_imported=2, findings_imported=5,
            remediation_attempts_imported=1, artifacts_imported=3,
            audit_events_reanchored=4, skipped_duplicates=0, failures=[],
        )
        d = summary.to_dict()
        self.assertEqual(d["runs_imported"], 2)
        self.assertEqual(d["findings_imported"], 5)
        self.assertEqual(d["failures"], [])


if __name__ == "__main__":
    unittest.main()

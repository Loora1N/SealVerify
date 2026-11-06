import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from importlib.metadata import version


class EntryPointTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "sealverify", *args],
            capture_output=True, text=True, encoding="utf-8",
            env=dict(os.environ, PYTHONIOENCODING="utf-8"), check=False,
        )

    def test_module_version_comes_from_package_metadata(self):
        completed = self.run_cli("--version")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "SealVerify " + version("sealverify"))

    def test_help_and_default_entry_explain_current_limit(self):
        for args in ((), ("--help",)):
            with self.subTest(args=args):
                completed = self.run_cli(*args)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("尚未实现", completed.stdout)

    def test_unknown_file_input_is_not_treated_as_verified(self):
        completed = self.run_cli("example.ofd")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("example.ofd", completed.stderr)

    def test_reader_missing_file_returns_readable_error(self):
        completed = self.run_cli("view", "file-that-does-not-exist.ofd", "--no-browser")
        self.assertEqual(completed.returncode, 1)
        self.assertIn("无法打开阅读器", completed.stderr)
        self.assertNotIn("Traceback", completed.stderr)

    def test_reader_rejects_conflicting_input_and_invalid_port(self):
        for args in (("view", "example.ofd", "--demo"), ("view", "--port", "65536")):
            with self.subTest(args=args):
                self.assertEqual(self.run_cli(*args).returncode, 2)

    def test_synthetic_example_reports_incomplete_instead_of_pass(self):
        example = Path(__file__).resolve().parents[1] / "examples" / "result_report.py"
        completed = subprocess.run(
            [sys.executable, str(example)], capture_output=True, text=True, encoding="utf-8",
            env=dict(os.environ, PYTHONIOENCODING="utf-8"), check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        data = json.loads(completed.stdout)
        self.assertIn("非真实验签", data["source_name"])
        self.assertEqual(data["overall_status"], "incomplete")
        self.assertEqual(data["summary"]["planned"], 3)


if __name__ == "__main__":
    unittest.main()

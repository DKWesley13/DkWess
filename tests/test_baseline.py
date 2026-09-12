from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from dkwess_securerepo.baseline import baseline_payload, compare_baseline, load_baseline, write_baseline
from dkwess_securerepo.scanner import scan_repository


class BaselineTests(unittest.TestCase):
    def _repo(self, root: Path) -> None:
        (root / "README.md").write_text("# fixture\n", encoding="utf-8")
        (root / "SECURITY.md").write_text("security\n", encoding="utf-8")
        (root / "CONTRIBUTING.md").write_text("contributing\n", encoding="utf-8")
        (root / "LICENSE").write_text("fixture license\n", encoding="utf-8")
        (root / ".gitignore").write_text(".env\n__pycache__/\nreports/\n", encoding="utf-8")
        (root / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")

    def test_baseline_round_trip_and_regression(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._repo(root)
            (root / ".env").write_text("fixture\n", encoding="utf-8")
            first = scan_repository(root)
            baseline_path = write_baseline(first, root / "baseline.json")
            baseline = load_baseline(baseline_path)
            comparison = compare_baseline(first, baseline)
            self.assertEqual(comparison.new_findings, ())
            self.assertEqual(len(comparison.unchanged_fingerprints), 1)
            (root / "id_rsa").write_text("fixture\n", encoding="utf-8")
            second = scan_repository(root)
            comparison = compare_baseline(second, baseline)
            self.assertEqual(len(comparison.new_findings), 1)
            self.assertTrue(comparison.has_new_at_or_above("HIGH"))

    def test_resolved_finding_is_not_passed_off_as_new(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._repo(root)
            secret = root / ".env"
            secret.write_text("fixture\n", encoding="utf-8")
            baseline = baseline_payload(scan_repository(root))
            secret.unlink()
            comparison = compare_baseline(scan_repository(root), baseline)
            self.assertEqual(comparison.new_findings, ())
            self.assertEqual(len(comparison.resolved_fingerprints), 1)


if __name__ == "__main__":
    unittest.main()

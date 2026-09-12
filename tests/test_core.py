from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from dkwess_securerepo.core import scan_repository, write_reports


class SecureRepoTests(unittest.TestCase):
    def _baseline(self, root: Path) -> None:
        (root / "README.md").write_text("# Example\n", encoding="utf-8")
        (root / "SECURITY.md").write_text("security\n", encoding="utf-8")
        (root / "CONTRIBUTING.md").write_text("contributing\n", encoding="utf-8")
        (root / "LICENSE").write_text("test fixture license\n", encoding="utf-8")
        (root / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
        (root / ".gitignore").write_text(".env\n__pycache__/\nreports/\n", encoding="utf-8")

    def test_clean_fixture_passes_implemented_checks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._baseline(root)
            result = scan_repository(root)
            self.assertEqual(result.status, "PASS")
            self.assertEqual(result.findings, [])
            self.assertIn("pyproject.toml", result.manifests)

    def test_sensitive_filename_is_high(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._baseline(root)
            (root / ".env").write_text("NOT_A_REAL_SECRET=test\n", encoding="utf-8")
            result = scan_repository(root)
            matches = [finding for finding in result.findings if finding.check_id == "SR-SEC-001"]
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0].severity, "HIGH")
            self.assertEqual(matches[0].category, "sensitive-files")
            self.assertEqual(matches[0].path, ".env")
            self.assertEqual(result.exit_code("HIGH"), 2)

    def test_env_example_is_not_treated_as_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._baseline(root)
            (root / ".env.example").write_text("TOKEN=replace-me\n", encoding="utf-8")
            result = scan_repository(root)
            self.assertFalse(any(finding.check_id == "SR-SEC-001" for finding in result.findings))

    def test_risky_workflow_rules_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._baseline(root)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "risky.yml").write_text(
                """name: risky
on:
  pull_request_target:
permissions: write-all
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: true
""",
                encoding="utf-8",
            )
            result = scan_repository(root)
            ids = {finding.check_id for finding in result.findings}
            self.assertTrue({"SR-GHA-001", "SR-GHA-002", "SR-GHA-003", "SR-GHA-005"}.issubset(ids))
            gha = next(cap for cap in result.capabilities if cap.capability == "GitHub Actions")
            self.assertEqual(gha.assessment, "FAIL")
            self.assertEqual(gha.coverage, "FULL")

    def test_full_sha_action_is_not_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._baseline(root)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "pinned.yml").write_text(
                "jobs:\n  test:\n    steps:\n      - uses: owner/action@0123456789abcdef0123456789abcdef01234567\n",
                encoding="utf-8",
            )
            result = scan_repository(root)
            self.assertFalse(any(finding.check_id == "SR-GHA-005" for finding in result.findings))
            gha = next(cap for cap in result.capabilities if cap.capability == "GitHub Actions")
            self.assertEqual(gha.assessment, "PASS")
            self.assertEqual(gha.coverage, "FULL")

    def test_missing_workflows_are_not_assessed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._baseline(root)
            result = scan_repository(root)
            gha = next(cap for cap in result.capabilities if cap.capability == "GitHub Actions")
            self.assertEqual(gha.assessment, "NOT_ASSESSED")
            self.assertEqual(gha.coverage, "UNKNOWN")

    def test_symlink_is_not_followed_by_sensitive_filename_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._baseline(root)
            target = root / "target.txt"
            target.write_text("safe fixture\n", encoding="utf-8")
            link = root / "secret.pem"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are unavailable in this environment")
            result = scan_repository(root)
            self.assertFalse(any(finding.check_id == "SR-SEC-001" for finding in result.findings))

    def test_reports_are_written_with_schema_v2_and_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._baseline(root)
            result = scan_repository(root)
            json_path, markdown_path = write_reports(result, root / "reports")
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], 2)
            self.assertEqual(payload["status"], "PASS")
            self.assertFalse(payload["security_guarantee"])
            self.assertTrue(payload["capabilities"])
            markdown = markdown_path.read_text(encoding="utf-8")
            self.assertIn("Capability matrix", markdown)
            self.assertIn("PASS != SECURITY GUARANTEE", markdown)


if __name__ == "__main__":
    unittest.main()

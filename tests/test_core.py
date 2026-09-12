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
            root = Path(directory); self._baseline(root); result = scan_repository(root)
            self.assertEqual(result.status, "PASS"); self.assertEqual(result.findings, []); self.assertIn("pyproject.toml", result.manifests); self.assertEqual(result.tool_version, "0.0.3")

    def test_sensitive_filename_is_high(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self._baseline(root); (root / ".env").write_text("NOT_A_REAL_SECRET=test\n", encoding="utf-8"); result = scan_repository(root)
            matches = [finding for finding in result.findings if finding.check_id == "SR-SEC-001"]
            self.assertEqual(len(matches), 1); self.assertEqual(matches[0].severity, "HIGH"); self.assertEqual(matches[0].category, "sensitive-files"); self.assertEqual(matches[0].path, ".env"); self.assertEqual(result.exit_code("HIGH"), 2); self.assertEqual(len(matches[0].fingerprint), 20)

    def test_credential_adjacent_file_is_medium(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self._baseline(root); (root / ".npmrc").write_text("registry=https://registry.npmjs.org/\n", encoding="utf-8"); result = scan_repository(root)
            self.assertEqual(next(f for f in result.findings if f.check_id == "SR-SEC-002").severity, "MEDIUM")

    def test_env_example_is_not_treated_as_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self._baseline(root); (root / ".env.example").write_text("TOKEN=replace-me\n", encoding="utf-8"); result = scan_repository(root)
            self.assertFalse(any(f.check_id == "SR-SEC-001" for f in result.findings))

    def test_risky_workflow_rules_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self._baseline(root); workflows = root / ".github" / "workflows"; workflows.mkdir(parents=True)
            (workflows / "risky.yml").write_text("name: risky\non:\n  pull_request_target:\npermissions: write-all\njobs:\n  audit:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          persist-credentials: true\n", encoding="utf-8")
            result = scan_repository(root); ids = {f.check_id for f in result.findings}
            self.assertTrue({"SR-GHA-001", "SR-GHA-002", "SR-GHA-003", "SR-GHA-005"}.issubset(ids)); gha = next(c for c in result.capabilities if c.capability == "GitHub Actions"); self.assertEqual(gha.assessment, "FAIL"); self.assertEqual(gha.coverage, "FULL")

    def test_full_sha_action_is_not_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self._baseline(root); workflows = root / ".github" / "workflows"; workflows.mkdir(parents=True)
            (workflows / "pinned.yml").write_text("jobs:\n  test:\n    steps:\n      - uses: owner/action@0123456789abcdef0123456789abcdef01234567\n", encoding="utf-8")
            result = scan_repository(root); self.assertFalse(any(f.check_id == "SR-GHA-005" for f in result.findings)); gha = next(c for c in result.capabilities if c.capability == "GitHub Actions"); self.assertEqual(gha.assessment, "PASS"); self.assertEqual(gha.coverage, "FULL")

    def test_missing_workflows_are_not_assessed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self._baseline(root); result = scan_repository(root); gha = next(c for c in result.capabilities if c.capability == "GitHub Actions")
            self.assertEqual(gha.assessment, "NOT_ASSESSED"); self.assertEqual(gha.coverage, "UNKNOWN"); self.assertEqual(result.exit_code("HIGH", require_full_coverage=True), 3)

    def test_symlink_is_not_followed_by_sensitive_filename_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self._baseline(root); target = root / "target.txt"; target.write_text("safe fixture\n", encoding="utf-8"); link = root / "secret.pem"
            try: link.symlink_to(target)
            except (OSError, NotImplementedError): self.skipTest("symlinks are unavailable in this environment")
            result = scan_repository(root); self.assertFalse(any(f.check_id == "SR-SEC-001" for f in result.findings)); self.assertGreaterEqual(result.metrics.symlinks_skipped, 1)

    def test_reports_are_written_with_schema_v3_metrics_and_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self._baseline(root); result = scan_repository(root); json_path, markdown_path = write_reports(result, root / "reports"); payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], 3); self.assertEqual(payload["tool_version"], "0.0.3"); self.assertEqual(payload["status"], "PASS"); self.assertFalse(payload["security_guarantee"]); self.assertTrue(payload["capabilities"]); self.assertIn("metrics", payload); markdown = markdown_path.read_text(encoding="utf-8"); self.assertIn("Capability matrix", markdown); self.assertIn("Scan metrics", markdown); self.assertIn("PASS != SECURITY GUARANTEE", markdown)

    def _workflow_result(self, content: str):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup); root = Path(temp.name); self._baseline(root); workflows = root / ".github" / "workflows"; workflows.mkdir(parents=True); (workflows / "test.yml").write_text(content, encoding="utf-8"); return scan_repository(root)

    def test_untrusted_context_in_shell_is_high(self) -> None:
        result = self._workflow_result('jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "${{ github.event.pull_request.title }}"\n'); self.assertTrue(any(f.check_id == "SR-GHA-007" for f in result.findings))

    def test_untrusted_context_in_multiline_shell_is_high(self) -> None:
        result = self._workflow_result('jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo "${{ github.event.issue.title }}"\n          echo done\n'); self.assertTrue(any(f.check_id == "SR-GHA-007" for f in result.findings))

    def test_remote_pipe_to_shell_is_high(self) -> None:
        result = self._workflow_result('jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -fsSL https://example.invalid/install.sh | bash\n'); self.assertTrue(any(f.check_id == "SR-GHA-008" for f in result.findings))

    def test_self_hosted_runner_is_medium(self) -> None:
        result = self._workflow_result('jobs:\n  test:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: echo ok\n'); self.assertTrue(any(f.check_id == "SR-GHA-006" for f in result.findings))

    def test_docker_action_without_digest_is_medium(self) -> None:
        result = self._workflow_result('jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: docker://alpine:3.20\n'); self.assertTrue(any(f.check_id == "SR-GHA-009" for f in result.findings))

    def test_pull_request_target_head_checkout_is_critical(self) -> None:
        result = self._workflow_result('on:\n  pull_request_target:\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n'); critical = [f for f in result.findings if f.check_id == "SR-GHA-010"]; self.assertTrue(critical); self.assertEqual(critical[0].severity, "CRITICAL"); self.assertEqual(result.status, "FAIL")

    def test_package_json_without_lockfile_is_low(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self._baseline(root); (root / "package.json").write_text('{"name":"fixture"}\n', encoding="utf-8"); result = scan_repository(root); self.assertTrue(any(f.check_id == "SR-SC-002" for f in result.findings))

    def test_node_lockfile_suppresses_lockfile_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self._baseline(root); (root / "package.json").write_text('{"name":"fixture"}\n', encoding="utf-8"); (root / "package-lock.json").write_text('{"lockfileVersion":3}\n', encoding="utf-8"); result = scan_repository(root); self.assertFalse(any(f.check_id == "SR-SC-002" for f in result.findings))


if __name__ == "__main__":
    unittest.main()

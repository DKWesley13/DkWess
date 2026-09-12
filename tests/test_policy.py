from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from dkwess_securerepo.core import scan_repository
from dkwess_securerepo.policy import PolicyConfig, apply_policy, load_policy


class PolicyTests(unittest.TestCase):
    def _repo(self, root: Path) -> None:
        for name in ("README.md", "SECURITY.md", "CONTRIBUTING.md", "LICENSE"):
            (root / name).write_text("fixture\n", encoding="utf-8")
        (root / ".gitignore").write_text(".env\n__pycache__/\nreports/\n", encoding="utf-8")
        (root / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")

    def test_policy_suppression_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self._repo(root)
            (root / ".env").write_text("fixture\n", encoding="utf-8")
            raw = scan_repository(root)
            filtered, application = apply_policy(raw, PolicyConfig(disabled_rules=frozenset({"SR-SEC-001"})))
            self.assertFalse(any(f.check_id == "SR-SEC-001" for f in filtered.findings))
            self.assertEqual(application.suppressed_count, 1)
            self.assertEqual(len(application.suppressed_fingerprints), 1)

    def test_critical_suppression_requires_explicit_override(self) -> None:
        with self.assertRaises(ValueError):
            PolicyConfig(disabled_rules=frozenset({"SR-GHA-010"}))

    def test_load_toml_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "securerepo.toml"
            path.write_text('[policy]\nfail_on="MEDIUM"\nrequire_full_coverage=true\nexclude_paths=["tests/fixtures/*"]\n', encoding="utf-8")
            policy = load_policy(path)
            self.assertEqual(policy.fail_on, "MEDIUM")
            self.assertTrue(policy.require_full_coverage)
            self.assertEqual(policy.exclude_paths, ("tests/fixtures/*",))


if __name__ == "__main__": unittest.main()

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from dkwess_securerepo.core import scan_repository
from dkwess_securerepo.sarif import sarif_payload


class SarifTests(unittest.TestCase):
    def test_sarif_contains_rule_location_and_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("README.md", "SECURITY.md", "CONTRIBUTING.md", "LICENSE"):
                (root / name).write_text("fixture\n", encoding="utf-8")
            (root / ".gitignore").write_text(".env\n__pycache__/\nreports/\n", encoding="utf-8")
            (root / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
            (root / ".env").write_text("fixture\n", encoding="utf-8")
            result = scan_repository(root)
            payload = sarif_payload(result)
            self.assertEqual(payload["version"], "2.1.0")
            run = payload["runs"][0]
            self.assertEqual(run["tool"]["driver"]["name"], "DkWess SecureRepo")
            entry = run["results"][0]
            self.assertIn("ruleId", entry)
            self.assertIn("dkwessSecureRepoFingerprint/v1", entry["partialFingerprints"])
            self.assertTrue(entry["locations"])


if __name__ == "__main__":
    unittest.main()

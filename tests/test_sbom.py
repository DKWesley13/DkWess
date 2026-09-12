from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from dkwess_securerepo.core import scan_repository
from dkwess_securerepo.sbom import sbom_payload


class SbomTests(unittest.TestCase):
    def _repo(self, root: Path) -> None:
        for name in ("README.md", "SECURITY.md", "CONTRIBUTING.md", "LICENSE"):
            (root / name).write_text("fixture\n", encoding="utf-8")
        (root / ".gitignore").write_text(".env\n__pycache__/\nreports/\n", encoding="utf-8")

    def test_requirements_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self._repo(root)
            (root / "requirements.txt").write_text("requests==2.32.3\nflask>=3\n", encoding="utf-8")
            payload = sbom_payload(root, scan_repository(root))
            self.assertEqual(payload["bomFormat"], "CycloneDX")
            names = {component["name"] for component in payload["components"]}
            self.assertIn("requests", names); self.assertIn("flask", names)
            versions = {component["name"]: component.get("version") for component in payload["components"]}
            self.assertEqual(versions["requests"], "2.32.3")

    def test_go_mod_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self._repo(root)
            (root / "go.mod").write_text("module example.test/app\nrequire example.test/lib v1.2.3\n", encoding="utf-8")
            (root / "go.sum").write_text("fixture\n", encoding="utf-8")
            payload = sbom_payload(root, scan_repository(root))
            self.assertTrue(any(component["name"] == "example.test/lib" for component in payload["components"]))


if __name__ == "__main__": unittest.main()

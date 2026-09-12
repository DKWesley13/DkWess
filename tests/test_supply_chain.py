from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from dkwess_securerepo.core import scan_repository
from dkwess_securerepo.provenance import provenance_payload
from dkwess_securerepo.supply_chain import supply_chain_payload


class SupplyChainTests(unittest.TestCase):
    def _repo(self, root: Path) -> None:
        for name in ("README.md", "SECURITY.md", "CONTRIBUTING.md", "LICENSE"):
            (root / name).write_text("fixture\n", encoding="utf-8")
        (root / ".gitignore").write_text(".env\n__pycache__/\nreports/\n", encoding="utf-8")
        (root / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")

    def test_action_inventory_marks_full_sha_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self._repo(root)
            workflows = root / ".github" / "workflows"; workflows.mkdir(parents=True)
            workflows.joinpath("ci.yml").write_text("jobs:\n  t:\n    steps:\n      - uses: owner/action@0123456789abcdef0123456789abcdef01234567\n", encoding="utf-8")
            payload = supply_chain_payload(root, scan_repository(root))
            actions = [item for item in payload["components"] if item["kind"] == "github-action"]
            self.assertEqual(len(actions), 1)
            self.assertTrue(actions[0]["immutable"])

    def test_provenance_redacts_url_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self._repo(root)
            git = root / ".git"; (git / "refs" / "heads").mkdir(parents=True)
            git.joinpath("HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            git.joinpath("refs/heads/main").write_text("a" * 40 + "\n", encoding="utf-8")
            git.joinpath("config").write_text('[remote "origin"]\n\turl = https://user:secret@example.com/org/repo.git?token=x\n', encoding="utf-8")
            payload = provenance_payload(root, scan_repository(root))
            self.assertEqual(payload["head_sha"], "a" * 40)
            self.assertEqual(payload["origin"], "https://example.com/org/repo.git")


if __name__ == "__main__":
    unittest.main()

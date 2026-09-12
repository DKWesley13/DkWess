from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest

from dkwess_securerepo.__main__ import main


class SecureRepoCliTests(unittest.TestCase):
    def test_list_checks(self) -> None:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(["--list-checks"])
        self.assertEqual(code, 0)
        self.assertIn("SR-GHA-010", buffer.getvalue())

    def test_explain_rule(self) -> None:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(["--explain", "SR-GHA-007"])
        self.assertEqual(code, 0)
        self.assertIn("Potentially untrusted GitHub context", buffer.getvalue())

    def test_unknown_explain_rule_fails(self) -> None:
        buffer = io.StringIO()
        with redirect_stderr(buffer):
            code = main(["--explain", "SR-NOPE-999"])
        self.assertEqual(code, 1)
        self.assertIn("Unknown SecureRepo rule", buffer.getvalue())

    def test_json_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("# fixture\n", encoding="utf-8")
            (root / "SECURITY.md").write_text("security\n", encoding="utf-8")
            (root / "CONTRIBUTING.md").write_text("contrib\n", encoding="utf-8")
            (root / "LICENSE").write_text("fixture\n", encoding="utf-8")
            (root / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
            (root / ".gitignore").write_text(".env\n__pycache__/\nreports/\n", encoding="utf-8")
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main([str(root), "--no-reports", "--json-stdout"])
            self.assertEqual(code, 0)
            self.assertIn('"schema_version": 3', buffer.getvalue())
            self.assertNotIn("DkWess SecureRepo v", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()

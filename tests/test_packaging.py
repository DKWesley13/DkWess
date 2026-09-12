from __future__ import annotations

from pathlib import Path
import tomllib
import unittest

import dkwess_securerepo


class PackagingTests(unittest.TestCase):
    def test_package_version_matches_pyproject(self) -> None:
        root = Path(__file__).resolve().parents[1]
        data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(data["project"]["version"], dkwess_securerepo.__version__)
        self.assertEqual(dkwess_securerepo.__version__, "0.0.3")


if __name__ == "__main__":
    unittest.main()

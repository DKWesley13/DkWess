from __future__ import annotations

from pathlib import Path
import re
import tomllib
import unittest

import dkwess_securerepo


class PackagingTests(unittest.TestCase):
    def test_package_version_matches_pyproject(self) -> None:
        root = Path(__file__).resolve().parents[1]
        data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        version = dkwess_securerepo.__version__
        self.assertEqual(data["project"]["version"], version)
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")


if __name__ == "__main__": unittest.main()

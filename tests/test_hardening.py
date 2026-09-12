from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from dkwess_securerepo.hardening import MAX_WORKFLOW_BYTES, describe_limits, preflight_repository


class HardeningTests(unittest.TestCase):
    def test_oversized_workflow_is_rejected_before_scanning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); workflows = root / ".github" / "workflows"; workflows.mkdir(parents=True)
            path = workflows / "huge.yml"
            with path.open("wb") as handle: handle.truncate(MAX_WORKFLOW_BYTES + 1)
            with self.assertRaises(ValueError): preflight_repository(root)

    def test_limits_are_explicit(self) -> None:
        limits = describe_limits(); self.assertGreater(limits["max_discovered_files"], 0); self.assertGreater(limits["max_workflow_bytes"], 0)


if __name__ == "__main__": unittest.main()

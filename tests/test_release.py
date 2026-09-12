from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from dkwess_securerepo.models import AuditResult, CapabilityAssessment, ScanMetrics
from dkwess_securerepo.release import REQUIRED_PUBLIC_FILES, release_readiness


class ReleaseTests(unittest.TestCase):
    def test_license_is_separate_from_technical_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in REQUIRED_PUBLIC_FILES:
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text("fixture\n", encoding="utf-8")
            result = AuditResult(
                root=str(root), findings=[], manifests=["pyproject.toml"],
                capabilities=[CapabilityAssessment("Governance", "PASS", "FULL", 0, "fixture")],
                metrics=ScanMetrics(1, 0, 0, 1, 1), tool_version="1.0.0",
            )
            readiness = release_readiness(root, result)
            self.assertTrue(readiness["technical_ready"])
            self.assertFalse(readiness["open_source_reuse_ready"])
            (root / "LICENSE").write_text("fixture license\n", encoding="utf-8")
            self.assertTrue(release_readiness(root, result)["open_source_reuse_ready"])


if __name__ == "__main__": unittest.main()

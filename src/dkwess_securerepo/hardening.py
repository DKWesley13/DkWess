from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

MAX_DISCOVERED_FILES = 100_000
MAX_WORKFLOW_BYTES = 1_048_576
IGNORED_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__", "reports", "dist", "build"}


@dataclass(frozen=True)
class PreflightStats:
    files_seen: int
    workflow_files_seen: int
    symlinks_skipped: int


def preflight_repository(root: str | Path) -> PreflightStats:
    original = Path(root).expanduser()
    if original.is_symlink():
        raise ValueError("Repository root must not be a symbolic link")
    resolved = original.resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"Repository path does not exist: {resolved}")
    if not resolved.is_dir():
        raise NotADirectoryError(f"Repository path is not a directory: {resolved}")
    files_seen = 0
    workflow_files_seen = 0
    symlinks_skipped = 0
    workflow_dir = resolved / ".github" / "workflows"
    for dirpath, dirnames, filenames in os.walk(resolved, topdown=True, followlinks=False):
        directory = Path(dirpath)
        kept: list[str] = []
        for dirname in dirnames:
            if dirname in IGNORED_DIRS:
                continue
            candidate = directory / dirname
            if candidate.is_symlink():
                symlinks_skipped += 1
                continue
            kept.append(dirname)
        dirnames[:] = kept
        for filename in filenames:
            candidate = directory / filename
            if candidate.is_symlink():
                symlinks_skipped += 1
                continue
            files_seen += 1
            if files_seen > MAX_DISCOVERED_FILES:
                raise ValueError(f"Repository exceeds SecureRepo file preflight limit ({MAX_DISCOVERED_FILES})")
            if candidate.parent == workflow_dir and candidate.suffix.lower() in {".yml", ".yaml"}:
                workflow_files_seen += 1
                try:
                    size = candidate.stat().st_size
                except OSError as exc:
                    raise ValueError(f"Unable to stat workflow {candidate.name}: {exc.__class__.__name__}") from exc
                if size > MAX_WORKFLOW_BYTES:
                    raise ValueError(f"Workflow {candidate.name} exceeds SecureRepo text limit ({MAX_WORKFLOW_BYTES} bytes)")
    return PreflightStats(files_seen, workflow_files_seen, symlinks_skipped)


def describe_limits() -> dict[str, int]:
    return {"max_discovered_files": MAX_DISCOVERED_FILES, "max_workflow_bytes": MAX_WORKFLOW_BYTES}

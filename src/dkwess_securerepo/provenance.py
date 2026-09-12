from __future__ import annotations

import configparser
import json
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .models import AuditResult


def _sanitize_remote(value: str) -> str:
    value = value.strip()
    if "://" not in value:
        return value
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


def _git_dir(root: Path) -> Path | None:
    candidate = root / ".git"
    if candidate.is_dir():
        return candidate
    if candidate.is_file():
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return None
        if text.lower().startswith("gitdir:"):
            target = text.split(":", 1)[1].strip()
            resolved = (root / target).resolve() if not Path(target).is_absolute() else Path(target)
            return resolved if resolved.is_dir() else None
    return None


def _head(git_dir: Path) -> tuple[str | None, str | None]:
    try:
        text = (git_dir / "HEAD").read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None, None
    if not text.startswith("ref:"):
        return text or None, None
    ref = text.split(":", 1)[1].strip()
    try:
        value = (git_dir / ref).read_text(encoding="utf-8", errors="replace").strip()
        if value:
            return value, ref
    except OSError:
        pass
    try:
        packed = (git_dir / "packed-refs").read_text(encoding="utf-8", errors="replace")
        for line in packed.splitlines():
            if not line or line.startswith("#") or line.startswith("^"):
                continue
            sha, name = line.split(" ", 1)
            if name.strip() == ref:
                return sha.strip(), ref
    except (OSError, ValueError):
        pass
    return None, ref


def _origin(git_dir: Path) -> str | None:
    parser = configparser.ConfigParser()
    try:
        parser.read(git_dir / "config", encoding="utf-8")
    except (OSError, configparser.Error):
        return None
    section = 'remote "origin"'
    if parser.has_option(section, "url"):
        return _sanitize_remote(parser.get(section, "url"))
    return None


def provenance_payload(root: str | Path, result: AuditResult) -> dict[str, object]:
    root_path = Path(root).expanduser().resolve()
    git_dir = _git_dir(root_path)
    head_sha: str | None = None
    head_ref: str | None = None
    origin: str | None = None
    if git_dir is not None:
        head_sha, head_ref = _head(git_dir)
        origin = _origin(git_dir)
    return {
        "schema_version": 1,
        "tool": "DkWess SecureRepo",
        "tool_version": result.tool_version,
        "repository_root": str(root_path),
        "vcs": "git" if git_dir is not None else None,
        "origin": origin,
        "head_sha": head_sha,
        "head_ref": head_ref,
        "manifests": list(result.manifests),
        "statement": "Local provenance evidence only; no remote trust or authenticity claim is made.",
    }


def write_provenance(root: str | Path, result: AuditResult, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(provenance_payload(root, result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target

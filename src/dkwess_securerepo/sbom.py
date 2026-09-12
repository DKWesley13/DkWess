from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import tomllib
import uuid

from .models import AuditResult

REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(?:\[.*?\])?\s*(.*)$")


def _component(name: str, version: str | None, source: str, ecosystem: str) -> dict[str, object]:
    item: dict[str, object] = {"type": "library", "name": name, "properties": [{"name": "dkwess:source", "value": source}, {"name": "dkwess:ecosystem", "value": ecosystem}]}
    if version:
        item["version"] = version
    return item


def _parse_requirement(text: str) -> tuple[str, str | None] | None:
    line = text.split("#", 1)[0].strip()
    if not line or line.startswith(("-", "http://", "https://", "git+")):
        return None
    line = line.split(";", 1)[0].strip()
    match = REQ_NAME_RE.match(line)
    if not match:
        return None
    name, spec = match.groups()
    exact = re.search(r"(?:^|,)\s*==\s*([^,\s]+)", spec)
    return name, exact.group(1) if exact else None


def _python_components(path: Path, relative: str) -> list[dict[str, object]]:
    components: list[dict[str, object]] = []
    if path.name.startswith("requirements") and path.suffix == ".txt":
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                parsed = _parse_requirement(line)
                if parsed:
                    components.append(_component(parsed[0], parsed[1], relative, "pypi"))
        except OSError:
            pass
    elif path.name == "pyproject.toml":
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, tomllib.TOMLDecodeError):
            return components
        project = data.get("project", {}) if isinstance(data, dict) else {}
        if isinstance(project, dict):
            for dep in project.get("dependencies", []) or []:
                if isinstance(dep, str):
                    parsed = _parse_requirement(dep)
                    if parsed:
                        components.append(_component(parsed[0], parsed[1], relative, "pypi"))
    return components


def _node_components(path: Path, relative: str) -> list[dict[str, object]]:
    if path.name != "package-lock.json":
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    components: list[dict[str, object]] = []
    packages = data.get("packages", {}) if isinstance(data, dict) else {}
    if isinstance(packages, dict):
        for key, value in packages.items():
            if not key or not isinstance(value, dict):
                continue
            name = value.get("name")
            if not isinstance(name, str):
                marker = "node_modules/"
                name = key.rsplit(marker, 1)[-1] if marker in key else None
            if isinstance(name, str) and name:
                version = value.get("version") if isinstance(value.get("version"), str) else None
                components.append(_component(name, version, relative, "npm"))
    return components


def _go_components(path: Path, relative: str) -> list[dict[str, object]]:
    if path.name != "go.mod":
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    components: list[dict[str, object]] = []
    in_require = False
    for raw in lines:
        line = raw.split("//", 1)[0].strip()
        if line == "require (":
            in_require = True; continue
        if in_require and line == ")":
            in_require = False; continue
        if line.startswith("require "):
            line = line[len("require "):].strip()
        elif not in_require:
            continue
        parts = line.split()
        if len(parts) >= 2:
            components.append(_component(parts[0], parts[1], relative, "golang"))
    return components


def sbom_payload(root: str | Path, result: AuditResult) -> dict[str, object]:
    root_path = Path(root).expanduser().resolve()
    components: list[dict[str, object]] = []
    for relative in result.manifests:
        path = root_path / relative
        components.extend(_python_components(path, relative))
        components.extend(_node_components(path, relative))
        components.extend(_go_components(path, relative))
    dedup: dict[tuple[str, str, str], dict[str, object]] = {}
    for item in components:
        props = item.get("properties", [])
        ecosystem = ""
        if isinstance(props, list):
            for prop in props:
                if isinstance(prop, dict) and prop.get("name") == "dkwess:ecosystem":
                    ecosystem = str(prop.get("value", ""))
        key = (ecosystem, str(item.get("name", "")), str(item.get("version", "")))
        dedup[key] = item
    ordered = [dedup[key] for key in sorted(dedup)]
    digest = hashlib.sha256(json.dumps(ordered, sort_keys=True).encode("utf-8")).hexdigest()
    serial = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/DKWesley13/DkWess/sbom/" + digest)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "DkWess SecureRepo", "version": result.tool_version}]},
            "properties": [
                {"name": "dkwess:scope", "value": "static-local-manifest-inventory"},
                {"name": "dkwess:statement", "value": "This SBOM is best-effort static inventory, not a build-resolved attestation."},
            ],
        },
        "components": ordered,
    }


def write_sbom(root: str | Path, result: AuditResult, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(sbom_payload(root, result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target

from __future__ import annotations

import json
from pathlib import Path
import re

from .models import AuditResult

USES_RE = re.compile(r"^\s*-?\s*uses\s*:\s*['\"]?([^\s#'\"]+)")
FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def supply_chain_payload(root: str | Path, result: AuditResult) -> dict[str, object]:
    root_path = Path(root).expanduser().resolve()
    components: list[dict[str, object]] = []
    for manifest in result.manifests:
        components.append({"kind": "manifest", "name": Path(manifest).name, "source_path": manifest})
    workflows = root_path / ".github" / "workflows"
    if workflows.is_dir():
        paths = sorted(list(workflows.glob("*.yml")) + list(workflows.glob("*.yaml")))
        for workflow in paths:
            try:
                text = workflow.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                match = USES_RE.match(line.split("#", 1)[0])
                if not match:
                    continue
                reference = match.group(1)
                if reference.startswith("./"):
                    continue
                if reference.startswith("docker://"):
                    components.append({
                        "kind": "container-action",
                        "name": reference,
                        "reference": reference,
                        "immutable": "@sha256:" in reference,
                        "source_path": f"{workflow.relative_to(root_path).as_posix()}:{line_number}",
                    })
                    continue
                action, separator, ref = reference.rpartition("@")
                components.append({
                    "kind": "github-action",
                    "name": action if separator else reference,
                    "reference": ref if separator else None,
                    "immutable": bool(separator and FULL_SHA_RE.fullmatch(ref)),
                    "source_path": f"{workflow.relative_to(root_path).as_posix()}:{line_number}",
                })
    components.sort(key=lambda item: (str(item.get("kind")), str(item.get("name")), str(item.get("source_path"))))
    return {
        "schema_version": 1,
        "tool": "DkWess SecureRepo",
        "tool_version": result.tool_version,
        "components": components,
        "component_count": len(components),
        "limitations": [
            "This inventory is static and local.",
            "It does not query vulnerability databases or execute package managers.",
            "Manifest presence does not prove every transitive dependency was resolved.",
        ],
    }


def write_supply_chain(root: str | Path, result: AuditResult, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(supply_chain_payload(root, result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target

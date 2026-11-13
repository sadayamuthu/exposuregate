"""Parser for ``package-lock.json`` v2/v3 (spec section 5.4)."""

from __future__ import annotations

import json
from typing import Any

from exposuregate.models import LockfileError, ParsedLockfile, Pin, Skipped

_NM = "node_modules/"
_DECLARATION_KEYS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def _table(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _declared(entry: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for key in _DECLARATION_KEYS:
        names |= set(_table(entry.get(key)))
    return names


def _key_name(key: str) -> str:
    return key.rsplit(_NM, 1)[1]


def _is_direct(key: str, roots: dict[str, set[str]]) -> bool:
    """Key is a top-level install and some root declares it.

    A top-level ``node_modules/<name>`` is hoisted, so any root (the project or a workspace
    folder) may have declared it; ``<workspace>/node_modules/<name>`` only that workspace.
    """
    prefix, _, name = key.rpartition(_NM)
    if _NM in prefix:
        return False
    if prefix == "":
        return any(name in declared for declared in roots.values())
    return name in roots.get(prefix.rstrip("/"), set())


def _skip_reason(entry: dict[str, Any]) -> str | None:
    if entry.get("link") is True:
        return "source:link"
    resolved = entry.get("resolved")
    if not isinstance(resolved, str) or resolved.startswith("https://"):
        return None
    if resolved.startswith(("git+", "git:")):
        return "source:git"
    if resolved.startswith("file:"):
        return "source:file"
    return "source:url"


def parse_npm(text: str) -> ParsedLockfile:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LockfileError("lockfile_parse", f"package-lock.json is invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise LockfileError("lockfile_parse", "package-lock.json is not a JSON object")
    if data.get("lockfileVersion") not in (2, 3):
        raise LockfileError(
            "lockfile_unsupported",
            f"package-lock.json lockfileVersion {data.get('lockfileVersion')!r} is not supported",
        )
    packages = data.get("packages")
    if not isinstance(packages, dict):
        raise LockfileError("lockfile_parse", "package-lock.json has no 'packages' table")

    # Root ("") and workspace folders (keys outside node_modules/) declare direct deps.
    roots = {k: _declared(_table(v)) for k, v in packages.items() if _NM not in k}

    occurrences: dict[tuple[str, str], list[tuple[str, bool]]] = {}
    non_dev: set[tuple[str, str]] = set()
    skipped: list[Skipped] = []
    for key, raw in packages.items():
        if _NM not in key:
            continue
        entry = _table(raw)
        key_name = _key_name(key)
        alias = entry.get("name")
        name = alias if isinstance(alias, str) else key_name
        reason = _skip_reason(entry)
        if reason is not None:
            item = Skipped(name, reason)
            if item not in skipped:
                skipped.append(item)
            continue
        version = entry.get("version")
        if not isinstance(version, str) or not version:
            raise LockfileError("lockfile_parse", f"package-lock.json entry {key!r} has no version")
        direct = _is_direct(key, roots)
        occurrences.setdefault((name, version), []).append((key, direct))
        if entry.get("dev") is not True:
            non_dev.add((name, version))
    pins = [
        Pin(
            "npm",
            name,
            version,
            "direct" if any(d for _, d in occ) else "transitive",
            paths=tuple(sorted(k for k, _ in occ)),
            dev_only=(name, version) not in non_dev,
        )
        for (name, version), occ in occurrences.items()
    ]
    return ParsedLockfile(type="npm", ecosystem="npm", pins=pins, skipped=skipped)

"""Parser for ``uv.lock`` (spec section 5.3)."""

from __future__ import annotations

import sys
from typing import Any

from exposuregate.models import LockfileError, ParsedLockfile, Pin, Skipped
from exposuregate.versions import normalize_name

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

_WORKSPACE_SOURCES = ("editable", "virtual")


def _table(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _dep_names(entries: Any) -> set[str]:
    names: set[str] = set()
    for dep in entries if isinstance(entries, list) else []:
        name = _table(dep).get("name")
        if isinstance(name, str):
            names.add(normalize_name("PyPI", name))
    return names


def _root_dependency_names(root: dict[str, Any]) -> set[str]:
    names = _dep_names(root.get("dependencies"))
    for key in ("optional-dependencies", "dev-dependencies"):
        for group in _table(root.get(key)).values():
            names |= _dep_names(group)
    return names


def _skip_reason(source: dict[str, Any]) -> str | None:
    """Reason a package is not graded, or None for a registry package."""
    if any(k in source for k in _WORKSPACE_SOURCES):
        return "source:workspace"
    if "registry" in source:
        return None
    for kind in ("git", "path", "directory", "url"):
        if kind in source:
            return f"source:{kind}"
    return "source:unknown"


def parse_uv(text: str) -> ParsedLockfile:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise LockfileError("lockfile_parse", f"uv.lock is not valid TOML: {exc}") from exc
    entries = [_table(e) for e in data.get("package") or []]
    direct: set[str] = set()
    for entry in entries:
        if _skip_reason(_table(entry.get("source"))) == "source:workspace":
            direct |= _root_dependency_names(entry)
    pins: list[Pin] = []
    skipped: list[Skipped] = []
    for entry in entries:
        name, version = entry.get("name"), entry.get("version")
        if not isinstance(name, str):
            raise LockfileError("lockfile_parse", "uv.lock package entry lacks a name")
        norm = normalize_name("PyPI", name)
        reason = _skip_reason(_table(entry.get("source")))
        if reason is not None:
            skipped.append(Skipped(norm, reason))
            continue
        if not isinstance(version, str) or not version:
            raise LockfileError("lockfile_parse", f"uv.lock package {name!r} lacks a version")
        pins.append(Pin("PyPI", norm, version, "direct" if norm in direct else "transitive"))
    return ParsedLockfile(type="uv", ecosystem="PyPI", pins=pins, skipped=skipped)

"""Parser for ``poetry.lock`` (spec section 5.2)."""

from __future__ import annotations

import sys
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from exposuregate.models import LockfileError, ParsedLockfile, Pin, Skipped
from exposuregate.versions import normalize_name

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


def _table(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _pep508_name(spec: Any) -> str | None:
    if not isinstance(spec, str):
        return None
    try:
        return Requirement(spec).name
    except InvalidRequirement:
        return None


def _direct_names(manifest_text: str | None) -> set[str] | None:
    """Normalized direct dependency names, or None when there is no readable manifest."""
    if manifest_text is None:
        return None
    try:
        data = tomllib.loads(manifest_text)
    except tomllib.TOMLDecodeError:
        return None
    names: list[str] = []
    poetry = _table(_table(data.get("tool")).get("poetry"))
    names += _table(poetry.get("dependencies"))
    names += _table(poetry.get("dev-dependencies"))
    for group in _table(poetry.get("group")).values():
        names += _table(_table(group).get("dependencies"))
    project = _table(data.get("project"))
    specs = list(project.get("dependencies") or [])
    for extra in _table(project.get("optional-dependencies")).values():
        specs += list(extra or [])
    names += [n for n in (_pep508_name(s) for s in specs) if n]
    return {normalize_name("PyPI", n) for n in names if n.lower() != "python"}


def parse_poetry(text: str, manifest_text: str | None) -> ParsedLockfile:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise LockfileError("lockfile_parse", f"poetry.lock is not valid TOML: {exc}") from exc
    direct = _direct_names(manifest_text)
    pins: list[Pin] = []
    skipped: list[Skipped] = []
    for entry in data.get("package") or []:
        entry = _table(entry)
        name, version = entry.get("name"), entry.get("version")
        if not isinstance(name, str) or not isinstance(version, str) or not version:
            raise LockfileError(
                "lockfile_parse", f"poetry.lock package entry lacks name/version: {name!r}"
            )
        norm = normalize_name("PyPI", name)
        source_type = _table(entry.get("source")).get("type")
        if source_type is not None and source_type != "legacy":
            skipped.append(Skipped(norm, f"source:{source_type}"))
            continue
        if direct is None:
            dependency = "unknown"
        else:
            dependency = "direct" if norm in direct else "transitive"
        pins.append(
            Pin(
                "PyPI",
                norm,
                version,
                dependency,
                source="legacy" if source_type == "legacy" else None,
            )
        )
    return ParsedLockfile(type="poetry", ecosystem="PyPI", pins=pins, skipped=skipped)

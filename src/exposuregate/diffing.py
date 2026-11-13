"""Diff two parsed lockfiles into added/changed pins."""

from __future__ import annotations

from functools import cmp_to_key

from exposuregate.models import ChangedPin, ParsedLockfile, Pin
from exposuregate.versions import InvalidVersion, compare


def _cmp(ecosystem: str, a: str, b: str) -> int:
    try:
        return compare(ecosystem, a, b)
    except InvalidVersion:
        return (a > b) - (a < b)


def changed_pins(old: ParsedLockfile | None, new: ParsedLockfile) -> list[ChangedPin]:
    """Pins in new whose key is not in old, with the lowest differing old version."""
    old_pins = old.pins if old is not None else []
    old_keys = {p.key for p in old_pins}
    old_versions: dict[str, set[str]] = {}
    for p in old_pins:
        if p.version:
            old_versions.setdefault(p.name, set()).add(p.version)

    def previous(pin: Pin) -> str | None:
        if not pin.version:
            return None
        others = [v for v in old_versions.get(pin.name, ()) if v != pin.version]
        if not others:
            return None
        def cmp(a: str, b: str) -> int:
            return _cmp(pin.ecosystem, a, b)

        return min(others, key=cmp_to_key(cmp))

    out = [ChangedPin(p, previous(p)) for p in new.pins if p.key not in old_keys]
    out.sort(key=lambda c: (c.pin.name, c.pin.version or c.pin.unpinned_spec or ""))
    return out

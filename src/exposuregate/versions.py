"""Package-name normalisation and version ordering (PEP 440 for PyPI, SemVer 2.0 for npm)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from packaging.version import InvalidVersion, Version

__all__ = ["InvalidVersion", "compare", "normalize_name", "parse_version"]

_SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


@dataclass(frozen=True)
class SemVer:
    major: int
    minor: int
    patch: int
    pre: tuple[str, ...]  # empty tuple means a release

    def _key(self) -> tuple[tuple[int, int, int], int, tuple[tuple[int, int, str], ...]]:
        # Release sorts after any pre-release; numeric ids < alphanumeric ids.
        ids = tuple(
            (0, int(p), "") if p.isdigit() else (1, 0, p) for p in self.pre
        )
        return ((self.major, self.minor, self.patch), 0 if self.pre else 1, ids)

    def __lt__(self, other: SemVer) -> bool:
        return self._key() < other._key()

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SemVer) and self._key() == other._key()

    def __hash__(self) -> int:
        return hash(self._key())


def normalize_name(ecosystem: str, name: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


def _parse_semver(v: str) -> SemVer:
    s = v.strip()
    if s.startswith("v"):
        s = s[1:]
    m = _SEMVER.match(s)
    if not m:
        raise InvalidVersion(f"Invalid semantic version: {v!r}")
    pre = tuple(m.group(4).split(".")) if m.group(4) else ()
    if any(p.isdigit() and len(p) > 1 and p.startswith("0") for p in pre):
        raise InvalidVersion(f"Invalid semantic version: {v!r}")
    return SemVer(int(m.group(1)), int(m.group(2)), int(m.group(3)), pre)


def parse_version(ecosystem: str, v: str) -> object:
    if ecosystem == "PyPI":
        return Version(v)
    return _parse_semver(v)


def compare(ecosystem: str, a: str, b: str) -> int:
    pa, pb = parse_version(ecosystem, a), parse_version(ecosystem, b)
    if pa == pb:
        return 0
    return -1 if pa < pb else 1  # type: ignore[operator]

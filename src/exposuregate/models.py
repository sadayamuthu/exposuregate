"""Core data models shared across ExposureGate modules."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Any

ACTION_RANK = {"pass": 0, "warn": 1, "block": 2}


@dataclass(frozen=True)
class Pin:
    ecosystem: str
    name: str
    version: str
    dependency: str
    paths: tuple[str, ...] = ()
    source: str | None = None
    marker: str | None = None
    dev_only: bool = False
    unpinned_spec: str | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.name, self.version or self.unpinned_spec or "")


@dataclass(frozen=True)
class ChangedPin:
    pin: Pin
    previous_version: str | None


@dataclass(frozen=True)
class Skipped:
    package: str
    reason: str


@dataclass
class ParsedLockfile:
    type: str
    ecosystem: str
    pins: list[Pin]
    skipped: list[Skipped]


@dataclass
class Denial:
    code: str
    detail: str
    enforced: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    finding_id: str
    lockfile: str
    ecosystem: str
    package: str
    version: str
    previous_version: str | None
    dependency: str
    reason: str
    cve_id: str | None
    advisory_ids: list[str]
    exposure_tier: str | None
    kev_listed: bool
    kev_date_added: str | None
    epss_score: float | None
    cvss_score: float | None
    fixed_in: list[str]
    base_action: str
    action: str
    suppressed_by: str | None
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def make_finding_id(
    lockfile: str, ecosystem: str, package: str, version: str, ident: str | None, reason: str
) -> str:
    """sha256 over lockfile|ecosystem|package|version|cve-or-advisory id|reason."""
    raw = "|".join([lockfile, ecosystem, package, version, ident or "", reason])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class LockfileError(Exception):
    """Lockfile problem; code is lockfile_parse or lockfile_unsupported."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code

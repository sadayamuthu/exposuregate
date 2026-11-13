"""OSV advisory matching and CVE extraction (spec 7.1, 7.2)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from functools import cmp_to_key
from typing import Any

from exposuregate.versions import InvalidVersion, compare, normalize_name, parse_version

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_RANGE_TYPES = ("ECOSYSTEM", "SEMVER")
_VERSION_KEYS = ("introduced", "fixed", "last_affected", "limit")


@dataclass
class Match:
    advisory_id: str
    fixed_in: list[str]


def cve_ids(record: dict[str, Any]) -> list[str]:
    ids = [record.get("id", ""), *record.get("aliases", [])]
    return sorted({i for i in ids if isinstance(i, str) and CVE_RE.match(i)})


def _in_range(v: str, events: list[dict[str, str]], eco: str) -> bool:
    def cmp(a: str, b: str) -> int:
        return compare(eco, a, b)

    def sort_key(e: dict[str, str]) -> str:
        for k in ("introduced", "fixed", "last_affected"):
            if k in e:
                return e[k]
        return "0"

    def order(a: dict[str, str], b: dict[str, str]) -> int:
        ka, kb = sort_key(a), sort_key(b)
        if ka == kb:
            return 0
        if ka == "0":
            return -1
        if kb == "0":
            return 1
        return cmp(ka, kb)

    affected = False
    for e in sorted(events, key=cmp_to_key(order)):
        if "introduced" in e and (e["introduced"] == "0" or cmp(v, e["introduced"]) >= 0):
            affected = True
        elif "fixed" in e and cmp(v, e["fixed"]) >= 0:
            affected = False
        elif "last_affected" in e and cmp(v, e["last_affected"]) > 0:
            affected = False
    limits = [e["limit"] for e in events if "limit" in e]
    if limits and all(cmp(v, lim) >= 0 for lim in limits):
        affected = False
    return affected


def _events_parse(eco: str, events: list[dict[str, str]]) -> bool:
    for e in events:
        for k in _VERSION_KEYS:
            if k in e and e[k] != "0":
                try:
                    parse_version(eco, e[k])
                except InvalidVersion:
                    return False
    return True


def _withdrawn(record: dict[str, Any], now: date) -> bool:
    w = record.get("withdrawn")
    if not w:
        return False
    try:
        return date.fromisoformat(str(w)[:10]) <= now
    except ValueError:
        return False  # unreadable marker: keep the advisory visible


def _strip_v(s: str) -> str:
    return s[1:] if s.startswith("v") else s


def _in_versions_list(eco: str, pin: str, listed: list[str]) -> bool:
    if eco != "PyPI":
        return any(_strip_v(x) == _strip_v(pin) for x in listed)
    pv = parse_version(eco, pin)
    for x in listed:
        try:
            if parse_version(eco, x) == pv:
                return True
        except InvalidVersion:
            if x == pin:
                return True
    return False


def match(
    record: dict[str, Any], ecosystem: str, name: str, version: str, now: date
) -> Match | None:
    if _withdrawn(record, now):
        return None
    want = normalize_name(ecosystem, name)
    entries = [
        a
        for a in record.get("affected", [])
        if a.get("package", {}).get("ecosystem") == ecosystem
        and normalize_name(ecosystem, a["package"].get("name", "")) == want
    ]
    if not entries:
        return None

    ranges = [
        r["events"]
        for a in entries
        for r in a.get("ranges", [])
        if r.get("type") in _RANGE_TYPES
    ]
    listed = [x for a in entries for x in a.get("versions", [])]
    needs_parse = bool(ranges) or (ecosystem == "PyPI" and bool(listed))
    if needs_parse:
        parse_version(ecosystem, version)  # raises InvalidVersion for the caller

    fixed: set[str] = set()
    hit = False
    for a in entries:
        in_list = bool(a.get("versions")) and _in_versions_list(
            ecosystem, version, a["versions"]
        )
        for r in a.get("ranges", []):
            if r.get("type") not in _RANGE_TYPES:
                continue
            events = r["events"]
            if not _events_parse(ecosystem, events):
                continue  # cannot evaluate a range with unparseable events
            inside = _in_range(version, events, ecosystem)
            if inside or in_list:
                hit = hit or inside
                fixed.update(e["fixed"] for e in events if "fixed" in e)
        hit = hit or in_list
    if not hit:
        return None

    def fixed_order(x: str, y: str) -> int:
        return compare(ecosystem, x, y)

    ordered = sorted(fixed, key=cmp_to_key(fixed_order))
    return Match(record["id"], ordered)

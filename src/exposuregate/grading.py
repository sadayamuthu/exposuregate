"""Grading, policy, suppressions and verdict (spec 7.3)."""

from __future__ import annotations

from dataclasses import replace
from datetime import date
from typing import Any

from exposuregate.config import Config, Suppression
from exposuregate.models import ACTION_RANK, ChangedPin, Denial, Finding, make_finding_id
from exposuregate.osv import CVE_RE, cve_ids, match
from exposuregate.store import DataStore
from exposuregate.versions import InvalidVersion, normalize_name


def _notes(cp: ChangedPin) -> list[str]:
    pin = cp.pin
    notes: list[str] = []
    if pin.marker:
        notes.append(f"marker: {pin.marker}")
    if pin.source:
        notes.append("source: legacy")
    if pin.dev_only:
        notes.append("dev_only")
    return notes


def _finding(
    lockfile: str,
    cp: ChangedPin,
    reason: str,
    base_action: str,
    *,
    cve_id: str | None = None,
    advisory_ids: list[str] | None = None,
    fixed_in: list[str] | None = None,
    row: dict[str, Any] | None = None,
) -> Finding:
    pin = cp.pin
    version = pin.version or pin.unpinned_spec or ""
    advisory_ids = advisory_ids or []
    ident = cve_id or (advisory_ids[0] if advisory_ids else None)
    row = row or {}
    return Finding(
        finding_id=make_finding_id(lockfile, pin.ecosystem, pin.name, version, ident, reason),
        lockfile=lockfile,
        ecosystem=pin.ecosystem,
        package=pin.name,
        version=version,
        previous_version=cp.previous_version,
        dependency=pin.dependency,
        reason=reason,
        cve_id=cve_id,
        advisory_ids=advisory_ids,
        exposure_tier=row.get("exposure_tier"),
        kev_listed=bool(row.get("kev_listed")),
        kev_date_added=row.get("kev_date_added"),
        epss_score=row.get("epss_score"),
        cvss_score=row.get("cvss_score"),
        fixed_in=fixed_in or [],
        base_action=base_action,
        action=base_action,
        suppressed_by=None,
        notes=_notes(cp),
    )


def _grade_pin(
    lockfile: str, cp: ChangedPin, store: DataStore, cfg: Config, now: date
) -> list[Finding]:
    pin = cp.pin
    if not pin.version:
        return [_finding(lockfile, cp, "unpinned", cfg.policy["unpinned"])]

    cves: dict[str, tuple[set[str], set[str]]] = {}
    no_cve: dict[str, set[str]] = {}
    for rec in store.advisories(pin.ecosystem, pin.name):
        try:
            m = match(rec, pin.ecosystem, pin.name, pin.version, now)
        except InvalidVersion:
            action = cfg.policy["unparseable_version"]
            return [_finding(lockfile, cp, "unparseable_version", action)]
        if m is None:
            continue
        ids = cve_ids(rec)
        if not ids:
            no_cve.setdefault(m.advisory_id, set()).update(m.fixed_in)
        for cve in ids:
            adv, fixed = cves.setdefault(cve, (set(), set()))
            adv.add(m.advisory_id)
            fixed.update(m.fixed_in)

    out: list[Finding] = []
    for cve in sorted(cves):
        adv, fixed = cves[cve]
        row = store.oebc(cve)
        if row is None:
            reason, base = "not_in_oebc", cfg.policy["not_in_oebc"]
        else:
            reason, base = "graded", cfg.policy[str(row["exposure_tier"])]
        out.append(
            _finding(
                lockfile, cp, reason, base, cve_id=cve, advisory_ids=sorted(adv),
                fixed_in=sorted(fixed), row=row,
            )
        )
    for adv_id in sorted(no_cve):
        out.append(
            _finding(
                lockfile, cp, "no_cve", cfg.policy["no_cve"], advisory_ids=[adv_id],
                fixed_in=sorted(no_cve[adv_id]),
            )
        )
    return out


def grade(
    lockfile: str,
    changes: list[ChangedPin],
    store: DataStore,
    cfg: Config,
    now: date,
) -> list[Finding]:
    findings: list[Finding] = []
    for cp in changes:
        for f in _grade_pin(lockfile, cp, store, cfg, now):
            findings.append(apply_policy(f, cp.pin.dependency, cfg, now))
    return findings


def unsupported_finding(lockfile: str, cfg: Config) -> Finding:
    action = cfg.policy["unsupported_lockfile"]
    return Finding(
        finding_id=make_finding_id(lockfile, "", "", "", None, "unsupported_lockfile"),
        lockfile=lockfile, ecosystem="", package="", version="", previous_version=None,
        dependency="direct", reason="unsupported_lockfile", cve_id=None, advisory_ids=[],
        exposure_tier=None, kev_listed=False, kev_date_added=None, epss_score=None,
        cvss_score=None, fixed_in=[], base_action=action, action=action,
        suppressed_by=None, notes=[],
    )


def _suppression_matches(s: Suppression, f: Finding) -> bool:
    if s.id != f.cve_id and s.id not in f.advisory_ids:
        return False
    if s.ecosystem is not None and s.ecosystem != f.ecosystem:
        return False
    if s.package is not None and normalize_name(f.ecosystem, s.package) != normalize_name(
        f.ecosystem, f.package
    ):
        return False
    return True


def apply_policy(finding: Finding, dependency: str, cfg: Config, now: date) -> Finding:
    action = finding.action
    if dependency == "transitive" and ACTION_RANK[action] > ACTION_RANK[cfg.transitive_max_action]:
        action = cfg.transitive_max_action
    out = replace(finding, action=action)
    for s in cfg.suppressions:
        if s.expires >= now and _suppression_matches(s, finding):
            return replace(out, action="pass", suppressed_by=s.id)
    return out


def expired_suppressions(
    findings: list[Finding], cfg: Config, now: date
) -> tuple[list[dict[str, Any]], list[Finding]]:
    report: list[dict[str, Any]] = []
    extra: list[Finding] = []
    for s in cfg.suppressions:
        if s.expires >= now or not any(_suppression_matches(s, f) for f in findings):
            continue
        eco, pkg = s.ecosystem or "", s.package or ""
        is_cve = bool(CVE_RE.match(s.id))
        report.append(
            {
                "id": s.id, "package": pkg, "ecosystem": eco,
                "reason": s.reason, "expires": s.expires.isoformat(),
            }
        )
        extra.append(
            Finding(
                finding_id=make_finding_id("", eco, pkg, "", s.id, "suppression_expired"),
                lockfile="", ecosystem=eco, package=pkg, version="", previous_version=None,
                dependency="direct", reason="suppression_expired",
                cve_id=s.id if is_cve else None,
                advisory_ids=[] if is_cve else [s.id],
                exposure_tier=None, kev_listed=False, kev_date_added=None, epss_score=None,
                cvss_score=None, fixed_in=[], base_action="warn", action="warn",
                suppressed_by=None,
                notes=[f"suppression for {s.id} expired on {s.expires.isoformat()}"],
            )
        )
    return report, extra


def verdict(findings: list[Finding], denials: list[Denial], fail_closed: bool) -> tuple[str, int]:
    if fail_closed and any(d.enforced for d in denials):
        return "DENY", 2
    worst = max((ACTION_RANK[f.action] for f in findings), default=0)
    if denials:
        worst = max(worst, ACTION_RANK["warn"])
    if worst >= ACTION_RANK["block"]:
        return "BLOCK", 1
    if worst >= ACTION_RANK["warn"]:
        return "WARN", 0
    return "PASS", 0

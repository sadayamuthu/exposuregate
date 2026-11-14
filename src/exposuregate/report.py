"""JSON and Markdown reports (spec 9)."""

from __future__ import annotations

import json
from datetime import date, datetime, timezone
from typing import Any

from exposuregate import __version__
from exposuregate.config import Config
from exposuregate.models import ACTION_RANK, Denial, Finding
from exposuregate.store import DataMeta, SourceMeta


def _source(s: SourceMeta) -> str | None:
    src = s.extra.get("source")
    return src if isinstance(src, str) else None


def _age(s: SourceMeta, as_of: date) -> int:
    return (as_of - s.date.date()).days


def _data_section(meta: DataMeta | None, as_of: date) -> dict[str, Any]:
    data: dict[str, Any] = {"oebc": None, "osv": {}}
    if meta is None:
        return data
    if meta.oebc is not None:
        o = meta.oebc
        data["oebc"] = {
            "source": _source(o),
            "generated_at": o.date.isoformat(),
            "age_days": _age(o, as_of),
            "count": o.count,
            "project_version": o.extra.get("project_version"),
            "rules": o.extra.get("rules"),
        }
    for eco, s in meta.osv.items():
        data["osv"][eco] = {
            "source": _source(s),
            "as_of": s.date.isoformat(),
            "age_days": _age(s, as_of),
            "advisories": s.count,
        }
    if meta.replay is not None:
        data["replay"] = meta.replay
    return data


def build_report(
    *,
    verdict: str,
    exit_code: int,
    as_of: date,
    input: dict[str, Any],
    meta: DataMeta | None,
    cfg: Config,
    lockfiles: list[dict[str, Any]],
    findings: list[Finding],
    skipped: list[dict[str, Any]],
    denials: list[Denial],
    expired: list[dict[str, Any]],
    timing_ms: dict[str, int],
) -> dict[str, Any]:
    ordered = sorted(
        findings,
        key=lambda f: (-ACTION_RANK[f.action], f.lockfile, f.package, f.version),
    )
    summary = {a: sum(1 for f in findings if f.action == a) for a in ("block", "warn", "pass")}
    summary["denials"] = len(denials)
    return {
        "tool": {"name": "exposuregate", "version": __version__},
        "verdict": verdict,
        "exit_code": exit_code,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "as_of": as_of.isoformat(),
        "input": input,
        "data": _data_section(meta, as_of),
        "policy": {**cfg.policy, "transitive_max_action": cfg.transitive_max_action},
        "lockfiles": lockfiles,
        "findings": [f.to_dict() for f in ordered],
        "skipped": skipped,
        "denials": [d.to_dict() for d in denials],
        "expired_suppressions": expired,
        "summary": summary,
        "timing_ms": timing_ms,
    }


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)


def _cell(v: object) -> str:
    s = "" if v is None else str(v)
    return s.replace("|", "\\|").replace("\n", " ")


def to_markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    out = [
        f"# ExposureGate: {report['verdict']}",
        "",
        f"Verdict: **{report['verdict']}** (exit {report['exit_code']}) - "
        f"{s['block']} block, {s['warn']} warn, {s['pass']} pass, {s['denials']} denials",
        "",
    ]
    if report["denials"]:
        out += ["## Denials", ""]
        for d in report["denials"]:
            flag = "enforced" if d["enforced"] else "not enforced"
            out.append(f"- `{d['code']}` ({flag}): {_cell(d['detail'])}")
        out.append("")
    out += ["## Findings", ""]
    if report["findings"]:
        out += [
            "| action | package | version | dependency | CVE/advisory | tier | KEV | fixed in |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for f in report["findings"]:
            ident = f["cve_id"] or ", ".join(f["advisory_ids"])
            out.append(
                "| " + " | ".join(_cell(x) for x in (
                    f["action"], f["package"], f["version"], f["dependency"], ident,
                    f["exposure_tier"], "yes" if f["kev_listed"] else "no",
                    ", ".join(f["fixed_in"]),
                )) + " |"
            )
    else:
        out.append("No findings.")
    out += ["", "## Data", ""]
    d = report["data"]
    parts = [f"as of {report['as_of']}"]
    if d["oebc"]:
        o = d["oebc"]
        parts.append(f"OEBC generated {o['generated_at'][:10]} ({o['age_days']}d old)")
    else:
        parts.append("OEBC missing")
    for eco, v in d["osv"].items():
        parts.append(f"OSV {eco} {v['as_of'][:10]} ({v['age_days']}d old)")
    out += ["Data: " + "; ".join(parts), "", "## Lockfiles", ""]
    for lf in report["lockfiles"]:
        extra = ""
        if lf["status"] == "graded":
            extra = (f" ({lf.get('pins_added_or_changed', 0)} graded, "
                     f"{lf.get('pins_skipped', 0)} skipped)")
        out.append(f"- `{_cell(lf['path'])}` [{lf['type'] or '-'}]: {lf['status']}{extra}")
    if report["skipped"]:
        out += ["", "## Skipped packages", ""]
        for sk in report["skipped"]:
            out.append(f"- `{_cell(sk['lockfile'])}` {_cell(sk['package'])}: {_cell(sk['reason'])}")
    return "\n".join(out) + "\n"

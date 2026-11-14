import json
from dataclasses import replace
from datetime import date, datetime, timezone
from pathlib import Path

import jsonschema
import pytest

from exposuregate import __version__
from exposuregate.config import load_config
from exposuregate.models import Denial, Finding
from exposuregate.report import build_report, to_json, to_markdown
from exposuregate.store import DataMeta, SourceMeta

SCHEMA = json.loads(
    (Path(__file__).resolve().parent.parent / "schemas" / "report.schema.json").read_text()
)
REASONS = ["graded", "not_in_oebc", "no_cve", "unparseable_version", "unpinned",
           "unsupported_lockfile", "suppression_expired"]
AS_OF = date(2026, 11, 14)


def mk(reason="graded", action="block", package="urllib3", lockfile="uv.lock", version="1.26.4"):
    return Finding(
        finding_id="f" * 64, lockfile=lockfile, ecosystem="PyPI", package=package,
        version=version, previous_version=None, dependency="transitive", reason=reason,
        cve_id="CVE-1", advisory_ids=["GHSA-x"], exposure_tier="CRITICAL", kev_listed=True,
        kev_date_added="2026-01-01", epss_score=0.5, cvss_score=9.8, fixed_in=["1.26.5"],
        base_action=action, action=action, suppressed_by=None, notes=[],
    )


def meta():
    ts = datetime(2026, 11, 11, tzinfo=timezone.utc)
    return DataMeta(
        SourceMeta("oebc", ts, 10, {"project_version": "1", "rules": {"a": 1}}),
        {"PyPI": SourceMeta("osv:PyPI", datetime(2026, 11, 14, tzinfo=timezone.utc), 5)},
    )


def build(findings=None, denials=None, m="default", verdict="BLOCK", code=1, expired=None):
    cfg = load_config(None, Path("."))
    return build_report(
        verdict=verdict, exit_code=code, as_of=AS_OF,
        input={"mode": "pr", "base": "a", "head": "b"},
        meta=meta() if m == "default" else m, cfg=cfg,
        lockfiles=[
            {"path": "uv.lock", "type": "uv", "status": "graded",
             "pins_added_or_changed": 5, "pins_skipped": 1},
            {"path": "Gemfile.lock", "type": None, "status": "unsupported"},
        ],
        findings=findings if findings is not None else [mk(r) for r in REASONS],
        skipped=[{"lockfile": "uv.lock", "package": "my|lib", "reason": "source:path"}],
        denials=denials or [], expired=expired or [],
        timing_ms={"load_data": 1, "read_lockfiles": 2, "match": 3, "total": 6},
    )


def test_report_validates_against_schema():
    r = build(denials=[Denial("data_stale", "old")])
    jsonschema.validate(r, SCHEMA)
    jsonschema.validate(json.loads(to_json(r)), SCHEMA)
    assert r["tool"] == {"name": "exposuregate", "version": __version__}
    assert r["policy"]["transitive_max_action"] == "block"
    assert r["summary"]["denials"] == 1
    assert r["timestamp"].endswith("Z")
    jsonschema.validate(build(m=None), SCHEMA)
    assert build(m=None)["data"]["oebc"] is None


def test_schema_rejects_unknown_verdict():
    r = build()
    r["verdict"] = "MAYBE"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(r, SCHEMA)
    r = build()
    r["extra"] = 1
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(r, SCHEMA)


def test_markdown_contains_verdict_denials_and_rows():
    r = build(denials=[Denial("data_stale", "OEBC old", enforced=False)])
    md = to_markdown(r)
    assert "BLOCK" in md
    assert "data_stale" in md and "OEBC old" in md and "not enforced" in md
    assert "| action | lockfile | package | version | dependency | reason | CVE/advisory |" in md
    assert "| tier | KEV | fixed in |" in md
    assert "urllib3" in md and "CVE-1" in md and "1.26.5" in md
    assert "Gemfile.lock" in md and "unsupported" in md
    assert "my\\|lib" in md
    assert "2026-11-11" in md


def test_markdown_unsupported_row_is_identifiable():
    f = mk(reason="unsupported_lockfile", action="warn", package="", lockfile="yarn.lock",
           version="")
    md = to_markdown(build(findings=[f], verdict="WARN", code=0))
    (row,) = [ln for ln in md.splitlines() if "unsupported_lockfile" in ln and ln.startswith("|")]
    assert "yarn.lock" in row and row.startswith("| warn |")


def test_markdown_shows_suppression_notes_and_expired():
    f = replace(mk(), action="pass", suppressed_by="CVE-1", notes=["marker: x", "dev_only"])
    exp = [{"id": "CVE-9", "package": "foo", "ecosystem": "PyPI", "reason": "old|r",
            "expires": "2026-11-01"}]
    md = to_markdown(build(findings=[f], verdict="PASS", code=0, expired=exp))
    assert "| pass (suppressed: CVE-1) |" in md
    assert "marker: x; dev_only" in md
    assert "## Expired suppressions" in md
    assert "`CVE-9` [PyPI foo]: expired 2026-11-01 (old\\|r)" in md
    assert "## Expired suppressions" not in to_markdown(build())


def test_markdown_no_data_needed_vs_missing():
    md = to_markdown(build(findings=[], m=None, verdict="PASS", code=0))
    assert "no data needed (no graded change)" in md and "OEBC missing" not in md
    md = to_markdown(build(findings=[], m=None, denials=[Denial("data_missing", "x")]))
    assert "OEBC missing" in md


def test_ordering_block_first():
    fs = [mk(action="pass", package="a"), mk(action="block", package="z"),
          mk(action="warn", package="m")]
    r = build(findings=fs)
    assert [f["action"] for f in r["findings"]] == ["block", "warn", "pass"]
    assert r["summary"] == {"block": 1, "warn": 1, "pass": 1, "denials": 0}


def test_report_records_snapshot_dates():
    r = build()
    assert r["as_of"] == "2026-11-14"
    assert r["data"]["oebc"]["age_days"] == 3
    assert r["data"]["oebc"]["generated_at"].startswith("2026-11-11")
    assert r["data"]["osv"]["PyPI"]["age_days"] == 0
    assert r["data"]["osv"]["PyPI"]["advisories"] == 5
    m = meta()
    m.replay = {"replay": True, "osv_mode": "archived", "as_of": "2026-01-01",
                "archive_day": "2025-12-31"}
    r = build(m=m)
    assert r["data"]["replay"] == m.replay
    jsonschema.validate(r, SCHEMA)
    assert "Replay as of 2026-01-01: OSV archived, archive day 2025-12-31" in to_markdown(r)
    r["data"]["replay"] = {"as_of": "2026-01-01"}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(r, SCHEMA)

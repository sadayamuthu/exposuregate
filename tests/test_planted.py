"""Planted-exposure set (spec 11): every case in fixtures/planted/cases.json against frozen data.

The data under fixtures/planted/data is frozen by scripts/freeze_fixtures.py from the snapshot
archive (OEBC built 2026-06-14, OSV exported 2026-11-13), so results never drift with upstream.
"""

import json
import urllib.request
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from exposuregate.__main__ import main

ROOT = Path(__file__).resolve().parent.parent
PLANTED = Path(__file__).resolve().parent / "fixtures" / "planted"
SPEC = json.loads((PLANTED / "cases.json").read_text())
SCHEMA = json.loads((ROOT / "schemas" / "report.schema.json").read_text())
DATA = [
    "--oebc", str(PLANTED / "data" / "oebc.json"),
    "--osv-dir", str(PLANTED / "data" / "osv"),
    *SPEC["scan_args"],
]


def scan(case: dict[str, Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> tuple[
    int, dict[str, Any]
]:
    argv = [
        "scan", "--old", str(PLANTED / case["old"]), "--new", str(PLANTED / case["new"]),
        "--lockfile-type", case["lockfile_type"], "--path", str(tmp_path), "--format", "json",
        *DATA,
    ]
    if case.get("manifest"):
        argv += ["--manifest", str(PLANTED / case["manifest"])]
    code = main(argv)
    report: dict[str, Any] = json.loads(capsys.readouterr().out)
    jsonschema.validate(report, SCHEMA)
    return code, report


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise AssertionError("scan must not use the network")

    monkeypatch.setattr(urllib.request, "urlopen", boom)


def test_scan_args_pin_the_archive_day() -> None:
    assert SPEC["scan_args"] == ["--as-of", "2026-11-13", "--max-age-days", "200"]
    provenance = json.loads((PLANTED / "data" / "provenance.json").read_text())
    assert provenance["scan_args"] == SPEC["scan_args"]
    assert provenance["oebc"]["generated_at_utc"].startswith(SPEC["data"]["oebc_generated"])


def test_every_lockfile_type_has_the_spec_cases() -> None:
    kinds = {(c["lockfile_type"], c["id"].split("-", 1)[1]) for c in SPEC["cases"]}
    for ltype in ("uv", "poetry", "requirements", "npm"):
        for kind in ("direct-kev", "transitive-kev", "high", "low", "benign"):
            assert (ltype, kind) in kinds


@pytest.mark.parametrize("case", SPEC["cases"], ids=[c["id"] for c in SPEC["cases"]])
def test_planted_case(
    case: dict[str, Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, report = scan(case, tmp_path, capsys)

    assert report["denials"] == []
    assert report["verdict"] == case["expected_verdict"]
    assert code == case["expected_exit_code"]
    got = {
        (f["package"], f["version"], f["cve_id"]): f for f in report["findings"]
    }
    for exp in case["expected_findings"]:
        key = (exp["package"], exp["version"], exp["cve_id"])
        assert key in got, f"missing finding {key}"
        f = got[key]
        actual = {k: f[k] for k in ("dependency", "reason", "exposure_tier", "action")}
        assert actual == {k: exp[k] for k in actual}, key
    if case["exact_findings"]:
        assert len(report["findings"]) == len(case["expected_findings"])
    if "transitive" in case["tags"]:
        assert any(f["dependency"] == "transitive" for f in report["findings"])


def test_staleness_cases_would_block_with_current_kev() -> None:
    """The stale_oebc cases document KEV listings newer than the frozen 2026-06-14 OEBC."""
    oebc = json.loads((PLANTED / "data" / "oebc.json").read_text())
    rows = {v["cve_id"]: v for v in oebc["vulnerabilities"]}
    assert rows["CVE-2026-48710"]["exposure_tier"] == "LOW"  # KEV-listed 2026-09-02
    assert not rows["CVE-2026-48710"]["kev_listed"]
    assert "CVE-2026-111497" not in rows  # KEV-listed 2026-10-27

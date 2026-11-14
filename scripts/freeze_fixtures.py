"""Freeze the OSV + OEBC subset used by the planted-exposure set (spec 11).

    python scripts/freeze_fixtures.py --archive ~/data/exposuregate-archive --day 2026-11-13 \
        --out tests/fixtures/planted/data

Reads the snapshot archive (layout of paper/eval/archive/archive.py, via exposuregate.archive),
keeps every OSV record that affects a package named in any planted case lockfile (both sides),
and the archived OEBC records for those records' CVE aliases. Writes:

  <out>/osv/<ecosystem>.zip         the OSV records, unchanged (one <id>.json per record;
                                    zipped, deterministically, to keep the fixture small)
  <out>/oebc.json                   OEBC catalog subset (catalog fields kept, count adjusted)
  <out>/provenance.json             archive day, source sha256s, counts, the scan arguments

Then checks every expected finding in cases.json against the frozen OEBC (tier, or absent for
``not_in_oebc``), so a refreeze that changes a planted case's grading fails loudly.
"""

from __future__ import annotations

import argparse
import gzip
import json
import shutil
import sys
import zipfile
from datetime import date
from pathlib import Path
from typing import Any

from exposuregate.archive import _osv_state, _pick_day
from exposuregate.lockfiles import ECOSYSTEM, parse
from exposuregate.osv import cve_ids
from exposuregate.store import parse_ts
from exposuregate.versions import normalize_name

# Ruling F: frozen OEBC is the 2026-06-14 build, OSV the archive day; pin "now" and widen the
# age limit so verdicts reflect grading, not staleness.
SCAN_ARGS = ["--as-of", "2026-11-13", "--max-age-days", "200"]


def case_packages(planted: Path, cases: list[dict[str, Any]]) -> set[tuple[str, str]]:
    """(ecosystem, normalized name) of every pin on either side of every case."""
    names: set[tuple[str, str]] = set()
    for case in cases:
        ltype = case["lockfile_type"]
        manifest = (planted / case["manifest"]).read_text() if case.get("manifest") else None
        for side in ("old", "new"):
            for pin in parse(ltype, (planted / case[side]).read_text(), manifest).pins:
                names.add((ECOSYSTEM[ltype], normalize_name(pin.ecosystem, pin.name)))
    return names


def _affects(rec: dict[str, Any], eco: str, wanted: set[str]) -> bool:
    for a in rec.get("affected", []):
        pkg = a.get("package", {}) if isinstance(a, dict) else {}
        if pkg.get("ecosystem") == eco and normalize_name(eco, pkg.get("name", "")) in wanted:
            return True
    return False


def _write_zip(path: Path, members: dict[str, str]) -> None:
    """A byte-for-byte reproducible zip (fixed timestamps, sorted members)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, members[name])


def freeze(archive: Path, day: date, out: Path, planted: Path) -> dict[str, Any]:
    cases = json.loads((planted / "cases.json").read_text())["cases"]
    packages = case_packages(planted, cases)
    ecosystems = sorted({eco for eco, _ in packages})
    day_s, man = _pick_day(archive, day, ecosystems)
    if day_s != day.isoformat():
        raise SystemExit(f"archive has no usable snapshot for {day} (latest usable: {day_s})")

    if out.exists():
        shutil.rmtree(out)
    cves: set[str] = set()
    counts: dict[str, int] = {}
    for eco in ecosystems:
        wanted = {n for e, n in packages if e == eco}
        records: dict[str, str] = {}
        for rec in _osv_state(archive, eco, day_s, man["sources"][f"osv-{eco}"]):
            if not _affects(rec, eco, wanted):
                continue
            if rec.get("modified") and parse_ts(str(rec["modified"])).date() > day:
                raise SystemExit(f"{rec['id']} modified after {day}: {rec['modified']}")
            records[f"{rec['id']}.json"] = json.dumps(rec, sort_keys=True) + "\n"
            cves.update(cve_ids(rec))
        _write_zip(out / "osv" / f"{eco}.zip", records)
        counts[eco] = len(records)

    oebc_src = man["sources"]["oebc"]
    catalog = json.loads(gzip.decompress((archive / oebc_src["blob"]).read_bytes()))
    vulns = sorted(
        (v for v in catalog["vulnerabilities"] if v.get("cve_id") in cves),
        key=lambda v: v["cve_id"],
    )
    subset = {k: v for k, v in catalog.items() if k != "vulnerabilities"}
    subset.update(count=len(vulns), vulnerabilities=vulns)
    (out / "oebc.json").write_text(json.dumps(subset, indent=1, sort_keys=True) + "\n")

    provenance = {
        "archive_day": day_s,
        "oebc": {"generated_at_utc": catalog["generated_at_utc"], "sha256": oebc_src["sha256"],
                 "records": len(vulns)},
        "osv": {eco: {"sha256": man["sources"][f"osv-{eco}"]["sha256"],
                      "as_of": man["sources"][f"osv-{eco}"].get("as_of"), "records": counts[eco]}
                for eco in ecosystems},
        "packages": sorted(f"{e}:{n}" for e, n in packages),
        "scan_args": SCAN_ARGS,
    }
    (out / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    return {v["cve_id"]: v for v in vulns}


def verify(oebc: dict[str, dict[str, Any]], planted: Path) -> list[str]:
    """Mismatches between cases.json expected tiers and the frozen OEBC."""
    errors = []
    for case in json.loads((planted / "cases.json").read_text())["cases"]:
        for f in case["expected_findings"]:
            row = oebc.get(f["cve_id"])
            tier = row["exposure_tier"] if row else None
            expected_reason = "graded" if tier else "not_in_oebc"
            if tier != f["exposure_tier"] or f["reason"] != expected_reason:
                errors.append(f"{case['id']}: {f['package']} {f['cve_id']} expected"
                              f" {f['reason']}/{f['exposure_tier']}, frozen OEBC has {tier}")
            kev = f" KEV {row['kev_date_added']}" if row and row.get("kev_listed") else ""
            print(f"{case['id']:32} {f['package']:12} {f['cve_id']:18} {tier}{kev}",
                  file=sys.stderr)
    return errors


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--archive", type=Path, required=True)
    ap.add_argument("--day", type=date.fromisoformat, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    out = a.out.expanduser().resolve()
    oebc = freeze(a.archive.expanduser(), a.day, out, out.parent)
    errors = verify(oebc, out.parent)
    for e in errors:
        print(f"MISMATCH {e}", file=sys.stderr)
    size = sum(p.stat().st_size for p in out.rglob("*") if p.is_file())
    print(f"frozen {len(oebc)} OEBC records, {size / 1e6:.2f} MB in {out}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

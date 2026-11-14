"""Regenerates tests/fixtures/oebc/mini.json.gz and tests/fixtures/osv/{PyPI,npm}.zip."""
# ruff: noqa: E501

import gzip
import json
import zipfile
from pathlib import Path

HERE = Path(__file__).parent


def osv(id_, eco, name, pub, mod, cve=None, fixed="9.9"):
    rec = {
        "schema_version": "1.7.5",
        "id": id_,
        "modified": mod,
        "aliases": [cve] if cve else [],
        "affected": [
            {
                "package": {"name": name, "ecosystem": eco},
                "ranges": [
                    {
                        "type": "ECOSYSTEM" if eco == "PyPI" else "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": fixed}],
                    }
                ],
            }
        ],
    }
    if pub:
        rec["published"] = pub
    return rec


PYPI = [
    osv("PYSEC-1", "PyPI", "Django", "2020-01-05T00:00:00Z", "2026-11-01T10:00:00.123456789Z", "CVE-2020-0001"),
    osv("PYSEC-2", "PyPI", "PyYAML", "2024-03-01T12:00:00Z", "2026-11-13T18:15:07.541730589Z", "CVE-2024-0002"),
    osv("GHSA-3", "PyPI", "zope.interface", None, "2026-10-01T00:00:00Z", None),
    osv("PYSEC-4", "PyPI", "requests", "2026-06-01T00:00:00Z", "2026-11-02T00:00:00Z", "CVE-2026-0004"),
]
NPM = [
    osv("GHSA-5", "npm", "lodash", "2021-02-02T00:00:00Z", "2026-11-12T09:00:00.5Z", "CVE-2021-0005"),
    osv("GHSA-6", "npm", "left-pad", "2025-05-05T00:00:00Z", "2026-11-10T00:00:00Z", "CVE-2025-0006"),
]
TIERS = ["CRITICAL", "HIGH", "HIGH", "MEDIUM", "MEDIUM", "LOW", "LOW", "LOW", "HIGH", "CRITICAL"]
VULNS = [
    {
        "cve_id": f"CVE-2020-{i:04d}" if i == 1 else f"CVE-20{20 + (i > 1) * 4}-{i:04d}",
        "exposure_tier": t,
        "kev_listed": t == "CRITICAL",
        "kev_date_added": "2022-03-01" if t == "CRITICAL" else None,
        "epss_score": round(0.9 / i, 5),
        "cvss_score": None if i % 3 == 0 else 5.0 + i / 3,
        "description": "ignored",
    }
    for i, t in enumerate(TIERS, 1)
]

if __name__ == "__main__":
    cat = {
        "project": "OEBC",
        "project_version": "0.1.0",
        "generated_at_utc": "2026-11-10T10:00:00Z",
        "rules": {"actionable_min_tier": "medium"},
        "count": len(VULNS),
        "vulnerabilities": VULNS,
    }
    (HERE / "oebc").mkdir(exist_ok=True)
    with gzip.GzipFile(HERE / "oebc" / "mini.json.gz", "wb", mtime=0) as f:
        f.write(json.dumps(cat, indent=1).encode())
    for eco, recs in (("PyPI", PYPI), ("npm", NPM)):
        with zipfile.ZipFile(HERE / "osv" / f"{eco}.zip", "w") as z:
            for r in recs:
                z.writestr(zipfile.ZipInfo(f"{r['id']}.json", (2026, 11, 13, 0, 0, 0)), json.dumps(r))

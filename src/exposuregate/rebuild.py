"""rebuild-oebc: an OEBC-shaped catalog as of a past date (spec 6.4).

KEV entries added on or before the date, the EPSS daily scores for the date (or the nearest
earlier file), and CVSS from the current OEBC catalog, combined with OEBC's tier rule
(``oebc/src/oebc/generate.py`` ``compute_exposure_tier``).
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import os
import re
from datetime import date
from pathlib import Path
from typing import Any

from exposuregate import __version__
from exposuregate.store import DataInvalid, DataMissing, load_oebc

EPSS_HIGH = 0.10
EPSS_MEDIUM = 0.01
_EPSS_NAME = re.compile(r"^epss_scores-(\d{4}-\d{2}-\d{2})\.csv\.gz$")


def tier(
    kev_listed: bool,
    epss: float | None,
    cvss: float | None,
    high: float = EPSS_HIGH,
    medium: float = EPSS_MEDIUM,
) -> str:
    """OEBC's exposure tier; first match wins, a missing score never qualifies."""
    if kev_listed:
        return "CRITICAL"
    if (epss is not None and epss >= high) or (cvss is not None and cvss >= 9.0):
        return "HIGH"
    if (epss is not None and epss >= medium) or (cvss is not None and cvss >= 7.0):
        return "MEDIUM"
    return "LOW"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_kev(path: Path, as_of: date) -> tuple[str | None, dict[str, str]]:
    """(catalog release date, {cve: dateAdded}) for entries added on or before ``as_of``."""
    if not path.is_file():
        raise DataMissing(f"KEV catalog not found: {path}")
    try:
        cat = json.loads(path.read_bytes())
        added: dict[str, str] = {}
        for v in cat["vulnerabilities"]:
            day = str(v["dateAdded"])[:10]
            if date.fromisoformat(day) <= as_of:
                added[str(v["cveID"])] = day
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise DataInvalid(f"invalid KEV catalog {path}: {e!r}") from e
    released = cat.get("dateReleased")
    return (str(released)[:10] if released else None), added


def _pick_epss(epss_dir: Path, as_of: date) -> tuple[date, Path]:
    files: list[tuple[date, Path]] = []
    if epss_dir.is_dir():
        for p in epss_dir.iterdir():
            m = _EPSS_NAME.match(p.name)
            if m:
                try:
                    files.append((date.fromisoformat(m.group(1)), p))
                except ValueError:
                    continue
    usable = [f for f in files if f[0] <= as_of]
    if not usable:
        raise DataMissing(f"no EPSS score file dated on or before {as_of} in {epss_dir}")
    return max(usable)


def _load_epss(path: Path) -> dict[str, float]:
    try:
        text = gzip.decompress(path.read_bytes()).decode("utf-8")
        lines = (ln for ln in text.splitlines() if ln and not ln.startswith("#"))
        rows = csv.DictReader(lines)
        return {r["cve"]: float(r["epss"]) for r in rows}
    except (OSError, EOFError, ValueError, KeyError, TypeError, UnicodeDecodeError) as e:
        raise DataInvalid(f"invalid EPSS file {path}: {e!r}") from e


def _write(cat: dict[str, Any], out: Path) -> None:
    data = json.dumps(cat, indent=1).encode("utf-8")
    if out.name.endswith(".gz"):
        data = gzip.compress(data, mtime=0)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, out)


def rebuild_oebc(
    as_of: date,
    kev: Path,
    epss_dir: Path,
    oebc: Path,
    out: Path,
    high: float = EPSS_HIGH,
    medium: float = EPSS_MEDIUM,
) -> dict[str, Any]:
    """Write and return an OEBC-shaped catalog as of ``as_of``; raises DataMissing/DataInvalid."""
    if not oebc.is_file():
        raise DataMissing(f"OEBC catalog not found: {oebc}")
    kev_released, kev_added = _load_kev(kev, as_of)
    epss_date, epss_path = _pick_epss(epss_dir, as_of)
    epss = _load_epss(epss_path)
    oebc_meta, oebc_rows = load_oebc(oebc)
    vulns = []
    for cve in sorted(set(oebc_rows) | set(epss)):
        row = oebc_rows.get(cve)
        cvss = row["cvss_score"] if row else None
        score = epss.get(cve)
        listed = cve in kev_added
        vulns.append({
            "cve_id": cve,
            "exposure_tier": tier(listed, score, cvss, high, medium),
            "kev_listed": listed,
            "kev_date_added": kev_added.get(cve),
            "epss_score": score,
            "cvss_score": cvss,
        })
    cat: dict[str, Any] = {
        "project": "Open Exposure Baseline Catalog (OEBC), rebuilt by exposuregate",
        "project_version": f"exposuregate-rebuild/{__version__}",
        "generated_at_utc": f"{as_of.isoformat()}T00:00:00Z",
        "rules": {
            "exposure_tier_definition": {
                "critical": "kev_listed = true",
                "high": f"epss_score >= {high} OR cvss_score >= 9.0",
                "medium": f"epss_score >= {medium} OR cvss_score >= 7.0",
                "low": "everything else",
            },
            "tier_order": "LOW < MEDIUM < HIGH < CRITICAL",
            "epss_high_threshold": high,
            "epss_medium_threshold": medium,
            "kev": f"entries with dateAdded <= {as_of.isoformat()}",
            "epss": f"daily scores of {epss_date.isoformat()} (nearest on or before as-of)",
            "cvss": "from the current OEBC catalog (CVSS as of its generation date)",
        },
        "count": len(vulns),
        "vulnerabilities": vulns,
        "rebuilt_from": [
            {"role": "kev", "path": str(kev), "date": kev_released, "sha256": _sha256(kev)},
            {"role": "epss", "path": str(epss_path), "date": epss_date.isoformat(),
             "sha256": _sha256(epss_path)},
            {"role": "cvss", "path": str(oebc), "date": oebc_meta.date.date().isoformat(),
             "sha256": _sha256(oebc)},
        ],
    }
    _write(cat, out)
    return cat

"""Snapshot archive reader (spec 6.5) and replay scans (spec 6.4)."""

import gzip
import hashlib
import json
from datetime import date
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from exposuregate.__main__ import main
from exposuregate.archive import ArchiveStore
from exposuregate.rebuild import rebuild_oebc
from exposuregate.store import DataInvalid, DataMissing

ROOT = Path(__file__).resolve().parent.parent
FIX = Path(__file__).resolve().parent / "fixtures"
SCHEMA = json.loads((ROOT / "schemas" / "report.schema.json").read_text())
OSV = FIX / "osv"


def osv(id_: str, name: str, modified: str, fixed: str, cve: str,
        published: str = "2024-01-01T00:00:00Z") -> dict[str, Any]:
    return {
        "id": id_, "modified": modified, "published": published, "aliases": [cve],
        "affected": [{
            "package": {"name": name, "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": fixed}]}],
        }],
    }


def oebc_catalog(generated: str, tier: str) -> dict[str, Any]:
    return {
        "project_version": "0.1.0", "generated_at_utc": generated, "rules": {}, "count": 1,
        "vulnerabilities": [{"cve_id": "CVE-2024-0010", "exposure_tier": tier,
                             "kev_listed": tier == "CRITICAL", "kev_date_added": None,
                             "epss_score": 0.5, "cvss_score": 8.0}],
    }


class ArchiveBuilder:
    """Writes days in the layout of paper/eval/archive/archive.py."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.seen: set[tuple[str, str]] = set()

    def _blob(self, source: str, ext: str, data: bytes) -> dict[str, Any]:
        digest = hashlib.sha256(data).hexdigest()
        rel = Path("blobs") / source / f"{digest}.{ext}"
        (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
        (self.root / rel).write_bytes(data)
        return {"url": f"https://example.invalid/{source}", "fetched_utc": "x",
                "sha256": digest, "bytes": len(data), "blob": str(rel)}

    def day(self, day: str, *, oebc: dict[str, Any] | None,
            pypi: list[dict[str, Any]] | None, errors: dict[str, str] | None = None) -> None:
        sources: dict[str, Any] = {}
        sources["kev"] = self._blob("kev", "json", b'{"vulnerabilities": []}')
        if oebc is not None:
            entry = self._blob("oebc", "json.gz", gzip.compress(json.dumps(oebc).encode()))
            entry["generated_at_utc"] = oebc["generated_at_utc"]
            sources["oebc"] = entry
        if pypi is not None:
            eco_dir = self.root / "osv" / "PyPI"
            eco_dir.mkdir(parents=True, exist_ok=True)
            idx = [{"id": r["id"], "modified": r["modified"]} for r in pypi]
            new = [r for r in pypi if (r["id"], r["modified"]) not in self.seen]
            self.seen |= {(r["id"], r["modified"]) for r in pypi}
            for kind, rows in (("index", idx), ("delta", new)):
                with gzip.open(eco_dir / f"{kind}-{day}.jsonl.gz", "wt") as g:
                    g.writelines(json.dumps(r) + "\n" for r in rows)
            sources["osv-PyPI"] = {"records": len(pypi), "new_or_modified": len(new),
                                   "index": f"osv/PyPI/index-{day}.jsonl.gz",
                                   "delta": f"osv/PyPI/delta-{day}.jsonl.gz"}
        manifest = {"date": day, "sources": sources, "errors": errors or {}}
        (self.root / "days").mkdir(parents=True, exist_ok=True)
        (self.root / "days" / f"{day}.json").write_text(json.dumps(manifest, indent=1))


DJANGO = osv("PYSEC-1", "Django", "2026-11-01T00:00:00Z", "3.0", "CVE-2020-0001")
LITELLM_OLD = osv("PYSEC-5", "litellm", "2026-11-05T00:00:00Z", "1.40.0", "CVE-2024-0010")
LITELLM_NEW = osv("PYSEC-5", "litellm", "2026-11-11T08:00:00Z", "1.20.0", "CVE-2024-0010")


@pytest.fixture
def archive(tmp_path: Path) -> Path:
    root = tmp_path / "archive"
    b = ArchiveBuilder(root)
    b.day("2026-11-10", oebc=oebc_catalog("2026-11-09T10:00:00Z", "HIGH"),
          pypi=[DJANGO, LITELLM_OLD])
    # day 2: PYSEC-5 modified (fix moved to 1.20.0), PYSEC-1 unchanged
    b.day("2026-11-11", oebc=oebc_catalog("2026-11-11T10:00:00Z", "CRITICAL"),
          pypi=[DJANGO, LITELLM_NEW])
    # day 3: OSV PyPI failed; OEBC fine
    b.day("2026-11-12", oebc=oebc_catalog("2026-11-12T10:00:00Z", "LOW"), pypi=None,
          errors={"osv-PyPI": "URLError: timed out"})
    return root


def ranges(store, name: str) -> list[str]:
    return [e["fixed"] for a in store.advisories("PyPI", name) for aff in a["affected"]
            for r in aff["ranges"] for e in r["events"] if "fixed" in e]


def test_archive_reconstructs_modified_record_as_of_each_day(archive):
    day1 = ArchiveStore.open(archive, date(2026, 11, 10), {"PyPI"})
    day2 = ArchiveStore.open(archive, date(2026, 11, 11), {"PyPI"})
    assert ranges(day1, "litellm") == ["1.40.0"]
    assert ranges(day2, "litellm") == ["1.20.0"]
    assert ranges(day1, "django") == ranges(day2, "django") == ["3.0"]
    assert day1.meta.osv["PyPI"].count == 2
    assert day1.meta.osv["PyPI"].date.isoformat() == "2026-11-05T00:00:00+00:00"
    assert day2.meta.osv["PyPI"].date.isoformat() == "2026-11-11T08:00:00+00:00"
    assert day1.meta.replay == {"osv_mode": "archived", "archive_day": "2026-11-10"}
    assert day1.oebc("CVE-2024-0010")["exposure_tier"] == "HIGH"
    assert day2.oebc("CVE-2024-0010")["exposure_tier"] == "CRITICAL"


def test_archive_uses_latest_day_not_after_as_of(archive):
    s = ArchiveStore.open(archive, date(2026, 11, 30))  # no OSV needed: OEBC-only day is fine
    assert s.meta.replay == {"osv_mode": "archived", "archive_day": "2026-11-12"}
    assert s.meta.osv == {}
    assert s.meta.oebc is not None and s.meta.oebc.date.date() == date(2026, 11, 12)
    assert str(archive) in s.meta.oebc.extra["source"]
    assert "2026-11-12" in s.meta.oebc.extra["source"]
    with pytest.raises(DataMissing):
        ArchiveStore.open(archive, date(2026, 11, 9), {"PyPI"})
    with pytest.raises(DataMissing):
        ArchiveStore.open(archive.parent / "nowhere", date(2026, 11, 30), {"PyPI"})


def test_archive_skips_day_with_error_for_source(archive):
    s = ArchiveStore.open(archive, date(2026, 11, 12), {"PyPI"})
    assert s.meta.replay == {"osv_mode": "archived", "archive_day": "2026-11-11"}
    assert ranges(s, "litellm") == ["1.20.0"]
    assert "2026-11-11" in s.meta.osv["PyPI"].extra["source"]


def test_archive_missing_record_or_bad_blob_is_invalid(archive):
    (archive / "osv" / "PyPI" / "delta-2026-11-11.jsonl.gz").unlink()
    with pytest.raises(DataInvalid, match="PYSEC-5"):
        ArchiveStore.open(archive, date(2026, 11, 11), {"PyPI"})
    day1 = json.loads((archive / "days" / "2026-11-10.json").read_text())
    (archive / day1["sources"]["oebc"]["blob"]).write_bytes(b"tampered")
    with pytest.raises(DataInvalid):
        ArchiveStore.open(archive, date(2026, 11, 10), {"PyPI"})


# ---- replay scans ------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_network(tmp_path, monkeypatch):
    monkeypatch.setenv("EXPOSUREGATE_DATA_DIR", str(tmp_path / "no-data-here"))

    def boom(*_a, **_k):
        raise AssertionError("network access in scan")

    monkeypatch.setattr("urllib.request.urlopen", boom)


def scan(capsys, tmp_path: Path, *args: str) -> tuple[int, dict[str, Any]]:
    new = tmp_path / "requirements.txt"
    new.write_text("litellm==1.30.0\n")
    code = main(["scan", "--new", str(new), "--lockfile-type", "requirements",
                 "--format", "json", *args])
    report = json.loads(capsys.readouterr().out)
    jsonschema.validate(report, SCHEMA)
    return code, report


def test_replay_report_flags_osv_mode(tmp_path, archive, capsys):
    _, r = scan(capsys, tmp_path, "--archive", str(archive), "--as-of", "2026-11-10",
                "--max-age-days", "30")
    assert r["data"]["replay"] == {"replay": True, "osv_mode": "archived",
                                   "as_of": "2026-11-10", "archive_day": "2026-11-10"}
    assert r["findings"][0]["exposure_tier"] == "HIGH"  # day-1 OEBC, day-1 ranges
    assert r["findings"][0]["fixed_in"] == ["1.40.0"]
    rebuilt = tmp_path / "rebuilt.json"
    rebuild_oebc(date(2026, 11, 11), FIX / "replay" / "kev.json", FIX / "replay" / "epss",
                 FIX / "oebc" / "mini.json.gz", rebuilt)
    _, r = scan(capsys, tmp_path, "--replay", "--as-of", "2026-11-11", "--oebc", str(rebuilt),
                "--osv-dir", str(OSV))
    assert r["data"]["replay"] == {"replay": True, "osv_mode": "current_filtered",
                                   "as_of": "2026-11-11"}
    assert "Replay" in _markdown(tmp_path, "--replay", "--as-of", "2026-11-11", "--oebc",
                                 str(rebuilt), "--osv-dir", str(OSV), capsys=capsys)
    _, plain = scan(capsys, tmp_path, "--as-of", "2026-11-11", "--oebc", str(rebuilt),
                    "--osv-dir", str(OSV))
    assert "replay" not in plain["data"]


def _markdown(tmp_path: Path, *args: str, capsys) -> str:
    new = tmp_path / "requirements.txt"
    main(["scan", "--new", str(new), "--lockfile-type", "requirements",
          "--format", "markdown", *args])
    return capsys.readouterr().out


def test_replay_does_not_deny_on_osv_future_dates(tmp_path, capsys):
    rebuilt = tmp_path / "rebuilt.json.gz"
    rebuild_oebc(date(2026, 11, 11), FIX / "replay" / "kev.json", FIX / "replay" / "epss",
                 FIX / "oebc" / "mini.json.gz", rebuilt)
    data = ["--as-of", "2026-11-11", "--oebc", str(rebuilt), "--osv-dir", str(OSV)]
    code, r = scan(capsys, tmp_path, *data)  # OSV modified 2026-11-13 > as-of
    assert "data_from_future" in [d["code"] for d in r["denials"]] and code == 2
    code, r = scan(capsys, tmp_path, "--replay", *data)
    assert r["denials"] == []
    (f,) = r["findings"]
    assert f["cve_id"] == "CVE-2024-0010" and f["kev_listed"] is False  # KEV added 11-12
    assert f["exposure_tier"] == "MEDIUM"
    assert code in (0, 1) and r["verdict"] != "DENY"


def test_archive_requires_as_of_and_is_not_filtered_by_published(tmp_path, archive, capsys):
    assert main(["scan", "--archive", str(archive)]) == 2
    assert "--as-of" in capsys.readouterr().err
    # published after the archive day is irrelevant: archived state is as of that day
    b = ArchiveBuilder(tmp_path / "a2")
    late = osv("PYSEC-7", "litellm", "2026-11-10T00:00:00Z", "1.40.0", "CVE-2024-0010",
               published="2026-11-20T00:00:00Z")
    b.day("2026-11-10", oebc=oebc_catalog("2026-11-09T10:00:00Z", "HIGH"), pypi=[late])
    _, r = scan(capsys, tmp_path, "--archive", str(tmp_path / "a2"), "--as-of", "2026-11-10")
    assert [f["advisory_ids"] for f in r["findings"]] == [["PYSEC-7"]]

"""rebuild-oebc: OEBC rebuilt as of a past date from KEV, EPSS and current CVSS (spec 6.4)."""

import gzip
import hashlib
import json
from datetime import date
from pathlib import Path

import pytest

from exposuregate.__main__ import main
from exposuregate.rebuild import rebuild_oebc, tier
from exposuregate.store import DataMissing, MemoryStore

FIX = Path(__file__).resolve().parent / "fixtures"
REPLAY = FIX / "replay"
KEV = REPLAY / "kev.json"
EPSS = REPLAY / "epss"
OEBC = FIX / "oebc" / "mini.json.gz"


def rebuild(tmp_path: Path, as_of: str, name: str = "rebuilt.json") -> dict:
    return rebuild_oebc(date.fromisoformat(as_of), KEV, EPSS, OEBC, tmp_path / name)


def by_cve(cat: dict) -> dict[str, dict]:
    return {v["cve_id"]: v for v in cat["vulnerabilities"]}


@pytest.mark.parametrize(
    ("kev", "epss", "cvss", "expected"),
    [
        (True, None, None, "CRITICAL"),
        (False, 0.10, None, "HIGH"),
        (False, 0.0999, 9.0, "HIGH"),
        (False, 0.0999, 8.99, "MEDIUM"),
        (False, 0.01, None, "MEDIUM"),
        (False, None, 7.0, "MEDIUM"),
        (False, 0.0099, 6.99, "LOW"),
        (False, None, None, "LOW"),
    ],
)
def test_tier_matches_oebc_rule(kev, epss, cvss, expected):
    assert tier(kev, epss, cvss) == expected


def test_tier_thresholds_are_parameters():
    assert tier(False, 0.05, None, high=0.05) == "HIGH"
    assert tier(False, 0.005, None, medium=0.005) == "MEDIUM"


def test_rebuild_excludes_kev_added_after_as_of(tmp_path):
    before = by_cve(rebuild(tmp_path, "2026-11-11"))["CVE-2024-0010"]
    assert before["kev_listed"] is False and before["kev_date_added"] is None
    assert before["exposure_tier"] == "MEDIUM"  # epss 0.07, cvss 8.33
    on = by_cve(rebuild(tmp_path, "2026-11-12"))["CVE-2024-0010"]
    assert on["kev_listed"] is True and on["kev_date_added"] == "2026-11-12"
    assert on["exposure_tier"] == "CRITICAL"


def test_rebuild_uses_nearest_earlier_epss_and_records_it(tmp_path):
    cat = rebuild(tmp_path, "2026-11-07")
    v = by_cve(cat)
    assert v["CVE-2024-0002"]["epss_score"] == 0.2  # from the 2026-11-01 file
    assert v["CVE-2024-0002"]["exposure_tier"] == "HIGH"
    (epss,) = [r for r in cat["rebuilt_from"] if r["role"] == "epss"]
    path = EPSS / "epss_scores-2026-11-01.csv.gz"
    assert epss == {"role": "epss", "path": str(path), "date": "2026-11-01",
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    assert {r["role"] for r in cat["rebuilt_from"]} == {"kev", "epss", "cvss"}
    for r in cat["rebuilt_from"]:
        assert r["sha256"] == hashlib.sha256(Path(r["path"]).read_bytes()).hexdigest()
    # on the day of a later file, that file wins
    later = rebuild(tmp_path, "2026-11-08")
    assert by_cve(later)["CVE-2024-0002"]["epss_score"] == 0.005


def test_rebuild_no_epss_before_date_errors(tmp_path):
    with pytest.raises(DataMissing, match="EPSS"):
        rebuild(tmp_path, "2026-10-31")
    assert not (tmp_path / "rebuilt.json").exists()


def test_rebuild_cve_universe_and_shape(tmp_path):
    cat = rebuild(tmp_path, "2026-11-08")
    v = by_cve(cat)
    assert "CVE-2099-0001" in v and v["CVE-2099-0001"]["cvss_score"] is None  # EPSS-only
    assert v["CVE-2024-0003"]["epss_score"] is None  # OEBC-only, not in EPSS
    assert v["CVE-2024-0003"]["exposure_tier"] == "LOW"
    assert v["CVE-2024-0008"]["cvss_score"] == pytest.approx(7.6667, abs=1e-3)
    assert cat["count"] == len(cat["vulnerabilities"]) == 11
    assert cat["generated_at_utc"] == "2026-11-08T00:00:00Z"
    assert cat["project_version"] == "exposuregate-rebuild/0.1.0"
    assert cat["rules"]["epss_high_threshold"] == 0.10
    assert cat["rules"]["epss_medium_threshold"] == 0.01
    assert set(v["CVE-2024-0002"]) == {"cve_id", "exposure_tier", "kev_listed",
                                       "kev_date_added", "epss_score", "cvss_score"}


def test_rebuild_output_loads_in_memory_store(tmp_path):
    rebuild(tmp_path, "2026-11-11", "plain.json")
    rebuild(tmp_path, "2026-11-11", "packed.json.gz")
    plain = json.loads((tmp_path / "plain.json").read_text())
    assert json.loads(gzip.decompress((tmp_path / "packed.json.gz").read_bytes())) == plain
    for name in ("plain.json", "packed.json.gz"):
        store = MemoryStore.from_files(tmp_path / name, [])
        assert store.meta.oebc is not None
        assert store.meta.oebc.date.isoformat() == "2026-11-11T00:00:00+00:00"
        assert store.oebc("CVE-2024-0010")["exposure_tier"] == "MEDIUM"


def test_cli_rebuild_oebc(tmp_path, capsys):
    out = tmp_path / "o" / "rebuilt.json.gz"
    argv = ["rebuild-oebc", "--as-of", "2026-11-12", "--kev", str(KEV), "--epss-dir", str(EPSS),
            "--oebc", str(OEBC), "--out", str(out)]
    assert main(argv) == 0
    cat = json.loads(gzip.decompress(out.read_bytes()))
    assert by_cve(cat)["CVE-2024-0010"]["exposure_tier"] == "CRITICAL"
    assert capsys.readouterr().out == ""
    argv[2] = "2026-10-01"
    assert main(argv) == 1
    assert "EPSS" in capsys.readouterr().err
    assert main(["rebuild-oebc", "--as-of", "2026-11-12"]) == 2

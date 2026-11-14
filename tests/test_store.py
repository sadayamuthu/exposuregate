from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from exposuregate.store import (
    DataInvalid,
    DataMissing,
    MemoryStore,
    SqliteStore,
    build_index,
)

FX = Path(__file__).parent / "fixtures"
OEBC = FX / "oebc" / "mini.json.gz"
PYPI = FX / "osv" / "PyPI.zip"
NPM = FX / "osv" / "npm.zip"

QUERIES = [
    ("PyPI", "django"),
    ("PyPI", "Django"),
    ("PyPI", "pyyaml"),
    ("PyPI", "zope-interface"),
    ("PyPI", "requests"),
    ("PyPI", "nope"),
    ("npm", "lodash"),
    ("npm", "left-pad"),
    ("npm", "Lodash"),
]


def mem(**kw):
    return MemoryStore.from_files(OEBC, [PYPI, NPM], **kw)


def ids(store, eco, name):
    return sorted(r["id"] for r in store.advisories(eco, name))


def test_memory_store_lookup_by_normalized_name():
    s = mem()
    assert ids(s, "PyPI", "DJANGO") == ["PYSEC-1"]
    assert ids(s, "PyPI", "PyYAML") == ["PYSEC-2"]
    assert ids(s, "PyPI", "zope.interface") == ["GHSA-3"]
    assert ids(s, "npm", "lodash") == ["GHSA-5"]
    assert ids(s, "npm", "Lodash") == []
    assert ids(s, "PyPI", "lodash") == []


def test_memory_store_published_before_filters():
    s = mem(published_before=date(2024, 3, 1))
    assert ids(s, "PyPI", "pyyaml") == ["PYSEC-2"]  # published on the date: kept
    assert ids(s, "PyPI", "requests") == []  # published 2026
    assert ids(s, "PyPI", "zope.interface") == ["GHSA-3"]  # no published: kept
    assert ids(s, "npm", "left-pad") == []
    assert ids(mem(published_before=date(2024, 2, 29)), "PyPI", "pyyaml") == []


def test_oebc_fields():
    s = mem()
    r = s.oebc("CVE-2020-0001")
    assert r is not None
    assert set(r) == {"exposure_tier", "kev_listed", "kev_date_added", "epss_score", "cvss_score"}
    assert r["exposure_tier"] == "CRITICAL" and r["kev_listed"] is True
    assert r["kev_date_added"] == "2022-03-01"
    assert s.oebc("CVE-2024-0003")["cvss_score"] is None
    assert s.oebc("CVE-1900-0000") is None


def test_meta_dates():
    m = mem().meta
    assert m.oebc is not None
    assert m.oebc.date == datetime(2026, 11, 10, 10, 0, tzinfo=timezone.utc)
    assert m.oebc.count == 10
    assert m.oebc.extra["project_version"] == "0.1.0"
    assert m.oebc.extra["rules"] == {"actionable_min_tier": "medium"}
    assert m.osv["PyPI"].date == datetime(2026, 11, 13, 18, 15, 7, 541730, tzinfo=timezone.utc)
    assert m.osv["PyPI"].count == 5
    assert m.osv["npm"].date == datetime(2026, 11, 12, 9, 0, 0, 500000, tzinfo=timezone.utc)


def test_directory_source(tmp_path):
    import zipfile

    with zipfile.ZipFile(PYPI) as z:
        z.extractall(tmp_path)
    s = MemoryStore.from_files(None, [tmp_path])
    assert ids(s, "PyPI", "django") == ["PYSEC-1"]
    assert s.meta.oebc is None


def test_sqlite_roundtrip_equals_memory(tmp_path):
    out = tmp_path / "index.sqlite"
    meta = build_index(OEBC, {"PyPI": PYPI, "npm": NPM}, out)
    m, sq = mem(), SqliteStore(out)
    assert meta == m.meta == sq.meta
    for eco, name in QUERIES:
        assert sorted(sq.advisories(eco, name), key=lambda r: r["id"]) == sorted(
            m.advisories(eco, name), key=lambda r: r["id"]
        )
    for i in range(1, 11):
        for cve in (f"CVE-2020-{i:04d}", f"CVE-2024-{i:04d}"):
            assert sq.oebc(cve) == m.oebc(cve)
    assert sq.oebc("CVE-1900-0000") is None


def test_sqlite_published_before(tmp_path):
    out = tmp_path / "index.sqlite"
    build_index(OEBC, {"PyPI": PYPI, "npm": NPM}, out)
    sq = SqliteStore(out, published_before=date(2024, 3, 1))
    assert ids(sq, "PyPI", "requests") == []
    assert ids(sq, "PyPI", "pyyaml") == ["PYSEC-2"]
    assert ids(sq, "PyPI", "zope.interface") == ["GHSA-3"]


def test_sqlite_missing_raises_data_missing(tmp_path):
    with pytest.raises(DataMissing):
        SqliteStore(tmp_path / "nope.sqlite")


def test_sqlite_invalid_raises_data_invalid(tmp_path):
    import sqlite3

    p = tmp_path / "x.sqlite"
    sqlite3.connect(p).close()
    with pytest.raises(DataInvalid):
        SqliteStore(p)
    p.write_bytes(b"not a database at all")
    with pytest.raises(DataInvalid):
        SqliteStore(p)


def test_oebc_plain_json_and_count_mismatch(tmp_path):
    import gzip
    import json

    cat = json.loads(gzip.open(OEBC).read())
    p = tmp_path / "c.json"
    p.write_text(json.dumps(cat))
    assert MemoryStore.from_files(p, []).meta.oebc.count == 10
    cat["count"] = 11
    p.write_text(json.dumps(cat))
    with pytest.raises(DataInvalid):
        MemoryStore.from_files(p, [])


def test_oebc_unknown_tier_is_data_invalid(tmp_path):
    import gzip
    import json

    cat = json.loads(gzip.open(OEBC).read())
    cat["vulnerabilities"][0]["exposure_tier"] = "SEVERE"
    p = tmp_path / "c.json"
    p.write_text(json.dumps(cat))
    with pytest.raises(DataInvalid, match="SEVERE"):
        MemoryStore.from_files(p, [])

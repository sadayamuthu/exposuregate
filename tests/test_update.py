import json
from pathlib import Path

import pytest

from exposuregate.store import DataInvalid, SqliteStore
from exposuregate.update import data_info, update_data

FX = Path(__file__).parent / "fixtures"


def urls(**over):
    u = {
        "oebc": (FX / "oebc" / "mini.json.gz").resolve().as_uri(),
        "osv": {
            "PyPI": (FX / "osv" / "PyPI.zip").resolve().as_uri(),
            "npm": (FX / "osv" / "npm.zip").resolve().as_uri(),
        },
    }
    u.update(over)
    return u


def test_update_data_from_file_urls(tmp_path):
    u = urls()
    meta = update_data(tmp_path, ["PyPI", "npm"], urls=u)
    assert meta.oebc.count == 10 and meta.osv["npm"].count == 2
    man = json.loads((tmp_path / "manifest.json").read_text())
    assert man["oebc"]["url"] == u["oebc"]
    assert man["oebc"]["generated_at_utc"].startswith("2026-11-10T10:00:00")
    assert man["oebc"]["count"] == 10
    assert man["osv"]["PyPI"]["url"] == u["osv"]["PyPI"]
    assert man["osv"]["PyPI"]["count"] == 4
    assert man["osv"]["PyPI"]["as_of"].startswith("2026-11-13T18:15:07")
    assert "downloaded_at" in man
    s = SqliteStore(tmp_path / "index.sqlite")
    assert [r["id"] for r in s.advisories("PyPI", "django")] == ["PYSEC-1"]
    assert not list(tmp_path.glob("*.tmp")) and not (tmp_path / "downloads").exists()


def test_update_data_failure_keeps_previous_index(tmp_path):
    update_data(tmp_path, ["PyPI"], urls=urls())
    before = (tmp_path / "index.sqlite").read_bytes()
    man = (tmp_path / "manifest.json").read_bytes()
    bad = tmp_path.parent / "bad.zip"
    bad.write_bytes(b"PK not a zip")
    with pytest.raises(DataInvalid):
        update_data(tmp_path, ["PyPI"], urls=urls(osv={"PyPI": bad.resolve().as_uri()}))
    assert (tmp_path / "index.sqlite").read_bytes() == before
    assert (tmp_path / "manifest.json").read_bytes() == man


def test_update_rejects_oebc_count_mismatch(tmp_path):
    import gzip

    cat = json.loads(gzip.open(FX / "oebc" / "mini.json.gz").read())
    cat["count"] = 99
    bad = tmp_path / "src" / "bad.json"
    bad.parent.mkdir()
    bad.write_text(json.dumps(cat))
    with pytest.raises(DataInvalid):
        update_data(tmp_path / "d", ["PyPI"], urls=urls(oebc=bad.resolve().as_uri()))
    assert not (tmp_path / "d" / "index.sqlite").exists()


def test_update_rejects_empty_ecosystem(tmp_path):
    import zipfile

    z = tmp_path / "empty.zip"
    zipfile.ZipFile(z, "w").close()
    with pytest.raises(DataInvalid):
        update_data(tmp_path / "d", ["PyPI"], urls=urls(osv={"PyPI": z.resolve().as_uri()}))


def test_update_rejects_unparseable_record(tmp_path):
    import zipfile

    z = tmp_path / "bad.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("a.json", "{not json")
    with pytest.raises(DataInvalid):
        update_data(tmp_path / "d", ["PyPI"], urls=urls(osv={"PyPI": z.resolve().as_uri()}))


def test_data_info_prints_dates(tmp_path):
    update_data(tmp_path, ["PyPI", "npm"], urls=urls())
    out = data_info(tmp_path)
    assert "2026-11-10" in out and "10" in out
    assert "PyPI" in out and "2026-11-13" in out
    assert "npm" in out and "2026-11-12" in out


def test_data_info_missing(tmp_path):
    from exposuregate.store import DataMissing

    with pytest.raises(DataMissing):
        data_info(tmp_path)

from dataclasses import replace
from datetime import date, datetime, timezone
from pathlib import Path

from exposuregate.config import Config as Cfg
from exposuregate.config import load_config
from exposuregate.freshness import check
from exposuregate.store import DataMeta, SourceMeta

NOW = date(2026, 11, 14)


def Config(**kw) -> Cfg:  # noqa: N802
    return replace(load_config(None, Path(".")), **kw)


def sm(source: str, d: str) -> SourceMeta:
    return SourceMeta(
        source=source,
        date=datetime.fromisoformat(d).replace(tzinfo=timezone.utc),
        count=1,
    )


def meta(oebc: str | None = "2026-11-14", **osv: str) -> DataMeta:
    return DataMeta(
        oebc=sm("oebc", oebc) if oebc else None,
        osv={k: sm("osv", v) for k, v in osv.items()},
    )


def codes(ds):
    return [d.code for d in ds]


def test_fresh_no_denials():
    m = meta(PyPI="2026-11-13")
    assert check(m, {"PyPI"}, NOW, Config(), False) == []


def test_oebc_stale_message_exact():
    m = meta(oebc="2026-06-14", PyPI="2026-11-14")
    ds = check(m, {"PyPI"}, NOW, Config(), False)
    assert [(d.code, d.detail) for d in ds] == [
        ("data_stale", "OEBC generated 2026-06-14 is 153 days old (max 7)")
    ]


def test_osv_stale_only_for_needed_ecosystem():
    m = meta(PyPI="2026-11-14", npm="2026-01-01")
    assert check(m, {"PyPI"}, NOW, Config(), False) == []
    ds = check(m, {"npm"}, NOW, Config(), False)
    assert codes(ds) == ["data_stale"]
    assert ds[0].detail == "OSV npm as of 2026-01-01 is 317 days old (max 7)"


def test_missing_store():
    ds = check(None, {"PyPI"}, NOW, Config(), False)
    assert codes(ds) == ["data_missing"]


def test_missing_oebc():
    ds = check(meta(oebc=None, PyPI="2026-11-14"), {"PyPI"}, NOW, Config(), False)
    assert codes(ds) == ["data_missing"]
    assert "OEBC" in ds[0].detail


def test_missing_needed_ecosystem():
    ds = check(meta(PyPI="2026-11-14"), {"PyPI", "npm"}, NOW, Config(), False)
    assert codes(ds) == ["data_missing"]
    assert "npm" in ds[0].detail


def test_no_needed_ecosystems():
    assert check(None, set(), NOW, Config(), False) == []
    assert check(meta(oebc="2020-01-01"), set(), NOW, Config(), False) == []


def test_per_source_override():
    m = meta(oebc="2026-11-01", PyPI="2026-11-01")
    cfg = Config(oebc_max_age_days=30)
    ds = check(m, {"PyPI"}, NOW, cfg, False)
    assert codes(ds) == ["data_stale"]
    assert ds[0].detail.startswith("OSV PyPI")


def test_future_non_replay():
    m = meta(oebc="2026-11-20", PyPI="2026-11-20")
    ds = check(m, {"PyPI"}, NOW, Config(), False)
    assert codes(ds) == ["data_from_future", "data_from_future"]
    assert "2026-11-20" in ds[0].detail


def test_replay_skips_osv_checks():
    m = meta(oebc="2026-11-14", PyPI="2030-01-01", npm="2020-01-01")
    assert check(m, {"PyPI", "npm"}, NOW, Config(), True) == []


def test_replay_still_rejects_future_oebc():
    m = meta(oebc="2026-11-20", PyPI="2026-11-14")
    assert codes(check(m, {"PyPI"}, NOW, Config(), True)) == ["data_from_future"]


def test_replay_oebc_stale_still_checked():
    m = meta(oebc="2026-06-14", PyPI="2026-11-14")
    assert codes(check(m, {"PyPI"}, NOW, Config(), True)) == ["data_stale"]


def test_boundary_exactly_max_age_is_fresh():
    m = meta(oebc="2026-11-07", PyPI="2026-11-07")
    assert check(m, {"PyPI"}, NOW, Config(), False) == []
    m = meta(oebc="2026-11-06", PyPI="2026-11-07")
    assert codes(check(m, {"PyPI"}, NOW, Config(), False)) == ["data_stale"]

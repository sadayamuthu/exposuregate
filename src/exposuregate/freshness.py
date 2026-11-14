"""Data freshness checks (spec 6.3, 6.4)."""

from __future__ import annotations

from datetime import date, datetime, timezone

from exposuregate.config import Config
from exposuregate.models import Denial
from exposuregate.store import DataMeta, SourceMeta


def _utc_date(dt: datetime) -> date:
    if dt.tzinfo is None:
        return dt.date()
    return dt.astimezone(timezone.utc).date()


def _check_source(
    label: str, name: str, src: SourceMeta, now: date, max_age: int, out: list[Denial]
) -> None:
    d = _utc_date(src.date)
    if d > now:
        out.append(
            Denial("data_from_future", f"{label} {name} {d} is after as-of date {now}")
        )
        return
    age = (now - d).days
    if age > max_age:
        out.append(
            Denial("data_stale", f"{label} {name} {d} is {age} days old (max {max_age})")
        )


def check(
    meta: DataMeta | None,
    needed_ecosystems: set[str],
    now: date,
    cfg: Config,
    replay: bool,
) -> list[Denial]:
    if not needed_ecosystems:
        return []
    if meta is None:
        return [Denial("data_missing", "no advisory data store found; run update-data")]
    out: list[Denial] = []
    if meta.oebc is None:
        out.append(Denial("data_missing", "OEBC catalog is missing from the data store"))
    else:
        _check_source("OEBC", "generated", meta.oebc, now, cfg.max_age("oebc"), out)
    for eco in sorted(needed_ecosystems):
        src = meta.osv.get(eco)
        if src is None:
            out.append(
                Denial("data_missing", f"OSV {eco} data is missing from the data store")
            )
        elif not replay:
            _check_source("OSV", f"{eco} as of", src, now, cfg.max_age("osv"), out)
    return out

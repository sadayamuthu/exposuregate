"""Advisory/OEBC data stores: in-memory and SQLite-backed (spec 6.1, 6.2)."""

from __future__ import annotations

import gzip
import json
import os
import re
import sqlite3
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from exposuregate.versions import normalize_name


class DataMissing(Exception):
    """The data store does not exist."""


class DataInvalid(Exception):
    """A data source or index is malformed."""


@dataclass
class SourceMeta:
    source: str
    date: datetime
    count: int
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class DataMeta:
    oebc: SourceMeta | None
    osv: dict[str, SourceMeta]
    replay: dict[str, Any] | None = None


class DataStore(Protocol):
    meta: DataMeta

    def advisories(self, ecosystem: str, name: str) -> list[dict[str, Any]]: ...

    def oebc(self, cve_id: str) -> dict[str, Any] | None: ...


_FRACTION = re.compile(r"\.(\d+)")
_OEBC_KEYS = ("exposure_tier", "kev_listed", "kev_date_added", "epss_score", "cvss_score")


def parse_ts(value: str) -> datetime:
    """Parse an OSV/OEBC timestamp (``Z``, nanosecond fractions) to an aware UTC datetime."""
    s = value.strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    s = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), s, count=1)
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _published_after(record: dict[str, Any], cutoff: date | None) -> bool:
    if cutoff is None or not record.get("published"):
        return False
    try:
        return parse_ts(str(record["published"])).date() > cutoff
    except ValueError:
        return False


# ---- loading ---------------------------------------------------------------


def _read_maybe_gzip(path: Path) -> bytes:
    try:
        raw = path.read_bytes()
        return gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw
    except (OSError, EOFError) as e:
        raise DataInvalid(f"cannot read {path}: {e}") from e


def load_oebc(path: Path) -> tuple[SourceMeta, dict[str, dict[str, Any]]]:
    try:
        cat = json.loads(_read_maybe_gzip(path))
        vulns = cat["vulnerabilities"]
        count = cat["count"]
        date_ = parse_ts(cat["generated_at_utc"])
    except (ValueError, KeyError, TypeError) as e:
        raise DataInvalid(f"invalid OEBC catalog {path}: {e!r}") from e
    if not isinstance(vulns, list) or len(vulns) != count:
        raise DataInvalid(f"OEBC {path}: count {count} != {len(vulns)} vulnerabilities")
    rows: dict[str, dict[str, Any]] = {}
    for v in vulns:
        if not isinstance(v, dict) or not isinstance(v.get("cve_id"), str):
            raise DataInvalid(f"OEBC {path}: record without cve_id")
        rows[v["cve_id"]] = {k: v.get(k) for k in _OEBC_KEYS}
    extra = {"project_version": cat.get("project_version"), "rules": cat.get("rules")}
    return SourceMeta("oebc", date_, count, extra), rows


def _parse_record(raw: bytes | str, where: str) -> dict[str, Any]:
    try:
        rec = json.loads(raw)
        if not isinstance(rec, dict) or not isinstance(rec.get("id"), str):
            raise ValueError("no id")
        if not isinstance(rec.get("affected", []), list):
            raise ValueError("affected is not a list")
        if rec.get("modified"):
            parse_ts(str(rec["modified"]))
        return rec
    except (ValueError, TypeError) as e:
        raise DataInvalid(f"invalid OSV record {where}: {e}") from e


def iter_osv(source: Path) -> Iterator[dict[str, Any]]:
    if source.is_dir():
        for p in sorted(source.rglob("*.json")):
            yield _parse_record(p.read_bytes(), str(p))
        return
    try:
        with zipfile.ZipFile(source) as z:
            for n in z.namelist():
                if n.endswith(".json"):
                    yield _parse_record(z.read(n), f"{source}:{n}")
    except (zipfile.BadZipFile, OSError) as e:
        raise DataInvalid(f"cannot open OSV source {source}: {e}") from e


def _ecosystems(rec: dict[str, Any]) -> set[str]:
    return {
        a["package"]["ecosystem"]
        for a in rec.get("affected", [])
        if isinstance(a, dict) and "ecosystem" in a.get("package", {})
    }


def _index_entries(rec: dict[str, Any]) -> set[tuple[str, str]]:
    return {
        (a["package"]["ecosystem"], normalize_name(a["package"]["ecosystem"], a["package"]["name"]))
        for a in rec.get("affected", [])
        if isinstance(a, dict) and {"ecosystem", "name"} <= set(a.get("package", {}))
    }


class _OsvTally:
    """Collects per-ecosystem counts and max `modified` across records."""

    def __init__(self) -> None:
        self.count: dict[str, int] = {}
        self.latest: dict[str, datetime] = {}

    def add(self, rec: dict[str, Any]) -> None:
        mod = parse_ts(str(rec["modified"])) if rec.get("modified") else None
        for eco in _ecosystems(rec):
            self.count[eco] = self.count.get(eco, 0) + 1
            cur = self.latest.get(eco, datetime.min.replace(tzinfo=timezone.utc))
            self.latest[eco] = max(cur, mod) if mod else cur

    def meta(self) -> dict[str, SourceMeta]:
        return {e: SourceMeta(f"osv:{e}", self.latest[e], n) for e, n in sorted(self.count.items())}


# ---- stores ----------------------------------------------------------------


class MemoryStore:
    def __init__(
        self,
        meta: DataMeta,
        advisories: dict[tuple[str, str], list[dict[str, Any]]],
        oebc: dict[str, dict[str, Any]],
    ) -> None:
        self.meta = meta
        self._adv = advisories
        self._oebc = oebc

    @classmethod
    def from_files(
        cls,
        oebc_path: Path | None,
        osv_sources: list[Path],
        published_before: date | None = None,
    ) -> MemoryStore:
        oebc_meta, oebc_rows = load_oebc(oebc_path) if oebc_path else (None, {})
        tally = _OsvTally()
        adv: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for src in osv_sources:
            for rec in iter_osv(src):
                tally.add(rec)
                if _published_after(rec, published_before):
                    continue
                for key in _index_entries(rec):
                    adv.setdefault(key, []).append(rec)
        return cls(DataMeta(oebc_meta, tally.meta()), adv, oebc_rows)

    def advisories(self, ecosystem: str, name: str) -> list[dict[str, Any]]:
        return list(self._adv.get((ecosystem, normalize_name(ecosystem, name)), []))

    def oebc(self, cve_id: str) -> dict[str, Any] | None:
        row = self._oebc.get(cve_id)
        return dict(row) if row else None


def _meta_to_json(m: DataMeta) -> str:
    def src(s: SourceMeta | None) -> dict[str, Any] | None:
        if s is None:
            return None
        return {"source": s.source, "date": s.date.isoformat(), "count": s.count, "extra": s.extra}

    return json.dumps(
        {"oebc": src(m.oebc), "osv": {e: src(s) for e, s in m.osv.items()}, "replay": m.replay}
    )


def _meta_from_json(text: str) -> DataMeta:
    def src(d: dict[str, Any] | None) -> SourceMeta | None:
        if d is None:
            return None
        return SourceMeta(d["source"], parse_ts(d["date"]), d["count"], d["extra"])

    d = json.loads(text)
    return DataMeta(
        src(d["oebc"]),
        {e: s for e, v in d["osv"].items() if (s := src(v)) is not None},
        d["replay"],
    )


def build_index(oebc_path: Path, osv_zips: dict[str, Path], out: Path) -> DataMeta:
    """Write the SQLite index atomically (temp file + os.replace)."""
    oebc_meta, oebc_rows = load_oebc(oebc_path)
    tally = _OsvTally()
    seen: set[tuple[str, str, str]] = set()
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    tmp.unlink(missing_ok=True)
    con = sqlite3.connect(tmp)
    try:
        con.executescript(
            "CREATE TABLE advisory(ecosystem TEXT, name TEXT, record_json TEXT);"
            "CREATE TABLE oebc(cve_id TEXT PRIMARY KEY, exposure_tier TEXT, kev_listed INTEGER,"
            " kev_date_added TEXT, epss_score REAL, cvss_score REAL);"
            "CREATE TABLE meta(key TEXT PRIMARY KEY, value_json TEXT);"
        )
        for eco, zpath in osv_zips.items():
            n = 0
            for rec in iter_osv(zpath):
                tally.add(rec)
                n += 1
                text = json.dumps(rec)
                for e, name in _index_entries(rec):
                    if (e, name, rec["id"]) not in seen:
                        seen.add((e, name, rec["id"]))
                        con.execute("INSERT INTO advisory VALUES(?,?,?)", (e, name, text))
            if n == 0 or eco not in tally.count:
                raise DataInvalid(f"OSV {eco}: no records for this ecosystem in {zpath}")
        con.executemany(
            "INSERT INTO oebc VALUES(?,?,?,?,?,?)",
            [
                (c, r["exposure_tier"], None if r["kev_listed"] is None else int(r["kev_listed"]),
                 r["kev_date_added"], r["epss_score"], r["cvss_score"])
                for c, r in oebc_rows.items()
            ],
        )
        meta = DataMeta(oebc_meta, tally.meta())
        con.execute("INSERT INTO meta VALUES('meta', ?)", (_meta_to_json(meta),))
        con.execute("CREATE INDEX advisory_idx ON advisory(ecosystem, name)")
        con.commit()
    except BaseException:
        con.close()
        tmp.unlink(missing_ok=True)
        raise
    con.close()
    os.replace(tmp, out)
    return meta


class SqliteStore:
    def __init__(self, path: Path, published_before: date | None = None) -> None:
        if not path.is_file():
            raise DataMissing(f"no data index at {path}; run `exposuregate update-data`")
        self._cutoff = published_before
        try:
            self._con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            row = self._con.execute("SELECT value_json FROM meta WHERE key='meta'").fetchone()
            self._con.execute("SELECT 1 FROM advisory LIMIT 1")
            self._con.execute("SELECT 1 FROM oebc LIMIT 1")
            if row is None:
                raise DataInvalid(f"{path}: no meta row")
            self.meta = _meta_from_json(row[0])
        except (sqlite3.DatabaseError, ValueError, KeyError, TypeError) as e:
            raise DataInvalid(f"{path} is not a valid exposuregate index: {e}") from e

    def advisories(self, ecosystem: str, name: str) -> list[dict[str, Any]]:
        rows = self._con.execute(
            "SELECT record_json FROM advisory WHERE ecosystem=? AND name=?",
            (ecosystem, normalize_name(ecosystem, name)),
        ).fetchall()
        recs = [json.loads(r[0]) for r in rows]
        return [r for r in recs if not _published_after(r, self._cutoff)]

    def oebc(self, cve_id: str) -> dict[str, Any] | None:
        row = self._con.execute(
            "SELECT exposure_tier, kev_listed, kev_date_added, epss_score, cvss_score"
            " FROM oebc WHERE cve_id=?",
            (cve_id,),
        ).fetchone()
        if row is None:
            return None
        d = dict(zip(_OEBC_KEYS, row, strict=True))
        if d["kev_listed"] is not None:
            d["kev_listed"] = bool(d["kev_listed"])
        return d

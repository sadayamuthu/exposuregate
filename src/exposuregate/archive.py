"""Reader for the daily snapshot archive (spec 6.5; layout of paper/eval/archive/archive.py).

Layout under the root:
  days/<D>.json                       manifest: "sources" per source, "errors" per failed source
  blobs/<source>/<sha256>.<ext>       KEV JSON and OEBC catalog
  osv/<eco>/index-<D>.jsonl.gz        every advisory {"id", "modified"} in that day's export
  osv/<eco>/delta-<D>.jsonl.gz        records whose (id, modified) was new that day

OSV state as of D: for each id in index-D, the record with that id and the same ``modified``
from delta files dated <= D.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from collections.abc import Iterable, Iterator
from datetime import date
from pathlib import Path
from typing import Any

from exposuregate.store import DataInvalid, DataMissing, MemoryStore, parse_osv_record


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        man: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(man.get("sources"), dict) or not isinstance(man.get("errors", {}), dict):
            raise ValueError("sources/errors are not objects")
    except (OSError, ValueError, AttributeError) as e:
        raise DataInvalid(f"invalid archive manifest {path}: {e}") from e
    return man


def _usable(man: dict[str, Any], needed: list[str]) -> bool:
    errors = man.get("errors", {})
    return all(s in man["sources"] and s not in errors for s in needed)


def _pick_day(root: Path, as_of: date, ecosystems: list[str]) -> tuple[str, dict[str, Any]]:
    """Latest manifest dated <= as_of with every needed source present and error-free."""
    days_dir = root / "days"
    if not days_dir.is_dir():
        raise DataMissing(f"no snapshot archive at {root} (missing days/)")
    days: list[date] = []
    for p in days_dir.glob("*.json"):
        try:
            days.append(date.fromisoformat(p.stem))
        except ValueError:
            continue
    needed = ["oebc", *(f"osv-{e}" for e in ecosystems)]
    for d in sorted((d for d in days if d <= as_of), reverse=True):
        man = _read_manifest(days_dir / f"{d.isoformat()}.json")
        if _usable(man, needed):
            return d.isoformat(), man
    raise DataMissing(
        f"archive {root}: no day on or before {as_of} with {', '.join(needed)} archived"
    )


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _jsonl(path: Path) -> Iterator[str]:
    try:
        with gzip.open(path, "rt", encoding="utf-8") as g:
            yield from (line for line in g if line.strip())
    except (OSError, EOFError, UnicodeDecodeError) as e:
        raise DataInvalid(f"cannot read {path}: {e}") from e


def _osv_state(root: Path, eco: str, day: str, entry: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Every record of ``eco`` as it stood on ``day``."""
    rel = entry.get("index") if isinstance(entry, dict) else None
    index = root / str(rel or f"osv/{eco}/index-{day}.jsonl.gz")
    if not index.is_file():
        raise DataMissing(f"archive index missing: {index}")
    wanted: dict[str, str] = {}
    for line in _jsonl(index):
        try:
            row = json.loads(line)
            wanted[str(row["id"])] = str(row["modified"])
        except (ValueError, KeyError, TypeError) as e:
            raise DataInvalid(f"invalid archive index line in {index}: {e!r}") from e
    deltas = sorted(
        p for p in (root / "osv" / eco).glob("delta-*.jsonl.gz")
        if p.name[len("delta-"):-len(".jsonl.gz")] <= day
    )
    for delta in deltas:
        if not wanted:
            break
        for line in _jsonl(delta):
            rec = parse_osv_record(line, str(delta))
            if wanted.get(rec["id"]) == rec.get("modified", ""):
                del wanted[rec["id"]]
                yield rec
    if wanted:
        sample = ", ".join(sorted(wanted)[:5])
        raise DataInvalid(
            f"archive {root}: {len(wanted)} {eco} records of {day} not found in deltas ({sample})"
        )


class ArchiveStore:
    @staticmethod
    def open(root: Path, as_of: date, ecosystems: Iterable[str] = ()) -> MemoryStore:
        """Data as archived on the latest day <= as_of whose OEBC and needed OSV were archived.

        ``ecosystems``: the OSV ecosystems to load; a day with an error for any of them (or for
        OEBC) is skipped. Archived state is already as of that day, so no ``published`` filter.
        """
        names = sorted(set(ecosystems))
        day, man = _pick_day(root, as_of, names)
        oebc_entry = man["sources"]["oebc"]
        try:
            blob = root / str(oebc_entry["blob"])
            expected = str(oebc_entry["sha256"])
        except (KeyError, TypeError) as e:
            raise DataInvalid(f"archive manifest {day}: bad oebc entry: {e!r}") from e
        if not blob.is_file():
            raise DataMissing(f"archived OEBC blob missing: {blob}")
        if _sha256(blob) != expected:
            raise DataInvalid(f"archived OEBC blob {blob} does not match sha256 {expected}")
        seen: set[str] = set()

        def records() -> Iterator[dict[str, Any]]:
            for eco in names:
                for rec in _osv_state(root, eco, day, man["sources"][f"osv-{eco}"]):
                    if rec["id"] not in seen:  # an advisory in two ecosystems' exports
                        seen.add(rec["id"])
                        yield rec

        store = MemoryStore.from_records(blob, records())
        store.meta.replay = {"osv_mode": "archived", "archive_day": day}
        if store.meta.oebc is not None:
            store.meta.oebc.extra["source"] = f"{blob} (archive {root}, day {day})"
        for eco, src in store.meta.osv.items():
            src.extra["source"] = f"{root / 'osv' / eco} (archive {root}, day {day})"
        return store

"""Scan orchestration: inputs -> lockfiles -> data -> grading -> report (spec 4, 5.5, 6.3, 10)."""

from __future__ import annotations

import json
import os
import posixpath
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timezone
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from exposuregate import freshness, gitio
from exposuregate.config import Config
from exposuregate.diffing import changed_pins
from exposuregate.grading import expired_suppressions, grade, unsupported_finding, verdict
from exposuregate.lockfiles import ECOSYSTEM, classify, parse
from exposuregate.models import ChangedPin, Denial, Finding, LockfileError, ParsedLockfile
from exposuregate.report import build_report
from exposuregate.store import (
    DataInvalid,
    DataMeta,
    DataMissing,
    DataStore,
    MemoryStore,
    SqliteStore,
)

_WALK_SKIP = {".git", "node_modules"}


class UsageError(Exception):
    """Invalid combination of scan options (exit 2)."""


@dataclass
class ScanOptions:
    mode: str = "pre-commit"  # pre-commit | pr | full | explicit | files
    target_branch: str = "main"
    base: str | None = None
    head: str | None = None
    old_file: Path | None = None
    new_file: Path | None = None
    lockfile_type: str | None = None
    manifest_file: Path | None = None
    path: Path = Path(".")
    data_dir: Path | None = None
    oebc_file: Path | None = None
    osv_dir: Path | None = None
    as_of: date | None = None
    replay: bool = False
    archive: Path | None = None
    fail_open: bool = False
    formats: list[str] = field(default_factory=lambda: ["json", "markdown"])
    output_dir: Path | None = None


Reader = Callable[[str, str], "str | None"]  # (side, path) -> text or None when absent


@dataclass
class _Inputs:
    paths: list[str]
    read: Reader
    input: dict[str, Any]
    forced_type: str | None = None  # --new/--lockfile-type: classify is bypassed


def _ms(start: float) -> int:
    return int(round((time.perf_counter() - start) * 1000))


def _read_file(p: Path | None) -> str | None:
    if p is None:
        return None
    try:
        return p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except UnicodeDecodeError as e:
        raise LockfileError("lockfile_parse", f"{p} is not UTF-8") from e


def _walk(root: Path) -> list[str]:
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _WALK_SKIP)
        rel = Path(dirpath).relative_to(root)
        out += [(rel / f).as_posix() for f in filenames]
    return sorted(out)


def _collect_inputs(opts: ScanOptions) -> _Inputs:
    if opts.mode == "files":
        assert opts.new_file is not None
        old, new, label = opts.old_file, opts.new_file, str(opts.new_file)

        def read_files(side: str, path: str) -> str | None:
            if side == "manifest":
                return _read_file(opts.manifest_file)
            return _read_file(old if side == "old" else new)

        meta = {"mode": "files", "old": str(old) if old else None, "new": label}
        return _Inputs([label], read_files, meta, forced_type=opts.lockfile_type)

    if opts.mode == "full":
        root = opts.path
        try:
            paths = [p for p in gitio.tracked_files(root) if (root / p).is_file()]
        except gitio.GitError:
            paths = _walk(root)

        def read_full(side: str, path: str) -> str | None:
            return None if side == "old" else _read_file(root / path)

        return _Inputs(paths, read_full, {"mode": "full", "path": str(root)})

    root = gitio.repo_root(opts.path)
    paths, old_ref, new_ref = gitio.changed_files(
        opts.mode, root, opts.target_branch, opts.base, opts.head
    )

    def read_git(side: str, path: str) -> str | None:
        return gitio.read_blob(old_ref if side == "old" else new_ref, path, root)

    def sha(ref: str | None) -> str | None:
        return gitio.rev_parse(ref, root) if ref not in (None, gitio.INDEX) else None

    meta = {"mode": opts.mode, "base": sha(old_ref), "head": sha(new_ref)}
    return _Inputs(paths, read_git, meta)


def _type_name(path: str, cfg: Config) -> str | None:
    base = posixpath.basename(path)
    for name, lf in cfg.lockfiles.items():
        if any(fnmatchcase(base, g) for g in lf.globs):
            return name
    return None


@dataclass
class _Graded:
    path: str
    ecosystem: str
    changes: list[ChangedPin]


@dataclass
class _LockfileResults:
    entries: list[dict[str, Any]] = field(default_factory=list)
    graded: list[_Graded] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)
    denials: list[Denial] = field(default_factory=list)


def _read_side(
    inp: _Inputs, side: str, path: str, res: _LockfileResults
) -> tuple[bool, str | None]:
    """(ok, text); on failure a denial naming the path and side is recorded."""
    try:
        return True, inp.read(side, path)
    except gitio.GitError as e:
        res.denials.append(Denial("git_error", f"{path} ({side} side): {e}"))
    except LockfileError as e:
        res.denials.append(Denial(e.code, f"{path} ({side} side): {e}"))
    return False, None


def _manifest_text(inp: _Inputs, side: str, path: str, ltype: str) -> str | None:
    if ltype != "poetry":
        return None
    if inp.forced_type is not None:
        side, mpath = "manifest", ""
    else:
        mpath = posixpath.join(posixpath.dirname(path), "pyproject.toml")
    try:
        return inp.read(side, mpath)
    except (gitio.GitError, LockfileError):
        return None  # poetry tags dependencies as "unknown" without a manifest


def _grade_lockfile(inp: _Inputs, path: str, ltype: str, res: _LockfileResults) -> None:
    ok_new, new_text = _read_side(inp, "new", path, res)
    ok_old, old_text = _read_side(inp, "old", path, res)
    entry: dict[str, Any] = {"path": path, "type": ltype}
    if not (ok_new and ok_old):
        res.entries.append({**entry, "status": "parse_error"})
        return
    if new_text is None:  # deleted: contributes nothing (spec 4.1)
        res.entries.append({**entry, "status": "unchanged", "pins_added_or_changed": 0,
                            "pins_skipped": 0})
        return
    parsed: dict[str, ParsedLockfile | None] = {"old": None, "new": None}
    failed = False
    for side, text in (("old", old_text), ("new", new_text)):
        if text is None:
            continue
        try:
            parsed[side] = parse(ltype, text, _manifest_text(inp, side, path, ltype))
        except LockfileError as e:
            res.denials.append(Denial(e.code, f"{path} ({side} side): {e}"))
            failed = True
    new = parsed["new"]
    if failed or new is None:
        res.entries.append({**entry, "status": "parse_error"})
        return
    old = parsed["old"]
    changes = changed_pins(old, new)
    old_skipped = set(old.skipped) if old else set()
    skipped = [s for s in new.skipped if s not in old_skipped]
    res.skipped += [{"lockfile": path, "package": s.package, "reason": s.reason} for s in skipped]
    res.entries.append({
        **entry, "status": "graded" if changes else "unchanged",
        "pins_added_or_changed": len(changes), "pins_skipped": len(skipped),
    })
    res.graded.append(_Graded(path, ECOSYSTEM[ltype], changes))


def _read_lockfiles(inp: _Inputs, cfg: Config) -> _LockfileResults:
    res = _LockfileResults()
    if inp.forced_type is not None:
        _grade_lockfile(inp, inp.paths[0], inp.forced_type, res)
        return res
    unexcluded = replace(cfg, excluded_paths=[])
    lockfile_dirs: set[str] = set()
    manifests: list[str] = []
    for path in inp.paths:
        kind = classify(path, cfg)
        would_be = classify(path, unexcluded) if kind == "excluded" else kind
        if would_be not in ("manifest", "ignore"):
            lockfile_dirs.add(posixpath.dirname(path))
        if kind == "ignore":
            continue
        if kind == "excluded":
            # Only dependency files are listed; an excluded README.md is not news.
            if would_be != "ignore":
                res.entries.append(
                    {"path": path, "type": _type_name(path, cfg), "status": "excluded"}
                )
        elif kind == "disabled":
            res.entries.append({"path": path, "type": _type_name(path, cfg), "status": "disabled"})
        elif kind == "unsupported":
            ok, text = _read_side(inp, "new", path, res)
            if ok and text is not None:
                res.entries.append({"path": path, "type": None, "status": "unsupported"})
                res.unsupported.append(path)
        elif kind == "manifest":
            manifests.append(path)
        else:
            _grade_lockfile(inp, path, kind, res)
    for path in manifests:
        if posixpath.dirname(path) not in lockfile_dirs:
            res.entries.append({"path": path, "type": None, "status": "manifest_only"})
    res.entries.sort(key=lambda e: e["path"])
    return res


def _manifest_sources(data_dir: Path) -> dict[str, Any]:
    try:
        man = json.loads((data_dir / "manifest.json").read_text())
        return man if isinstance(man, dict) else {}
    except (OSError, ValueError):
        return {}


def _set_source(meta: DataMeta, oebc: str | None, osv: Callable[[str], str | None]) -> None:
    if meta.oebc is not None and oebc:
        meta.oebc.extra["source"] = oebc
    for eco, src in meta.osv.items():
        value = osv(eco)
        if value:
            src.extra["source"] = value


def _osv_sources(osv_dir: Path) -> list[Path]:
    if osv_dir.is_file():
        return [osv_dir]
    sources: list[Path] = sorted(osv_dir.glob("*.zip"))
    if any(osv_dir.rglob("*.json")):
        sources.append(osv_dir)
    return sources


def _open_store(opts: ScanOptions, cfg: Config) -> DataStore:
    """Open the advisory store; raises DataMissing / DataInvalid."""
    if opts.archive is not None:
        # Hook for Task 14: ArchiveStore reading the snapshot archive layout (spec 6.5).
        raise UsageError("--archive is not yet supported")
    if opts.oebc_file is not None or opts.osv_dir is not None:
        if opts.oebc_file is not None and not opts.oebc_file.exists():
            raise DataMissing(f"OEBC file not found: {opts.oebc_file}")
        if opts.osv_dir is not None and not opts.osv_dir.exists():
            raise DataMissing(f"OSV source not found: {opts.osv_dir}")
        mem = MemoryStore.from_files(
            opts.oebc_file,
            _osv_sources(opts.osv_dir) if opts.osv_dir else [],
            published_before=opts.as_of,
        )
        osv_src = str(opts.osv_dir) if opts.osv_dir else None
        _set_source(mem.meta, str(opts.oebc_file) if opts.oebc_file else None,
                    lambda _eco: osv_src)
        return mem
    data_dir = opts.data_dir or cfg.data_dir
    index = data_dir / "index.sqlite"
    sq = SqliteStore(index, published_before=opts.as_of)
    man = _manifest_sources(data_dir)
    oebc_man = man.get("oebc")
    oebc_url = oebc_man.get("url") if isinstance(oebc_man, dict) else None
    osv_man = man.get("osv")
    if not isinstance(osv_man, dict):
        osv_man = {}

    def osv_url(eco: str) -> str:
        entry = osv_man.get(eco)
        url = entry.get("url") if isinstance(entry, dict) else None
        return url if isinstance(url, str) else str(index)

    _set_source(sq.meta, oebc_url if isinstance(oebc_url, str) else str(index), osv_url)
    return sq


def run_scan(opts: ScanOptions, cfg: Config) -> tuple[dict[str, Any], int]:
    t_total = time.perf_counter()
    now = opts.as_of or datetime.now(timezone.utc).date()
    fail_closed = cfg.fail_closed and not opts.fail_open

    t0 = time.perf_counter()
    inp = _collect_inputs(opts)
    res = _read_lockfiles(inp, cfg)
    read_ms = _ms(t0)
    denials = list(res.denials)

    needed = {g.ecosystem for g in res.graded if g.changes}
    meta: DataMeta | None = None
    store: DataStore | None = None
    t0 = time.perf_counter()
    if needed:  # no graded change -> no data needed, freshness not checked (spec 10)
        try:
            store = _open_store(opts, cfg)
            meta = store.meta
            denials += freshness.check(meta, needed, now, cfg, opts.replay)
        except DataMissing as e:
            denials.append(Denial("data_missing", str(e)))
        except DataInvalid as e:
            denials.append(Denial("data_invalid", str(e)))
    load_ms = _ms(t0)

    t0 = time.perf_counter()
    findings: list[Finding] = []
    if store is not None:
        for g in res.graded:
            findings += grade(g.path, g.changes, store, cfg, now)
    findings += [unsupported_finding(p, cfg) for p in res.unsupported]
    expired, expired_findings = expired_suppressions(findings, cfg, now)
    findings += expired_findings
    match_ms = _ms(t0)

    if not fail_closed:
        denials = [replace(d, enforced=False) for d in denials]
    verdict_, code = verdict(findings, denials, fail_closed)
    report = build_report(
        verdict=verdict_, exit_code=code, as_of=now, input=inp.input, meta=meta, cfg=cfg,
        lockfiles=res.entries, findings=findings, skipped=res.skipped, denials=denials,
        expired=expired,
        timing_ms={"load_data": load_ms, "read_lockfiles": read_ms, "match": match_ms,
                   "total": _ms(t_total)},
    )
    return report, code

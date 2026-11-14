"""Command line interface (spec 4.1, 4.2)."""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from datetime import date
from pathlib import Path

from exposuregate import __version__
from exposuregate.config import REPORT_FORMATS, Config, ConfigError, load_config
from exposuregate.gitio import GitError
from exposuregate.lockfiles import PARSERS
from exposuregate.report import to_json, to_markdown
from exposuregate.scan import ScanOptions, UsageError, run_scan
from exposuregate.store import DataInvalid, DataMissing

USAGE_EXIT = 2


def _iso_date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid date {value!r}, expected YYYY-MM-DD") from None


def _non_negative(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        n = -1
    if n < 0:
        raise argparse.ArgumentTypeError(f"expected a non-negative integer, got {value!r}")
    return n


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="exposuregate")
    p.add_argument("--version", action="version", version=f"exposuregate {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="grade dependency versions added in lockfiles")
    s.add_argument("--mode", choices=["pre-commit", "pr", "full"])
    s.add_argument("--target-branch", default="main")
    s.add_argument("--base")
    s.add_argument("--head")
    s.add_argument("--old", type=Path)
    s.add_argument("--new", type=Path)
    s.add_argument("--lockfile-type", choices=sorted(PARSERS))
    s.add_argument("--manifest", type=Path)
    s.add_argument("--path", type=Path, default=Path("."))
    s.add_argument("--config", type=Path)
    s.add_argument("--format", nargs="+", choices=REPORT_FORMATS, dest="formats")
    s.add_argument("--output-dir", type=Path)
    s.add_argument("--data-dir", type=Path)
    s.add_argument("--oebc", type=Path)
    s.add_argument("--osv-dir", type=Path)
    s.add_argument("--as-of", type=_iso_date)
    s.add_argument("--replay", action="store_true")
    s.add_argument("--archive", type=Path)
    s.add_argument("--max-age-days", type=_non_negative)
    s.add_argument("--fail-open", action="store_true")

    u = sub.add_parser("update-data", help="download OEBC and OSV data (uses the network)")
    u.add_argument("--data-dir", type=Path)
    u.add_argument("--ecosystems", nargs="+", default=["PyPI", "npm"], choices=["PyPI", "npm"])

    r = sub.add_parser("rebuild-oebc", help="rebuild an OEBC catalog as of a past date")
    r.add_argument("--as-of", type=_iso_date, required=True)
    r.add_argument("--kev", type=Path, required=True)
    r.add_argument("--epss-dir", type=Path, required=True)
    r.add_argument("--oebc", type=Path, required=True)
    r.add_argument("--out", type=Path, required=True)

    i = sub.add_parser("data-info", help="show the local data snapshot")
    i.add_argument("--data-dir", type=Path)
    return p


def _scan_mode(p: argparse.ArgumentParser, a: argparse.Namespace) -> str:
    """Validate the mutually exclusive input selections and return the scan mode."""
    git_refs = a.base is not None or a.head is not None
    files = a.old is not None or a.new is not None
    if sum([a.mode is not None, git_refs, files]) > 1:
        p.error("choose one input: --mode, --base/--head, or --old/--new")
    if git_refs and (a.base is None or a.head is None):
        p.error("--base and --head must be given together")
    if files and a.new is None:
        p.error("--old needs --new")
    if a.new is not None and a.lockfile_type is None:
        p.error("--new needs --lockfile-type")
    if a.new is None and (a.lockfile_type is not None or a.manifest is not None):
        p.error("--lockfile-type and --manifest are only valid with --new")
    if a.replay and a.as_of is None:
        p.error("--replay needs --as-of")
    if a.archive is not None and a.as_of is None:
        p.error("--archive needs --as-of")
    if a.archive is not None and (a.oebc is not None or a.osv_dir is not None):
        p.error("--archive cannot be combined with --oebc/--osv-dir")
    if git_refs:
        return "explicit"
    if files:
        return "files"
    return a.mode or "pre-commit"


def _resolve(base: Path, p: Path) -> Path:
    p = p.expanduser()
    return p if p.is_absolute() else base / p


def _scan(p: argparse.ArgumentParser, a: argparse.Namespace) -> int:
    mode = _scan_mode(p, a)
    cfg: Config = load_config(a.config, a.path)
    # Precedence: CLI flags > EXPOSUREGATE_DATA_DIR (applied by load_config) > config file.
    if a.data_dir is not None:
        cfg = replace(cfg, data_dir=a.data_dir.expanduser())
    if a.max_age_days is not None:
        cfg = replace(cfg, max_age_days=a.max_age_days)  # per-source overrides still win
    formats = a.formats or cfg.report_formats
    out_dir = a.output_dir or (Path(cfg.output_dir) if cfg.output_dir else None)
    opts = ScanOptions(
        mode=mode, target_branch=a.target_branch, base=a.base, head=a.head,
        old_file=a.old, new_file=a.new, lockfile_type=a.lockfile_type, manifest_file=a.manifest,
        path=a.path, data_dir=cfg.data_dir, oebc_file=a.oebc, osv_dir=a.osv_dir, as_of=a.as_of,
        replay=a.replay, archive=a.archive, fail_open=a.fail_open, formats=formats,
        output_dir=_resolve(a.path, out_dir) if out_dir else None,
    )
    print(f"exposuregate: scanning ({mode})", file=sys.stderr)
    report, code = run_scan(opts, cfg)
    rendered = {"json": to_json(report), "markdown": to_markdown(report)}
    for fmt in formats:
        sys.stdout.write(rendered[fmt].rstrip("\n") + "\n")
    if opts.output_dir is not None:
        opts.output_dir.mkdir(parents=True, exist_ok=True)
        names = {"json": "report.json", "markdown": "report.md"}
        for fmt in formats:
            (opts.output_dir / names[fmt]).write_text(rendered[fmt], encoding="utf-8")
        print(f"exposuregate: reports written to {opts.output_dir}", file=sys.stderr)
    s = report["summary"]
    print(
        f"exposuregate: {report['verdict']} ({s['block']} block, {s['warn']} warn,"
        f" {s['pass']} pass, {s['denials']} denials)",
        file=sys.stderr,
    )
    return code


def _data_dir(a: argparse.Namespace) -> Path:
    if a.data_dir is not None:
        return Path(a.data_dir).expanduser()
    return load_config(None, Path(".")).data_dir


def main(argv: list[str] | None = None) -> int:
    p = _parser()
    try:
        a = p.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else USAGE_EXIT
    try:
        if a.command == "scan":
            return _scan(p, a)
        if a.command == "update-data":
            from exposuregate.update import update_data

            data_dir = _data_dir(a)
            print(f"exposuregate: updating data in {data_dir}", file=sys.stderr)
            update_data(data_dir, list(a.ecosystems))
            return 0
        if a.command == "rebuild-oebc":
            from exposuregate.rebuild import rebuild_oebc

            cat = rebuild_oebc(a.as_of, a.kev, a.epss_dir, a.oebc, a.out)
            print(f"exposuregate: rebuilt OEBC as of {a.as_of}: {cat['count']} CVEs -> {a.out}",
                  file=sys.stderr)
            return 0
        if a.command == "data-info":
            from exposuregate.update import data_info

            print(data_info(_data_dir(a)))
            return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else USAGE_EXIT
    except (ConfigError, GitError, UsageError) as e:
        print(f"exposuregate: error: {e}", file=sys.stderr)
        return USAGE_EXIT
    except (DataMissing, DataInvalid) as e:
        print(f"exposuregate: error: {e}", file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001 - exit 1 means BLOCK, so never let a crash reach it
        print(f"exposuregate: unexpected error: {type(e).__name__}: {e}", file=sys.stderr)
        return USAGE_EXIT
    return USAGE_EXIT


if __name__ == "__main__":
    sys.exit(main())

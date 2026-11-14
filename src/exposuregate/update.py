"""update-data and data-info (spec 6.2). The only module that touches the network."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from exposuregate.store import DataInvalid, DataMeta, DataMissing, SqliteStore, build_index

_TIMEOUT_S = 300
OEBC_URL = "https://openastra.org/oebc/catalog/v0.1/latest.json.gz"
OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"


def _download(url: str, dest: Path) -> None:
    try:
        with urllib.request.urlopen(url, timeout=_TIMEOUT_S) as resp, dest.open("wb") as f:  # noqa: S310
            shutil.copyfileobj(resp, f)
    except (OSError, ValueError) as e:
        raise DataInvalid(f"download failed for {url}: {e}") from e


def update_data(
    data_dir: Path, ecosystems: list[str], urls: dict[str, Any] | None = None
) -> DataMeta:
    urls = urls or {}
    oebc_url: str = urls.get("oebc", OEBC_URL)
    osv_urls: dict[str, str] = {
        e: urls.get("osv", {}).get(e, OSV_URL.format(eco=e)) for e in ecosystems
    }
    data_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="dl-", dir=data_dir) as tmpname:
        tmp = Path(tmpname)
        oebc_file = tmp / "oebc.bin"
        _download(oebc_url, oebc_file)
        zips: dict[str, Path] = {}
        for eco, url in osv_urls.items():
            zips[eco] = tmp / f"{eco}.zip"
            _download(url, zips[eco])
        new_index = tmp / "index.sqlite"
        meta = build_index(oebc_file, zips, new_index)
        manifest: dict[str, Any] = {
            "downloaded_at": datetime.now(timezone.utc).isoformat(),
            "oebc": {
                "url": oebc_url,
                "generated_at_utc": meta.oebc.date.isoformat() if meta.oebc else None,
                "count": meta.oebc.count if meta.oebc else 0,
                "project_version": meta.oebc.extra.get("project_version") if meta.oebc else None,
            },
            "osv": {
                e: {"url": osv_urls[e], "as_of": meta.osv[e].date.isoformat(),
                    "count": meta.osv[e].count}
                for e in ecosystems
            },
        }
        man_tmp = data_dir / "manifest.json.tmp"
        man_tmp.write_text(json.dumps(manifest, indent=2))
        idx_tmp = data_dir / "index.sqlite.tmp"
        shutil.move(str(new_index), idx_tmp)
        os.replace(idx_tmp, data_dir / "index.sqlite")
        os.replace(man_tmp, data_dir / "manifest.json")
    return meta


def data_info(data_dir: Path) -> str:
    store = SqliteStore(data_dir / "index.sqlite")
    meta = store.meta
    lines = [f"Data directory: {data_dir}"]
    man = data_dir / "manifest.json"
    if man.is_file():
        try:
            lines.append(f"Downloaded at: {json.loads(man.read_text()).get('downloaded_at')}")
        except ValueError:
            pass
    if meta.oebc is None:
        raise DataMissing(f"{data_dir}: index has no OEBC data")
    o = meta.oebc
    lines.append(
        f"OEBC: generated {o.date.isoformat()} ({o.count} records,"
        f" project_version {o.extra.get('project_version')})"
    )
    for eco, s in meta.osv.items():
        lines.append(f"OSV {eco}: as_of {s.date.isoformat()} ({s.count} records)")
    return "\n".join(lines)

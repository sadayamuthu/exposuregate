from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from exposuregate.config import Config, load_config
from exposuregate.lockfiles import ECOSYSTEM, classify, parse


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    return load_config(None, tmp_path)


def test_classify_default_globs(cfg: Config) -> None:
    assert classify("a/b/requirements-dev.txt", cfg) == "requirements"
    assert classify("requirements.txt", cfg) == "requirements"
    assert classify("x/uv.lock", cfg) == "uv"
    assert classify("poetry.lock", cfg) == "poetry"
    assert classify("ui/package-lock.json", cfg) == "npm"


def test_classify_unsupported(cfg: Config) -> None:
    assert classify("web/yarn.lock", cfg) == "unsupported"


def test_classify_manifest(cfg: Config) -> None:
    assert classify("pyproject.toml", cfg) == "manifest"
    assert classify("ui/package.json", cfg) == "manifest"


def test_classify_ignore(cfg: Config) -> None:
    assert classify("README.md", cfg) == "ignore"


def test_classify_excluded_beats_type(cfg: Config) -> None:
    cfg = replace(cfg, excluded_paths=["vendor/*"])
    assert classify("vendor/uv.lock", cfg) == "excluded"
    assert classify("src/uv.lock", cfg) == "uv"


def test_classify_disabled_type(cfg: Config) -> None:
    lf = dict(cfg.lockfiles)
    lf["npm"] = replace(lf["npm"], enabled=False)
    cfg = replace(cfg, lockfiles=lf)
    assert classify("package-lock.json", cfg) == "disabled"
    assert classify("uv.lock", cfg) == "uv"


def test_custom_globs(cfg: Config) -> None:
    lf = dict(cfg.lockfiles)
    lf["requirements"] = replace(lf["requirements"], globs=["deps-*.txt"])
    cfg = replace(cfg, lockfiles=lf)
    assert classify("deps-a.txt", cfg) == "requirements"
    assert classify("requirements.txt", cfg) == "ignore"


def test_case_sensitive(cfg: Config) -> None:
    assert classify("UV.LOCK", cfg) == "ignore"


def test_parse_dispatch_and_unknown() -> None:
    p = parse("requirements", "a==1.0\n")
    assert p.type == "requirements"
    assert ECOSYSTEM["npm"] == "npm"
    with pytest.raises(ValueError):
        parse("bogus", "")

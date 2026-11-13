"""Lockfile classification and parser dispatch."""

from __future__ import annotations

import posixpath
from collections.abc import Callable
from fnmatch import fnmatchcase

from exposuregate.config import Config
from exposuregate.lockfiles.npm import parse_npm
from exposuregate.lockfiles.poetry import parse_poetry
from exposuregate.lockfiles.requirements import parse_requirements
from exposuregate.lockfiles.uv import parse_uv
from exposuregate.models import ParsedLockfile

PARSERS: dict[str, Callable[..., ParsedLockfile]] = {
    "requirements": parse_requirements,
    "poetry": parse_poetry,
    "uv": parse_uv,
    "npm": parse_npm,
}

ECOSYSTEM = {"requirements": "PyPI", "poetry": "PyPI", "uv": "PyPI", "npm": "npm"}

_MANIFESTS = ("pyproject.toml", "package.json")


def classify(path: str, cfg: Config) -> str:
    """Classify a repo-relative path as a lockfile type or a non-lockfile category."""
    norm = path.replace("\\", "/")
    if any(fnmatchcase(norm, pat) for pat in cfg.excluded_paths):
        return "excluded"
    base = posixpath.basename(norm)
    for name, lf in cfg.lockfiles.items():
        if any(fnmatchcase(base, g) for g in lf.globs):
            return name if lf.enabled else "disabled"
    if any(fnmatchcase(base, g) for g in cfg.unsupported_globs):
        return "unsupported"
    if base in _MANIFESTS:
        return "manifest"
    return "ignore"


def parse(type: str, text: str, manifest_text: str | None = None) -> ParsedLockfile:
    """Parse lockfile text of the given type; only poetry uses manifest_text."""
    if type not in PARSERS:
        raise ValueError(f"unknown lockfile type: {type}")
    if type == "poetry":
        return parse_poetry(text, manifest_text)
    return PARSERS[type](text)

"""Configuration loading with strict validation (spec section 8)."""

from __future__ import annotations

import copy
import os
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

ACTIONS = ("block", "warn", "pass")
REPORT_FORMATS = ("json", "markdown")
CONFIG_FILENAME = ".exposuregate.yml"

DEFAULTS: dict[str, Any] = {
    "fail_closed": True,
    "data": {
        "dir": "~/.cache/exposuregate",
        "max_age_days": 7,
        "oebc_max_age_days": None,
        "osv_max_age_days": None,
    },
    "policy": {
        "CRITICAL": "block",
        "HIGH": "warn",
        "MEDIUM": "pass",
        "LOW": "pass",
        "not_in_oebc": "warn",
        "no_cve": "warn",
        "unparseable_version": "warn",
        "unpinned": "warn",
        "unsupported_lockfile": "warn",
        "transitive_max_action": "block",
    },
    "lockfiles": {
        "requirements": {"enabled": True, "globs": ["requirements*.txt"]},
        "poetry": {"enabled": True, "globs": ["poetry.lock"]},
        "uv": {"enabled": True, "globs": ["uv.lock"]},
        "npm": {"enabled": True, "globs": ["package-lock.json"]},
    },
    "unsupported_globs": [
        "yarn.lock", "pnpm-lock.yaml", "Pipfile.lock", "bun.lock", "bun.lockb",
        "Cargo.lock", "go.sum", "Gemfile.lock", "composer.lock", "gradle.lockfile",
    ],
    "exclusions": {"paths": []},
    "suppressions": [],
    "reporting": {"format": ["json", "markdown"], "output_dir": ".exposuregate/reports"},
}

_SUPPRESSION_KEYS = {"id", "reason", "expires", "package", "ecosystem"}


class ConfigError(Exception):
    """Invalid configuration (exit code 2)."""


@dataclass
class Suppression:
    id: str
    reason: str
    expires: date
    package: str | None = None
    ecosystem: str | None = None


@dataclass
class LockfileTypeConfig:
    enabled: bool
    globs: list[str]


@dataclass
class Config:
    fail_closed: bool
    data_dir: Path
    max_age_days: int
    oebc_max_age_days: int | None
    osv_max_age_days: int | None
    policy: dict[str, str]
    transitive_max_action: str
    lockfiles: dict[str, LockfileTypeConfig]
    unsupported_globs: list[str]
    excluded_paths: list[str]
    suppressions: list[Suppression]
    report_formats: list[str]
    output_dir: str | None

    def max_age(self, source: str) -> int:
        if source == "oebc":
            override = self.oebc_max_age_days
        elif source == "osv":
            override = self.osv_max_age_days
        else:
            raise ValueError(f"unknown data source: {source!r}")
        return self.max_age_days if override is None else override


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _str_list(v: Any, path: str) -> list[str]:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ConfigError(f"{path}: expected a list of strings")
    return list(v)


def _merge(default: Any, user: Any, path: str) -> Any:
    """Deep-merge user over default, rejecting unknown keys in dict sections."""
    if not isinstance(default, dict):
        return user
    if not isinstance(user, dict):
        raise ConfigError(f"{path or '<root>'}: expected a mapping")
    merged = copy.deepcopy(default)
    for key, value in user.items():
        kpath = f"{path}.{key}" if path else str(key)
        if key not in default:
            raise ConfigError(f"unknown key: {kpath}")
        merged[key] = _merge(default[key], value, kpath)
    return merged


def _validate_scalar_types(d: dict[str, Any]) -> None:
    if not isinstance(d["fail_closed"], bool):
        raise ConfigError("fail_closed: expected a boolean")
    data = d["data"]
    if not isinstance(data["dir"], str) or not data["dir"]:
        raise ConfigError("data.dir: expected a non-empty string")
    if not _is_int(data["max_age_days"]) or data["max_age_days"] < 0:
        raise ConfigError("data.max_age_days: expected a non-negative integer")
    for k in ("oebc_max_age_days", "osv_max_age_days"):
        v = data[k]
        if v is not None and (not _is_int(v) or v < 0):
            raise ConfigError(f"data.{k}: expected a non-negative integer or null")
    for k, v in d["policy"].items():
        if v not in ACTIONS:
            raise ConfigError(f"policy.{k}: invalid action {v!r}, expected one of {list(ACTIONS)}")
    for name, lf in d["lockfiles"].items():
        if not isinstance(lf["enabled"], bool):
            raise ConfigError(f"lockfiles.{name}.enabled: expected a boolean")
        _str_list(lf["globs"], f"lockfiles.{name}.globs")
    _str_list(d["unsupported_globs"], "unsupported_globs")
    _str_list(d["exclusions"]["paths"], "exclusions.paths")
    fmts = _str_list(d["reporting"]["format"], "reporting.format")
    for f in fmts:
        if f not in REPORT_FORMATS:
            raise ConfigError(
                f"reporting.format: invalid format {f!r}, expected one of {list(REPORT_FORMATS)}"
            )
    out = d["reporting"]["output_dir"]
    if out is not None and not isinstance(out, str):
        raise ConfigError("reporting.output_dir: expected a string or null")


def _parse_suppression(raw: Any, idx: int) -> Suppression:
    path = f"suppressions[{idx}]"
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected a mapping")
    for key in raw:
        if key not in _SUPPRESSION_KEYS:
            raise ConfigError(f"unknown key: {path}.{key}")
    for key in ("id", "reason", "expires"):
        if key not in raw or raw[key] is None:
            raise ConfigError(f"{path}.{key}: required")
    for key in ("id", "reason"):
        if not isinstance(raw[key], str) or not raw[key].strip():
            raise ConfigError(f"{path}.{key}: expected a non-empty string")
    for key in ("package", "ecosystem"):
        v = raw.get(key)
        if v is not None and (not isinstance(v, str) or not v):
            raise ConfigError(f"{path}.{key}: expected a non-empty string")
    exp = raw["expires"]
    if isinstance(exp, datetime):
        exp = exp.date()
    elif isinstance(exp, str):
        try:
            exp = date.fromisoformat(exp)
        except ValueError:
            raise ConfigError(f"{path}.expires: invalid date {exp!r}") from None
    elif not isinstance(exp, date):
        raise ConfigError(f"{path}.expires: expected a date (YYYY-MM-DD)")
    return Suppression(
        id=raw["id"], reason=raw["reason"], expires=exp,
        package=raw.get("package"), ecosystem=raw.get("ecosystem"),
    )


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise ConfigError(f"cannot read config {path}: {e}") from e
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    return loaded


def load_config(path: Path | None, cwd: Path) -> Config:
    user: dict[str, Any] = {}
    if path is not None:
        if not path.is_file():
            raise ConfigError(f"config file not found: {path}")
        user = _read_yaml(path)
    elif (cwd / CONFIG_FILENAME).is_file():
        user = _read_yaml(cwd / CONFIG_FILENAME)

    # Suppressions and lockfile entries are validated separately: lists are
    # replaced wholesale, and lockfile types are a closed set from the defaults.
    suppressions_raw = user.pop("suppressions", [])
    if not isinstance(suppressions_raw, list):
        raise ConfigError("suppressions: expected a list")
    merged = _merge({**DEFAULTS, "suppressions": None}, {**user, "suppressions": None}, "")
    merged["suppressions"] = suppressions_raw
    _validate_scalar_types(merged)

    env_dir = os.environ.get("EXPOSUREGATE_DATA_DIR")
    data = merged["data"]
    policy = dict(merged["policy"])
    transitive = policy.pop("transitive_max_action")
    return Config(
        fail_closed=merged["fail_closed"],
        data_dir=Path(env_dir or data["dir"]).expanduser(),
        max_age_days=data["max_age_days"],
        oebc_max_age_days=data["oebc_max_age_days"],
        osv_max_age_days=data["osv_max_age_days"],
        policy=policy,
        transitive_max_action=transitive,
        lockfiles={
            n: LockfileTypeConfig(enabled=lf["enabled"], globs=list(lf["globs"]))
            for n, lf in merged["lockfiles"].items()
        },
        unsupported_globs=list(merged["unsupported_globs"]),
        excluded_paths=list(merged["exclusions"]["paths"]),
        suppressions=[_parse_suppression(s, i) for i, s in enumerate(suppressions_raw)],
        report_formats=list(merged["reporting"]["format"]),
        output_dir=merged["reporting"]["output_dir"],
    )

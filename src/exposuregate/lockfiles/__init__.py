"""Lockfile parsers, keyed by lockfile type."""

from __future__ import annotations

from collections.abc import Callable

from exposuregate.models import ParsedLockfile

PARSERS: dict[str, Callable[..., ParsedLockfile]] = {}

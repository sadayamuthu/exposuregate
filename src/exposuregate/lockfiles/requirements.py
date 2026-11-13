"""Parser for ``requirements*.txt`` files (spec section 5.1)."""

from __future__ import annotations

import re

from packaging.requirements import InvalidRequirement, Requirement

from exposuregate.models import LockfileError, ParsedLockfile, Pin
from exposuregate.versions import normalize_name

_INLINE_COMMENT = re.compile(r"(?:^|\s)#(.*)$")
_HASH_OPTION = re.compile(r"(?:^|\s)--hash(?:=|\s+)\S+")
_EGG = re.compile(r"[#&]egg=([^&\s]+)")
_VIA = re.compile(r"^via\b(.*)$", re.IGNORECASE)
_INCLUDE_REF = re.compile(r"^-[rc](?:\s|=|$)")
_EDITABLE = ("-e", "--editable")


class _Entry:
    def __init__(self, text: str) -> None:
        self.text = text
        self.comments: list[str] = []


def _logical_entries(text: str) -> list[_Entry]:
    """Join continuations, strip comments, attach comment lines to the preceding requirement."""
    entries: list[_Entry] = []
    current: _Entry | None = None
    parts: list[str] | None = None
    comments: list[str] = []

    def finish(parts_: list[str], comments_: list[str]) -> _Entry | None:
        joined = _HASH_OPTION.sub("", " ".join(parts_)).strip()
        if not joined:
            return None
        first = joined.split(None, 1)[0]
        if joined.startswith("-") and first not in _EDITABLE:
            return None  # option line (-i, -r, -c, --index-url, ...)
        entry = _Entry(joined)
        entry.comments.extend(comments_)
        entries.append(entry)
        return entry

    for raw in text.splitlines():
        line = raw.strip()
        if parts is None and not line:
            current = None
            continue
        if parts is None and line.startswith("#"):
            if current is not None:
                current.comments.append(line[1:].strip())
            continue
        match = _INLINE_COMMENT.search(line)
        if match:
            comments.append(match.group(1).strip())
            line = line[: match.start()].rstrip()
        if line.endswith("\\"):
            parts = (parts or []) + [line[:-1].strip()]
            continue
        current = finish((parts or []) + [line], comments)
        parts, comments = None, []
    if parts is not None:
        finish(parts, comments)
    return entries


def _dependency_kind(comments: list[str]) -> str:
    """pip-compile ``# via`` rules: no via or any -r/-c reference is direct."""
    for i, comment in enumerate(comments):
        match = _VIA.match(comment)
        if not match:
            continue
        rest = match.group(1)
        sources = [rest] if rest.strip() else comments[i + 1 :]
        items = [s.strip() for src in sources for s in src.split(",") if s.strip()]
        return "direct" if any(_INCLUDE_REF.match(item) for item in items) else "transitive"
    return "direct"


def _pin_for(entry: _Entry) -> Pin:
    line = entry.text
    dependency = _dependency_kind(entry.comments)
    body = line.split(None, 1)[1] if line.split(None, 1)[0] in _EDITABLE and " " in line else line
    req: Requirement | None
    try:
        req = Requirement(body)
    except InvalidRequirement:
        req = None
    marker = str(req.marker) if req is not None and req.marker is not None else None
    if req is not None and req.url is None and not line.startswith("-"):
        specs = list(req.specifier)
        if len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
            return Pin(
                "PyPI",
                normalize_name("PyPI", req.name),
                specs[0].version,
                dependency,
                marker=marker,
            )
    if req is not None:
        name = normalize_name("PyPI", req.name)
    else:
        egg = _EGG.search(line)
        name = normalize_name("PyPI", egg.group(1)) if egg else line
    return Pin("PyPI", name, "", dependency, marker=marker, unpinned_spec=line)


def parse_requirements(text: str | bytes) -> ParsedLockfile:
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LockfileError(
                "lockfile_parse", f"requirements file is not valid UTF-8: {exc}"
            ) from exc
    text = text.removeprefix("﻿")
    pins = [_pin_for(entry) for entry in _logical_entries(text)]
    return ParsedLockfile(type="requirements", ecosystem="PyPI", pins=pins, skipped=[])

"""Git inputs for scan (spec 4.1): changed paths and blob reads at a ref or the index."""

from __future__ import annotations

import subprocess
from pathlib import Path

from exposuregate.models import LockfileError

INDEX = ":"


class GitError(Exception):
    """A git command failed (not a repository, bad ref, unreadable object)."""


def _git(args: list[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    try:
        proc = subprocess.run(
            ["git", "--literal-pathspecs", *args], cwd=cwd, capture_output=True, check=False
        )
    except OSError as e:
        raise GitError(f"cannot run git: {e}") from e
    if check and proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise GitError(f"git {' '.join(args)} failed: {err}")
    return proc


def _names(raw: bytes) -> list[str]:
    return sorted({p.decode("utf-8", "surrogateescape") for p in raw.split(b"\0") if p})


def repo_root(cwd: Path) -> Path:
    proc = _git(["rev-parse", "--show-toplevel"], cwd, check=False)
    if proc.returncode != 0:
        raise GitError(f"not a git repository: {cwd}")
    return Path(proc.stdout.decode().strip()).resolve()


def _has_commit(ref: str, cwd: Path) -> bool:
    proc = _git(["rev-parse", "--verify", "-q", f"{ref}^{{commit}}"], cwd, check=False)
    return proc.returncode == 0


def rev_parse(ref: str, cwd: Path) -> str:
    if not _has_commit(ref, cwd):
        raise GitError(f"unknown git revision: {ref}")
    return _git(["rev-parse", f"{ref}^{{commit}}"], cwd).stdout.decode().strip()


def _diff(old: str, new: str, cwd: Path) -> list[str]:
    return _names(_git(["diff", "--name-only", "--no-renames", "-z", old, new], cwd).stdout)


def changed_files(
    mode: str,
    cwd: Path,
    target_branch: str = "main",
    base: str | None = None,
    head: str | None = None,
) -> tuple[list[str], str | None, str]:
    """Repo-relative changed paths plus the old and new refs to read them at."""
    root = repo_root(cwd)
    if mode == "pre-commit":
        if not _has_commit("HEAD", root):
            # Unborn branch: every staged file is new; there is no old side.
            return _names(_git(["ls-files", "-z"], root).stdout), None, INDEX
        staged = _git(["diff", "--cached", "--name-only", "--no-renames", "-z"], root).stdout
        return _names(staged), "HEAD", INDEX
    if mode == "pr":
        target = target_branch
        if not _has_commit(target, root) and _has_commit(f"origin/{target}", root):
            # CI checkouts (e.g. actions/checkout) only have the remote-tracking branch.
            target = f"origin/{target}"
        rev_parse(target, root)
        proc = _git(["merge-base", target, "HEAD"], root, check=False)
        if proc.returncode != 0:
            raise GitError(f"no merge base between {target} and HEAD")
        mb = proc.stdout.decode().strip()
        return _diff(mb, "HEAD", root), mb, "HEAD"
    if mode == "explicit":
        if base is None or head is None:
            raise GitError("explicit mode needs both base and head")
        rev_parse(base, root)
        rev_parse(head, root)
        return _diff(base, head, root), base, head
    raise ValueError(f"unknown git mode: {mode}")


def tracked_files(cwd: Path) -> list[str]:
    """Files tracked by git under cwd, relative to cwd."""
    repo_root(cwd)
    return _names(_git(["ls-files", "-z"], cwd).stdout)


def _blob_sha(ref: str, path: str, cwd: Path) -> str | None:
    if ref == INDEX:
        listing = _git(["ls-files", "-s", "-z", "--", path], cwd).stdout
        # "<mode> <sha> <stage>\t<path>"
        entries = [e.split(b"\t", 1)[0].split() for e in listing.split(b"\0") if e]
        shas = [e[1] for e in entries if len(e) == 3 and e[2] == b"0"]
    else:
        listing = _git(["ls-tree", "-z", ref, "--", path], cwd).stdout
        # "<mode> <type> <sha>\t<path>"
        entries = [e.split(b"\t", 1)[0].split() for e in listing.split(b"\0") if e]
        shas = [e[2] for e in entries if len(e) == 3 and e[1] == b"blob"]
    return shas[0].decode() if shas else None


def blob_exists(ref: str | None, path: str, cwd: Path) -> bool:
    """Whether path exists at ref (``":"`` = index), without reading or decoding it."""
    return ref is not None and _blob_sha(ref, path, cwd) is not None


def read_blob(ref: str | None, path: str, cwd: Path) -> str | None:
    """Text of path at ref (``":"`` = index); None when ref is None or path is absent there."""
    if ref is None:
        return None
    sha = _blob_sha(ref, path, cwd)
    if sha is None:
        return None
    side = "index" if ref == INDEX else ref
    proc = _git(["cat-file", "blob", sha], cwd, check=False)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise GitError(f"cannot read {path} at {side}: {err}")
    try:
        return proc.stdout.decode("utf-8")
    except UnicodeDecodeError as e:
        raise LockfileError("lockfile_parse", f"{path} at {side} is not UTF-8") from e

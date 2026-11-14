import subprocess
from pathlib import Path

import pytest

from exposuregate.gitio import GitError, changed_files, read_blob, repo_root


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *args],
        cwd=cwd, check=True, capture_output=True, text=True,
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "user.name", "Test")
    git(r, "config", "user.email", "test@example.invalid")
    return r


def write(repo: Path, rel: str, text: str) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_not_a_repo_raises(tmp_path):
    with pytest.raises(GitError):
        changed_files("pre-commit", tmp_path)


def test_precommit_without_head(repo):
    write(repo, "a/uv.lock", "x")
    git(repo, "add", ".")
    paths, old, new = changed_files("pre-commit", repo)
    assert paths == ["a/uv.lock"] and old is None and new == ":"
    assert read_blob(old, "a/uv.lock", repo) is None
    assert read_blob(new, "a/uv.lock", repo) == "x"


def test_precommit_with_head_reads_both_sides(repo):
    write(repo, "uv.lock", "old")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "c1")
    write(repo, "uv.lock", "new")
    write(repo, "other.txt", "unstaged")
    git(repo, "add", "uv.lock")
    paths, old, new = changed_files("pre-commit", repo)
    assert paths == ["uv.lock"] and old == "HEAD" and new == ":"
    assert read_blob(old, "uv.lock", repo) == "old"
    assert read_blob(new, "uv.lock", repo) == "new"
    assert read_blob("HEAD", "missing.lock", repo) is None


def test_pr_mode_merge_base(repo):
    write(repo, "a.txt", "1")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "-qb", "feature")
    write(repo, "b.txt", "2")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "feature")
    git(repo, "checkout", "-q", "main")
    write(repo, "c.txt", "3")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "main moves on")
    git(repo, "checkout", "-q", "feature")
    paths, old, new = changed_files("pr", repo, target_branch="main")
    assert paths == ["b.txt"] and old == base and new == "HEAD"


def test_explicit_refs_and_bad_ref(repo):
    write(repo, "a.txt", "1")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "c1")
    write(repo, "a.txt", "2")
    git(repo, "commit", "-qam", "c2")
    paths, old, new = changed_files("explicit", repo, base="HEAD~1", head="HEAD")
    assert paths == ["a.txt"] and (old, new) == ("HEAD~1", "HEAD")
    with pytest.raises(GitError):
        changed_files("explicit", repo, base="nope", head="HEAD")
    with pytest.raises(GitError):
        changed_files("pr", repo, target_branch="nope")


def test_unreadable_blob_raises_git_error(repo):
    write(repo, "uv.lock", "content")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "c1")
    sha = git(repo, "rev-parse", "HEAD:uv.lock")
    (repo / ".git" / "objects" / sha[:2] / sha[2:]).unlink()
    with pytest.raises(GitError, match="uv.lock"):
        read_blob("HEAD", "uv.lock", repo)


def test_repo_root_from_subdir(repo):
    (repo / "sub").mkdir()
    assert repo_root(repo / "sub") == repo.resolve()

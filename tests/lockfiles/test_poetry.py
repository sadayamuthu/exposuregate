from __future__ import annotations

from pathlib import Path

import pytest

from exposuregate.lockfiles.poetry import parse_poetry
from exposuregate.models import LockfileError, Pin, Skipped

FIX = Path(__file__).parent.parent / "fixtures" / "lockfiles" / "poetry"
V1_LOCK = (FIX / "v1" / "poetry.lock").read_text()
V1_MANIFEST = (FIX / "v1" / "pyproject.toml").read_text()
V2_LOCK = (FIX / "v2" / "poetry.lock").read_text()
V2_MANIFEST = (FIX / "v2" / "pyproject.toml").read_text()


def pins(lock: str, manifest: str | None) -> dict[str, Pin]:
    return {p.name: p for p in parse_poetry(lock, manifest).pins}


def test_direct_from_tool_poetry_dependencies() -> None:
    p = pins(V1_LOCK, V1_MANIFEST)
    assert p["requests"] == Pin("PyPI", "requests", "2.31.0", "direct")
    assert "python" not in p


def test_direct_from_groups_and_dev_dependencies() -> None:
    p = pins(V1_LOCK, V1_MANIFEST)
    assert p["pytest"].dependency == "direct"
    manifest = "[tool.poetry.dev-dependencies]\npytest = '^8'\n"
    assert pins(V1_LOCK, manifest)["pytest"].dependency == "direct"


def test_direct_from_project_dependencies_pep508() -> None:
    p = pins(V2_LOCK, V2_MANIFEST)
    assert p["fastapi"].dependency == "direct"
    assert p["pytest"].dependency == "direct"  # optional-dependencies


def test_others_transitive() -> None:
    assert pins(V1_LOCK, V1_MANIFEST)["certifi"].dependency == "transitive"
    assert pins(V2_LOCK, V2_MANIFEST)["starlette"].dependency == "transitive"


def test_no_manifest_all_unknown() -> None:
    parsed = parse_poetry(V1_LOCK, None)
    assert parsed.type == "poetry"
    assert parsed.ecosystem == "PyPI"
    assert {p.dependency for p in parsed.pins} == {"unknown"}


def test_invalid_manifest_is_unknown() -> None:
    assert {p.dependency for p in parse_poetry(V1_LOCK, "= not toml [").pins} == {"unknown"}


def test_git_directory_file_url_sources_skipped() -> None:
    parsed = parse_poetry(V1_LOCK, V1_MANIFEST)
    assert parsed.skipped == [
        Skipped("git-tool", "source:git"),
        Skipped("local-pkg", "source:directory"),
        Skipped("file-pkg", "source:file"),
        Skipped("url-pkg", "source:url"),
    ]
    names = {p.name for p in parsed.pins}
    assert not names & {"git-tool", "local-pkg", "file-pkg", "url-pkg"}


def test_legacy_source_graded_with_source_field() -> None:
    p = pins(V1_LOCK, V1_MANIFEST)
    assert p["internal-lib"].source == "legacy"
    assert p["internal-lib"].dependency == "direct"
    assert p["requests"].source is None


def test_invalid_toml_raises_lockfile_parse() -> None:
    with pytest.raises(LockfileError) as exc:
        parse_poetry("= not toml [", None)
    assert exc.value.code == "lockfile_parse"


def test_missing_version_raises_lockfile_parse() -> None:
    with pytest.raises(LockfileError) as exc:
        parse_poetry('[[package]]\nname = "x"\n', None)
    assert exc.value.code == "lockfile_parse"


def test_missing_name_raises_lockfile_parse() -> None:
    with pytest.raises(LockfileError) as exc:
        parse_poetry('[[package]]\nversion = "1"\n', None)
    assert exc.value.code == "lockfile_parse"

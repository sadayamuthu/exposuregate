from __future__ import annotations

from pathlib import Path

import pytest

from exposuregate.lockfiles.uv import parse_uv
from exposuregate.models import LockfileError, Pin, Skipped

FIX = Path(__file__).parent.parent / "fixtures" / "lockfiles" / "uv"
SINGLE = (FIX / "single" / "uv.lock").read_text()
WORKSPACE = (FIX / "workspace" / "uv.lock").read_text()


def pins(text: str) -> dict[str, Pin]:
    return {p.name: p for p in parse_uv(text).pins}


def test_registry_packages_graded() -> None:
    parsed = parse_uv(SINGLE)
    assert parsed.type == "uv"
    assert parsed.ecosystem == "PyPI"
    assert pins(SINGLE)["idna"] == Pin("PyPI", "idna", "3.7", "transitive")
    assert not parsed.skipped or all(s.package == "demo-app" for s in parsed.skipped)


def test_root_dependencies_direct_rest_transitive() -> None:
    p = pins(SINGLE)
    assert p["fastapi"].dependency == "direct"
    assert p["starlette"].dependency == "transitive"
    assert p["anyio"].dependency == "transitive"


def test_optional_and_dev_dependencies_direct() -> None:
    p = pins(SINGLE)
    assert p["click"].dependency == "direct"
    assert p["pytest"].dependency == "direct"


def test_workspace_members_are_roots_not_pins() -> None:
    parsed = parse_uv(WORKSPACE)
    names = {p.name for p in parsed.pins}
    assert names == {"certifi", "requests"}
    assert Skipped("core", "source:workspace") in parsed.skipped
    assert Skipped("web", "source:workspace") in parsed.skipped
    assert Skipped("ws-root", "source:workspace") in parsed.skipped
    p = pins(WORKSPACE)
    assert p["requests"].dependency == "direct"  # listed by member `core`
    assert p["certifi"].dependency == "transitive"


def test_git_path_directory_url_skipped() -> None:
    text = """version = 1
[[package]]
name = "a"
version = "1.0"
source = { git = "https://github.com/x/a?rev=abc#abc" }
[[package]]
name = "b"
version = "1.0"
source = { path = "../b.whl" }
[[package]]
name = "c"
version = "1.0"
source = { directory = "../c" }
[[package]]
name = "d"
version = "1.0"
source = { url = "https://example.com/d.whl" }
[[package]]
name = "e"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
"""
    parsed = parse_uv(text)
    assert [(s.package, s.reason) for s in parsed.skipped] == [
        ("a", "source:git"),
        ("b", "source:path"),
        ("c", "source:directory"),
        ("d", "source:url"),
    ]
    assert [p.name for p in parsed.pins] == ["e"]


def test_same_name_two_versions_two_pins() -> None:
    text = """version = 1
[[package]]
name = "Numpy"
version = "1.26.4"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "numpy"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
"""
    parsed = parse_uv(text)
    assert [(p.name, p.version) for p in parsed.pins] == [("numpy", "1.26.4"), ("numpy", "2.0.0")]


def test_invalid_toml_raises() -> None:
    with pytest.raises(LockfileError) as ei:
        parse_uv("version = [")
    assert ei.value.code == "lockfile_parse"


def test_registry_entry_without_version_raises() -> None:
    text = '[[package]]\nname = "a"\nsource = { registry = "https://pypi.org/simple" }\n'
    with pytest.raises(LockfileError):
        parse_uv(text)

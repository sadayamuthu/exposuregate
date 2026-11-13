from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from exposuregate.lockfiles.npm import parse_npm
from exposuregate.models import LockfileError, Pin, Skipped

FIX = Path(__file__).parent.parent / "fixtures" / "lockfiles" / "npm"
V3 = (FIX / "v3" / "package-lock.json").read_text()
V2 = (FIX / "v2" / "package-lock.json").read_text()
V1 = (FIX / "v1" / "package-lock.json").read_text()


def pins(text: str) -> dict[tuple[str, str], Pin]:
    return {p.key: p for p in parse_npm(text).pins}


def lock(packages: dict[str, Any], version: int = 3) -> str:
    return json.dumps({"lockfileVersion": version, "packages": packages})


def reg(version: str, **extra: Any) -> dict[str, Any]:
    return {"version": version, "resolved": "https://registry.npmjs.org/x.tgz", **extra}


def test_v3_names_from_key_last_segment() -> None:
    parsed = parse_npm(V3)
    assert parsed.type == "npm"
    assert parsed.ecosystem == "npm"
    p = pins(V3)
    assert ("b", "2.0.0") in p
    assert ("b", "1.0.0") in p
    assert ("@scope/pkg", "5.0.0") in p
    assert p[("b", "2.0.0")].paths == ("node_modules/a/node_modules/b",)


def test_alias_uses_name_field() -> None:
    p = pins(V3)
    assert ("strip-ansi", "6.0.1") in p
    assert ("strip", "6.0.1") not in p
    assert p[("strip-ansi", "6.0.1")].dependency == "direct"


def test_direct_requires_top_level_key_and_root_declaration() -> None:
    p = pins(V3)
    assert p[("a", "1.0.0")].dependency == "direct"
    assert p[("dev-tool", "4.1.0")].dependency == "direct"
    # nested under a package: transitive even though a root might declare the name
    assert p[("b", "2.0.0")].dependency == "transitive"
    # top-level but not declared by any root
    assert p[("b", "1.0.0")].dependency == "transitive"


def test_nested_same_name_as_root_declaration_is_transitive() -> None:
    text = lock(
        {
            "": {"dependencies": {"b": "^1"}},
            "node_modules/a": reg("1.0.0"),
            "node_modules/a/node_modules/b": reg("2.0.0"),
            "node_modules/b": reg("1.0.0"),
        }
    )
    p = pins(text)
    assert p[("b", "2.0.0")].dependency == "transitive"
    assert p[("b", "1.0.0")].dependency == "direct"


def test_same_name_version_at_many_paths_is_one_pin_with_all_paths() -> None:
    parsed = parse_npm(V3)
    shared = [p for p in parsed.pins if p.name == "shared"]
    assert len(shared) == 1
    assert shared[0].paths == (
        "node_modules/a/node_modules/shared",
        "node_modules/dev-tool/node_modules/shared",
        "node_modules/shared",
    )
    assert shared[0].dependency == "transitive"
    assert shared[0].dev_only is False


def test_many_paths_direct_if_any_path_direct() -> None:
    text = lock(
        {
            "": {"dependencies": {"s": "^1"}},
            "node_modules/x/node_modules/s": reg("1.0.0"),
            "node_modules/s": reg("1.0.0"),
            "node_modules/y/node_modules/s": reg("1.0.0"),
        }
    )
    (pin,) = [p for p in parse_npm(text).pins if p.name == "s"]
    assert len(pin.paths) == 3
    assert pin.dependency == "direct"


def test_link_skipped() -> None:
    parsed = parse_npm(V3)
    assert Skipped("pkg-a", "source:link") in parsed.skipped
    assert not any(p.name == "pkg-a" for p in parsed.pins)


def test_non_registry_resolved_skipped() -> None:
    parsed = parse_npm(V3)
    assert Skipped("gitdep", "source:git") in parsed.skipped
    assert Skipped("local-dep", "source:file") in parsed.skipped
    assert not any(p.name in ("gitdep", "local-dep") for p in parsed.pins)


@pytest.mark.parametrize(
    ("resolved", "reason"),
    [
        ("git+https://h/r.git#x", "source:git"),
        ("git://h/r.git#x", "source:git"),
        ("file:../x", "source:file"),
        ("http://h/x.tgz", "source:url"),
        ("ftp://h/x.tgz", "source:url"),
    ],
)
def test_skip_reason_by_scheme(resolved: str, reason: str) -> None:
    parsed = parse_npm(lock({"node_modules/x": {"version": "1.0.0", "resolved": resolved}}))
    assert parsed.skipped == [Skipped("x", reason)]
    assert parsed.pins == []


def test_dev_only_recorded() -> None:
    p = pins(V3)
    assert p[("dev-tool", "4.1.0")].dev_only is True
    assert p[("dev-only-helper", "0.9.0")].dev_only is True
    assert p[("a", "1.0.0")].dev_only is False


def test_in_bundle_graded() -> None:
    p = pins(V3)
    assert ("bundled", "1.1.0") in p
    assert p[("bundled", "1.1.0")].dev_only is False


def test_missing_resolved_graded() -> None:
    assert ("x", "1.0.0") in pins(lock({"node_modules/x": {"version": "1.0.0"}}))


def test_workspace_root_declarations_count_as_direct() -> None:
    p = pins(V3)
    assert p[("ws-dep", "2.0.1")].dependency == "direct"
    assert p[("ws-dev", "1.0.0")].dependency == "direct"
    assert not any("packages/a" in path for pin in p.values() for path in pin.paths)
    assert "pkg-a" not in {n for n, _ in p}


def test_peer_and_optional_declarations_direct() -> None:
    text = lock(
        {
            "": {"peerDependencies": {"p": "*"}, "optionalDependencies": {"o": "*"}},
            "node_modules/p": reg("1.0.0"),
            "node_modules/o": reg("1.0.0"),
        }
    )
    p = pins(text)
    assert p[("p", "1.0.0")].dependency == "direct"
    assert p[("o", "1.0.0")].dependency == "direct"


def test_v2_supported() -> None:
    parsed = parse_npm(V2)
    assert {p.key for p in parsed.pins} == {("a", "1.0.0"), ("b", "2.0.0"), ("b", "1.0.0")}


def test_v1_raises_lockfile_unsupported() -> None:
    with pytest.raises(LockfileError) as exc:
        parse_npm(V1)
    assert exc.value.code == "lockfile_unsupported"


def test_missing_lockfile_version_raises_lockfile_unsupported() -> None:
    with pytest.raises(LockfileError) as exc:
        parse_npm(json.dumps({"packages": {}}))
    assert exc.value.code == "lockfile_unsupported"


def test_invalid_json_raises_lockfile_parse() -> None:
    with pytest.raises(LockfileError) as exc:
        parse_npm("{not json")
    assert exc.value.code == "lockfile_parse"


def test_non_object_and_missing_packages_raise_parse() -> None:
    for text in ("[]", json.dumps({"lockfileVersion": 3})):
        with pytest.raises(LockfileError) as exc:
            parse_npm(text)
        assert exc.value.code == "lockfile_parse"


def test_entry_without_version_raises_parse() -> None:
    with pytest.raises(LockfileError) as exc:
        parse_npm(lock({"node_modules/x": {"resolved": "https://r/x.tgz"}}))
    assert exc.value.code == "lockfile_parse"

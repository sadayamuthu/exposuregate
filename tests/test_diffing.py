from __future__ import annotations

import json

from exposuregate.diffing import changed_pins
from exposuregate.lockfiles import parse
from exposuregate.models import ParsedLockfile


def req(text: str) -> ParsedLockfile:
    return parse("requirements", text)


def uv(version: str, extra: str) -> str:
    return f'''version = 1
[[package]]
name = "idna"
version = "{version}"
source = {{ registry = "https://pypi.org/simple" }}
{extra}
'''


def npm(version: str, resolved: str, integrity: str) -> str:
    return json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "r", "dependencies": {"left-pad": "^1"}},
                "node_modules/left-pad": {
                    "version": version,
                    "resolved": resolved,
                    "integrity": integrity,
                },
            },
        }
    )


def test_new_file_all_pins_changed() -> None:
    out = changed_pins(None, req("b==2.0\na==1.0\n"))
    assert [(c.pin.name, c.pin.version, c.previous_version) for c in out] == [
        ("a", "1.0", None),
        ("b", "2.0", None),
    ]


def test_version_bump_has_previous_version() -> None:
    out = changed_pins(req("a==1.0\n"), req("a==1.1\n"))
    assert [(c.pin.version, c.previous_version) for c in out] == [("1.1", "1.0")]


def test_previous_version_is_lowest_other_version() -> None:
    out = changed_pins(req("a==1.10\na==1.9\n"), req("a==2.0\n"))
    assert out[0].previous_version == "1.9"


def test_removed_pins_ignored() -> None:
    assert changed_pins(req("a==1.0\nb==1.0\n"), req("a==1.0\n")) == []


def test_unchanged_relock_yields_nothing_uv() -> None:
    old = parse("uv", uv("3.7", 'sdist = { url = "https://x/a.tar.gz", hash = "sha256:aa" }'))
    new = parse("uv", uv("3.7", 'sdist = { url = "https://y/b.tar.gz", hash = "sha256:bb" }'))
    assert changed_pins(old, new) == []


def test_unchanged_relock_yields_nothing_npm() -> None:
    old = parse("npm", npm("1.0.0", "https://r1/x.tgz", "sha512-aaa"))
    new = parse("npm", npm("1.0.0", "https://r2/x.tgz", "sha512-bbb"))
    assert old.pins
    assert changed_pins(old, new) == []


def test_name_case_change_is_not_a_change() -> None:
    assert changed_pins(req("PyYAML==6.0\n"), req("pyyaml==6.0\n")) == []


def test_unpinned_spec_change_is_a_change() -> None:
    out = changed_pins(req("a>=1\n"), req("a>=2\n"))
    assert len(out) == 1
    assert out[0].pin.unpinned_spec
    assert out[0].previous_version is None


def test_unpinned_to_pinned_has_no_previous_version() -> None:
    out = changed_pins(req("a>=1\n"), req("a==1.0\n"))
    assert [(c.pin.version, c.previous_version) for c in out] == [("1.0", None)]


def test_pinned_to_unpinned_previous_none() -> None:
    out = changed_pins(req("a==1.0\n"), req("a>=1\n"))
    assert len(out) == 1 and out[0].previous_version is None


def test_unparseable_versions_fall_back_lexicographic() -> None:
    out = changed_pins(req("a===zzz\na===bbb\n"), req("a==2.0\n"))
    assert out[0].previous_version == "bbb"

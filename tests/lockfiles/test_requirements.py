from __future__ import annotations

from pathlib import Path

import pytest

from exposuregate.lockfiles.requirements import parse_requirements
from exposuregate.models import LockfileError, Pin

FIXTURE = (
    Path(__file__).parent.parent / "fixtures" / "lockfiles" / "requirements" / "pip-compile.txt"
)


def by_name(text: str) -> dict[str, Pin]:
    return {p.name: p for p in parse_requirements(text).pins}


def test_pinned_with_extras_and_hashes() -> None:
    parsed = parse_requirements(FIXTURE.read_text())
    assert parsed.type == "requirements"
    assert parsed.ecosystem == "PyPI"
    assert parsed.skipped == []
    pins = {p.name: p for p in parsed.pins}
    assert pins["requests"] == Pin("PyPI", "requests", "2.32.0", "direct")
    assert len(parsed.pins) == 7


def test_pip_compile_fixture_dependency_kinds() -> None:
    pins = {p.name: p for p in parse_requirements(FIXTURE.read_text()).pins}
    assert pins["urllib3"].dependency == "transitive"
    assert pins["certifi"].dependency == "transitive"
    assert pins["pyyaml"].dependency == "direct"
    assert pins["pysocks"].marker == 'python_version < "3.11"'


def test_triple_equals_pinned() -> None:
    pin = by_name("foo===1.2.3\n")["foo"]
    assert pin.version == "1.2.3"
    assert pin.unpinned_spec is None


def test_marker_recorded() -> None:
    pin = by_name("colorama==0.4.6 ; python_version < '3.11'\n")["colorama"]
    assert pin.marker == 'python_version < "3.11"'
    assert pin.version == "0.4.6"


def test_via_only_package_is_transitive() -> None:
    pin = by_name("urllib3==2.0.0\n    # via requests\n")["urllib3"]
    assert pin.dependency == "transitive"


def test_via_inline_comment_forms() -> None:
    pins = by_name("a==1  # via b\nc==1  # via -r requirements.in, d\n")
    assert pins["a"].dependency == "transitive"
    assert pins["c"].dependency == "direct"


def test_via_with_dash_r_is_direct_even_with_packages() -> None:
    text = "foo==1.0\n    # via\n    #   -r requirements.in\n    #   bar\n"
    assert by_name(text)["foo"].dependency == "direct"
    text = "foo==1.0\n    # via\n    #   -c constraints.txt\n    #   bar\n"
    assert by_name(text)["foo"].dependency == "direct"


def test_via_multiline_packages_only_is_transitive() -> None:
    text = "foo==1.0\n    # via\n    #   bar\n    #   baz\n"
    assert by_name(text)["foo"].dependency == "transitive"


def test_via_does_not_leak_to_next_requirement() -> None:
    text = "foo==1.0\n    # via bar\nbaz==2.0\n"
    pins = by_name(text)
    assert pins["foo"].dependency == "transitive"
    assert pins["baz"].dependency == "direct"


def test_no_via_is_direct() -> None:
    assert by_name("foo==1.0\n")["foo"].dependency == "direct"


@pytest.mark.parametrize(
    ("line", "name"),
    [
        ("requests>=2", "requests"),
        ("flask", "flask"),
        ("-e .", "-e ."),
        ("git+https://example.invalid/x.git#egg=x", "x"),
        ("-e git+https://example.invalid/Y_z.git#egg=Y_z", "y-z"),
        ("pkg @ https://example.invalid/pkg.whl", "pkg"),
        ("foo==1.*", "foo"),
        ("foo>=1,<2", "foo"),
        ("not a requirement!!", "not a requirement!!"),
    ],
)
def test_unpinned_forms(line: str, name: str) -> None:
    parsed = parse_requirements(line + "\n")
    assert len(parsed.pins) == 1
    pin = parsed.pins[0]
    assert pin.name == name
    assert pin.version == ""
    assert pin.unpinned_spec == line


def test_unpinned_spec_strips_hashes_comments_and_joins_continuations() -> None:
    text = "requests>=2 \\\n    --hash=sha256:abc  \\\n    --hash=sha256:def\n    # via -r in\n"
    pin = by_name(text)["requests"]
    assert pin.unpinned_spec == "requests>=2"
    assert pin.dependency == "direct"
    pin = by_name("flask  # a comment\n")["flask"]
    assert pin.unpinned_spec == "flask"


def test_unpinned_follows_via_rules() -> None:
    assert by_name("flask\n    # via bar\n")["flask"].dependency == "transitive"


def test_option_lines_ignored() -> None:
    text = (
        "-i https://pypi.org/simple\n"
        "--index-url https://pypi.org/simple\n"
        "--extra-index-url https://x.invalid/simple\n"
        "-r other.txt\n"
        "-c c.txt\n"
        "--no-binary :all:\n"
        "--hash=sha256:abc\n"
        "\n# just a comment\n"
    )
    assert parse_requirements(text).pins == []


def test_name_normalized() -> None:
    assert "pyyaml" in by_name("PyYAML==6.0\n")
    assert "zope-interface" in by_name("zope.interface==6.0\n")


def test_undecodable_input_raises() -> None:
    with pytest.raises(LockfileError) as exc:
        parse_requirements(b"\xff\xfe\x00bad")
    assert exc.value.code == "lockfile_parse"


def test_crlf_and_bom() -> None:
    pins = by_name("﻿foo==1.0\r\nbar==2.0\r\n")
    assert set(pins) == {"foo", "bar"}

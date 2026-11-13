import pytest

from exposuregate.models import make_finding_id
from exposuregate.versions import InvalidVersion, compare, normalize_name, parse_version


def test_normalize_pypi():
    assert normalize_name("PyPI", "Zope.Interface__x") == "zope-interface-x"


def test_normalize_npm_keeps_case_and_scope():
    assert normalize_name("npm", "@Scope/Pkg") == "@Scope/Pkg"


def test_pep440_order():
    assert compare("PyPI", "1.0rc1", "1.0") < 0 and compare("PyPI", "1.0.post1", "1.0") > 0


def test_semver_prerelease_precedence():
    chain = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
             "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"]
    assert all(compare("npm", a, b) < 0 for a, b in zip(chain, chain[1:], strict=False))
    assert all(compare("npm", b, a) > 0 for a, b in zip(chain, chain[1:], strict=False))


def test_semver_numeric_not_lexicographic():
    assert compare("npm", "1.2.10", "1.2.9") > 0


def test_semver_build_metadata_ignored_and_v_prefix():
    assert compare("npm", "v1.2.3+abc", "1.2.3") == 0


def test_invalid_versions_raise():
    with pytest.raises(InvalidVersion):
        parse_version("npm", "1.2")
    with pytest.raises(InvalidVersion):
        parse_version("PyPI", "not a version")


def test_finding_id_stable():
    a = make_finding_id("uv.lock", "PyPI", "starlette", "0.1", "CVE-1", "graded")
    assert a == make_finding_id("uv.lock", "PyPI", "starlette", "0.1", "CVE-1", "graded")
    assert len(a) == 64
    assert a != make_finding_id("uv.lock", "PyPI", "starlette", "0.1", "CVE-2", "graded")

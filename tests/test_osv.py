import json
from datetime import date
from pathlib import Path

import pytest

from exposuregate.osv import Match, cve_ids, match
from exposuregate.versions import InvalidVersion

NOW = date(2026, 11, 14)
FIX = Path(__file__).parent / "fixtures" / "osv"


def rec(name="pkg", eco="PyPI", ranges=None, versions=None, **extra):
    aff = {"package": {"ecosystem": eco, "name": name}}
    if ranges is not None:
        aff["ranges"] = ranges
    if versions is not None:
        aff["versions"] = versions
    return {"id": "GHSA-aaaa-bbbb-cccc", "affected": [aff], **extra}


def rng(*events, type="ECOSYSTEM"):
    return {"type": type, "events": list(events)}


def m(record, version, eco="PyPI", name="pkg"):
    return match(record, eco, name, version, NOW)


def test_versions_list_hit():
    r = rec(versions=["1.0.0", "1.1.0"])
    assert m(r, "1.1.0") == Match("GHSA-aaaa-bbbb-cccc", [])
    assert m(r, "1.2.0") is None


def test_versions_list_compared_as_pep440():
    assert m(rec(versions=["1.0.0"]), "1.0") is not None


def test_versions_list_unparseable_entry_string_equality():
    r = rec(versions=["weird-1", "1.0"])
    assert m(r, "1.0") is not None


def test_versions_list_npm_string_equality_strips_v():
    r = rec(eco="npm", versions=["v1.2.3"])
    assert m(r, "1.2.3", eco="npm") is not None
    assert m(r, "1.2.4", eco="npm") is None
    assert m(r, "not-a-version", eco="npm") is None  # no parse needed


def test_range_introduced_fixed():
    r = rec(ranges=[rng({"introduced": "1.0"}, {"fixed": "2.0"})])
    assert m(r, "0.9") is None
    assert m(r, "1.0") is not None
    assert m(r, "1.5") is not None
    assert m(r, "2.0") is None


def test_introduced_zero():
    r = rec(ranges=[rng({"introduced": "0"}, {"fixed": "0.5"})])
    assert m(r, "0.0.1") is not None
    assert m(r, "0.5") is None


def test_last_affected_inclusive():
    r = rec(ranges=[rng({"introduced": "0"}, {"last_affected": "1.4"})])
    assert m(r, "1.4") is not None
    assert m(r, "1.4.1") is None


def test_multiple_ranges_union():
    r = rec(ranges=[
        rng({"introduced": "0"}, {"fixed": "1.0"}),
        rng({"introduced": "2.0"}, {"fixed": "2.5"}),
    ])
    assert m(r, "0.5") is not None
    assert m(r, "1.5") is None
    assert m(r, "2.1") is not None


def test_events_sorted_before_evaluation():
    r = rec(ranges=[rng({"fixed": "2.0"}, {"introduced": "1.0"})])
    assert m(r, "1.5") is not None
    assert m(r, "2.1") is None


def test_limit():
    r = rec(ranges=[rng({"introduced": "0"}, {"limit": "3.0"})])
    assert m(r, "2.9") is not None
    assert m(r, "3.0") is None


def test_git_range_ignored():
    r = rec(ranges=[rng({"introduced": "0"}, type="GIT")])
    assert m(r, "1.0") is None
    assert m(r, "not a version") is None  # nothing to evaluate -> no raise


def test_ecosystem_and_git_ranges_together():
    r = rec(ranges=[rng({"introduced": "0"}, type="GIT"),
                    rng({"introduced": "0"}, {"fixed": "1.0"})])
    assert m(r, "0.5") is not None


def test_semver_npm_range():
    r = rec(eco="npm", ranges=[rng({"introduced": "1.0.0"}, {"fixed": "1.2.0-rc.1"},
                                   type="SEMVER")])
    assert m(r, "1.2.0-beta", eco="npm") is not None
    assert m(r, "1.2.0", eco="npm") is None


def test_withdrawn_before_now_skipped():
    r = rec(versions=["1.0"], withdrawn="2026-11-01T00:00:00Z")
    assert m(r, "1.0") is None
    r = rec(versions=["1.0"], withdrawn="2026-11-14T10:00:00Z")
    assert m(r, "1.0") is None


def test_withdrawn_after_now_still_matches():
    r = rec(versions=["1.0"], withdrawn="2026-12-01T00:00:00Z")
    assert m(r, "1.0") is not None


def test_other_ecosystem_ignored():
    assert m(rec(eco="npm", versions=["1.0"]), "1.0") is None


def test_name_normalized_both_sides():
    r = rec(name="Django", versions=["4.2"])
    assert m(r, "4.2", name="django") is not None
    r = rec(name="zope.interface", versions=["5.0"])
    assert m(r, "5.0", name="Zope_Interface") is not None


def test_npm_names_exact():
    assert m(rec(eco="npm", name="Vite", versions=["1.0.0"]), "1.0.0",
             eco="npm", name="vite") is None


def test_fixed_in_collected():
    r = rec(ranges=[
        rng({"introduced": "0"}, {"fixed": "1.5"}),
        rng({"introduced": "0"}, {"fixed": "1.2"}),
        rng({"introduced": "3.0"}, {"fixed": "3.1"}),
    ])
    assert m(r, "1.0") == Match("GHSA-aaaa-bbbb-cccc", ["1.2", "1.5"])


def test_fixed_in_sorted_by_version_not_string():
    r = rec(ranges=[rng({"introduced": "0"}, {"fixed": "10.0"}),
                    rng({"introduced": "0"}, {"fixed": "9.0"})])
    assert m(r, "1.0").fixed_in == ["9.0", "10.0"]


def test_fixed_in_when_matched_via_versions_list_only():
    r = rec(versions=["2.0"], ranges=[rng({"introduced": "0"}, {"fixed": "1.0"}),
                                      rng({"introduced": "3.0"}, {"fixed": "3.1"})])
    assert m(r, "2.0").fixed_in == ["1.0", "3.1"]


def test_multiple_affected_entries_union():
    r = rec(ranges=[rng({"introduced": "0"}, {"fixed": "1.0"})])
    r["affected"].append({"package": {"ecosystem": "PyPI", "name": "PKG"},
                          "ranges": [rng({"introduced": "2.0"}, {"fixed": "2.2"})]})
    assert m(r, "2.1").fixed_in == ["2.2"]
    assert m(r, "0.1").fixed_in == ["1.0"]


def test_unparseable_event_version_skips_range():
    r = rec(ranges=[rng({"introduced": "0"}, {"fixed": "garbage!"}),
                    rng({"introduced": "0"}, {"fixed": "1.0"})])
    assert m(r, "0.5").fixed_in == ["1.0"]


def test_unparseable_pin_version_raises():
    r = rec(ranges=[rng({"introduced": "0"}, {"fixed": "1.0"})])
    with pytest.raises(InvalidVersion):
        m(r, "not a version")


def test_unparseable_pin_pypi_versions_list_raises():
    with pytest.raises(InvalidVersion):
        m(rec(versions=["1.0"]), "not a version")


def test_unparseable_pin_other_package_no_raise():
    r = rec(name="other", ranges=[rng({"introduced": "0"})])
    assert m(r, "not a version") is None


def test_cve_ids_from_id_and_aliases():
    r = {"id": "GHSA-x", "aliases": ["CVE-2026-48710", "PYSEC-x"]}
    assert cve_ids(r) == ["CVE-2026-48710"]
    assert cve_ids({"id": "CVE-2024-1234", "aliases": ["CVE-2024-1234", "CVE-2023-99999"]}) == [
        "CVE-2023-99999", "CVE-2024-1234"]


def test_cve_ids_empty_when_none():
    assert cve_ids({"id": "GHSA-x", "aliases": ["PYSEC-1", "CVE-12-1"]}) == []
    assert cve_ids({"id": "GHSA-x"}) == []


def load(name):
    return json.loads((FIX / name).read_text())


def test_real_pysec():
    r = load("pysec_real.json")
    assert cve_ids(r) == ["CVE-2005-4644"]
    assert match(r, "PyPI", "Trac", "0.9", NOW) is not None
    assert match(r, "PyPI", "trac", "0.10", NOW) is None


def test_real_ghsa_starlette():
    r = load("ghsa_starlette_real.json")
    assert cve_ids(r) == ["CVE-2025-54121"]
    mt = match(r, "PyPI", "starlette", "0.40.0", NOW)
    assert mt is not None and mt.fixed_in == ["0.47.2"]
    assert match(r, "PyPI", "starlette", "0.47.2", NOW) is None


def test_real_ghsa_vite():
    r = load("ghsa_vite_real.json")
    assert cve_ids(r) == ["CVE-2023-34092"]
    mt = match(r, "npm", "vite", "3.1.0", NOW)
    assert mt is not None and mt.fixed_in == ["3.2.7"]
    assert match(r, "npm", "vite", "3.2.7", NOW) is None

from dataclasses import replace
from datetime import date, datetime, timezone

import pytest

from exposuregate.config import load_config
from exposuregate.grading import (
    apply_policy,
    expired_suppressions,
    grade,
    unsupported_finding,
    verdict,
)
from exposuregate.models import ChangedPin, Denial, Pin
from exposuregate.store import DataMeta, MemoryStore, SourceMeta

NOW = date(2026, 11, 14)


def adv(id_, name, cves=(), eco="PyPI", fixed="9.9", introduced="0"):
    return {
        "id": id_,
        "aliases": list(cves),
        "affected": [
            {
                "package": {"ecosystem": eco, "name": name},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": introduced}, {"fixed": fixed}]}
                ],
            }
        ],
    }


def row(tier, kev=False):
    return {
        "exposure_tier": tier, "kev_listed": kev, "kev_date_added": "2022-03-01" if kev else None,
        "epss_score": 0.5, "cvss_score": 9.0,
    }


def store():
    advs = {
        ("PyPI", "kevpkg"): [adv("PYSEC-1", "kevpkg", ["CVE-2020-0001"])],
        ("PyPI", "highpkg"): [adv("PYSEC-2", "highpkg", ["CVE-2020-0002"])],
        ("PyPI", "medpkg"): [adv("PYSEC-3", "medpkg", ["CVE-2020-0003"])],
        ("PyPI", "lowpkg"): [adv("PYSEC-4", "lowpkg", ["CVE-2020-0004"])],
        ("PyPI", "unknown"): [adv("PYSEC-5", "unknown", ["CVE-2020-9999"])],
        ("PyPI", "nocve"): [adv("GHSA-6", "nocve")],
        ("PyPI", "twice"): [
            adv("PYSEC-7", "twice", ["CVE-2020-0001"], fixed="2.0"),
            adv("GHSA-7", "twice", ["CVE-2020-0001"], fixed="3.0"),
        ],
    }
    oebc = {
        "CVE-2020-0001": row("CRITICAL", True),
        "CVE-2020-0002": row("HIGH"),
        "CVE-2020-0003": row("MEDIUM"),
        "CVE-2020-0004": row("LOW"),
    }
    meta = DataMeta(SourceMeta("oebc", datetime(2026, 11, 10, tzinfo=timezone.utc), 4), {})
    return MemoryStore(meta, advs, oebc)


def cfg(tmp_path, text=""):
    p = tmp_path / "c.yml"
    p.write_text(text)
    return load_config(p, tmp_path)


def cp(name, version="1.0", dep="direct", prev=None, **kw):
    return ChangedPin(Pin("PyPI", name, version, dep, **kw), prev)


def g(tmp_path, pin, text=""):
    return grade("uv.lock", [pin], store(), cfg(tmp_path, text), NOW)


def test_kev_cve_blocks(tmp_path):
    (f,) = g(tmp_path, cp("kevpkg", prev="0.9"))
    assert (f.reason, f.action, f.base_action) == ("graded", "block", "block")
    assert f.cve_id == "CVE-2020-0001" and f.kev_listed and f.exposure_tier == "CRITICAL"
    assert f.kev_date_added == "2022-03-01" and f.epss_score == 0.5 and f.cvss_score == 9.0
    assert f.fixed_in == ["9.9"] and f.previous_version == "0.9" and f.version == "1.0"
    assert f.advisory_ids == ["PYSEC-1"]


def test_high_warns(tmp_path):
    (f,) = g(tmp_path, cp("highpkg"))
    assert f.action == "warn"


def test_medium_low_pass_but_reported(tmp_path):
    for n in ("medpkg", "lowpkg"):
        (f,) = g(tmp_path, cp(n))
        assert f.action == "pass" and f.reason == "graded"


def test_not_in_oebc_warns(tmp_path):
    (f,) = g(tmp_path, cp("unknown"))
    assert (f.reason, f.action) == ("not_in_oebc", "warn")
    assert (f.exposure_tier, f.kev_listed) == (None, False)


def test_no_cve_warns(tmp_path):
    (f,) = g(tmp_path, cp("nocve"))
    assert (f.reason, f.action, f.cve_id, f.advisory_ids) == ("no_cve", "warn", None, ["GHSA-6"])


def test_unparseable_version_warns_once(tmp_path):
    s = store()
    s._adv[("PyPI", "kevpkg")].append(adv("PYSEC-X", "kevpkg", ["CVE-2020-0001"]))
    fs = grade("uv.lock", [cp("kevpkg", "not a version")], s, cfg(tmp_path), NOW)
    assert len(fs) == 1 and fs[0].reason == "unparseable_version" and fs[0].action == "warn"


def test_unpinned_warns(tmp_path):
    pin = ChangedPin(Pin("PyPI", "foo", "", "direct", unpinned_spec=">=1"), None)
    (f,) = g(tmp_path, pin)
    assert (f.reason, f.action, f.version) == ("unpinned", "warn", ">=1")


def test_unsupported_finding_warns(tmp_path):
    f = unsupported_finding("yarn.lock", cfg(tmp_path))
    assert (f.reason, f.action, f.package, f.version) == ("unsupported_lockfile", "warn", "", "")
    f2 = unsupported_finding("yarn.lock", cfg(tmp_path, "policy:\n  unsupported_lockfile: block\n"))
    assert f2.action == "block"


def test_two_advisories_same_cve_one_finding_merged_ids(tmp_path):
    (f,) = g(tmp_path, cp("twice"))
    assert f.advisory_ids == ["GHSA-7", "PYSEC-7"] and f.fixed_in == ["2.0", "3.0"]


def test_policy_overrides_apply(tmp_path):
    (f,) = g(tmp_path, cp("highpkg"), "policy:\n  HIGH: block\n")
    assert f.action == "block"
    (f,) = g(tmp_path, cp("kevpkg"), "policy:\n  CRITICAL: warn\n")
    assert f.action == "warn"
    (f,) = g(tmp_path, cp("unknown"), "policy:\n  not_in_oebc: block\n")
    assert f.action == "block"


@pytest.mark.parametrize(
    ("key", "pin", "default"),
    [
        ("CRITICAL", cp("kevpkg"), "block"),
        ("HIGH", cp("highpkg"), "warn"),
        ("MEDIUM", cp("medpkg"), "pass"),
        ("LOW", cp("lowpkg"), "pass"),
        ("not_in_oebc", cp("unknown"), "warn"),
        ("no_cve", cp("nocve"), "warn"),
        ("unparseable_version", cp("highpkg", version="not.a.version!"), "warn"),
        ("unpinned", cp("highpkg", version=""), "warn"),
    ],
)
def test_every_policy_key_overrides_behaviour(tmp_path, key, pin, default):
    (f,) = g(tmp_path, pin)
    assert f.action == default
    other = "pass" if default != "pass" else "block"
    (f,) = g(tmp_path, pin, f"policy:\n  {key}: {other}\n")
    assert f.action == other


def test_policy_unsupported_lockfile_override(tmp_path):
    for action in ("pass", "warn", "block"):
        c = cfg(tmp_path, f"policy:\n  unsupported_lockfile: {action}\n")
        assert unsupported_finding("yarn.lock", c).action == action


def test_notes(tmp_path):
    (f,) = g(tmp_path, cp("highpkg", marker="python_version<'3.9'", source="legacy", dev_only=True))
    assert f.notes == ["marker: python_version<'3.9'", "source: legacy", "dev_only"]


def test_transitive_cap(tmp_path):
    text = "policy:\n  transitive_max_action: warn\n"
    (f,) = g(tmp_path, cp("kevpkg", dep="transitive"), text)
    assert (f.action, f.base_action) == ("warn", "block")
    (f,) = g(tmp_path, cp("kevpkg", dep="direct"), text)
    assert f.action == "block"
    (f,) = g(tmp_path, cp("medpkg", dep="transitive"), text)
    assert f.action == "pass"


def sup(text):
    return f"suppressions:\n  - {text}\n"


def test_suppression_unexpired(tmp_path):
    c = sup("{id: CVE-2020-0001, reason: ok, expires: 2026-11-14}")
    (f,) = g(tmp_path, cp("kevpkg"), c)
    assert (f.action, f.suppressed_by, f.base_action) == ("pass", "CVE-2020-0001", "block")
    c = sup("{id: PYSEC-1, reason: ok, expires: 2027-01-01, package: KEVPKG, ecosystem: PyPI}")
    (f,) = g(tmp_path, cp("kevpkg"), c)
    assert f.suppressed_by == "PYSEC-1"


def test_suppression_expired_reported_and_warns(tmp_path):
    c = cfg(tmp_path, sup("{id: CVE-2020-0001, reason: old, expires: 2026-11-13}"))
    fs = grade("uv.lock", [cp("kevpkg")], store(), c, NOW)
    assert fs[0].action == "block" and fs[0].suppressed_by is None
    rep, extra = expired_suppressions(fs, c, NOW)
    assert rep == [{"id": "CVE-2020-0001", "package": "", "ecosystem": "", "reason": "old",
                    "expires": "2026-11-13"}]
    (e,) = extra
    assert e.reason == "suppression_expired" and e.action == "warn" and e.base_action == "warn"
    assert e.cve_id == "CVE-2020-0001" and "2026-11-13" in e.notes[0]
    assert len(e.finding_id) == 64


def test_renewed_suppression_after_expired_entry_suppresses_without_warning(tmp_path):
    c = cfg(tmp_path, sup("{id: CVE-2020-0001, reason: old, expires: 2026-11-13}")
            + "  - {id: CVE-2020-0001, reason: renewed, expires: 2027-01-01}\n")
    fs = grade("uv.lock", [cp("kevpkg")], store(), c, NOW)
    assert fs[0].action == "pass" and fs[0].suppressed_by == "CVE-2020-0001"
    rep, extra = expired_suppressions(fs, c, NOW)
    assert rep == [] and extra == []


def test_expired_suppression_advisory_id_and_unmatched(tmp_path):
    c = cfg(tmp_path, sup("{id: GHSA-6, reason: r, expires: 2026-01-01, package: nocve}")
            + "  - {id: CVE-1999-0001, reason: r, expires: 2026-01-01}\n")
    fs = grade("uv.lock", [cp("nocve")], store(), c, NOW)
    rep, extra = expired_suppressions(fs, c, NOW)
    assert [r["id"] for r in rep] == ["GHSA-6"]
    assert extra[0].cve_id is None and extra[0].advisory_ids == ["GHSA-6"]
    assert extra[0].package == "nocve"


def test_suppression_package_mismatch_no_effect(tmp_path):
    c = sup("{id: CVE-2020-0001, reason: ok, expires: 2027-01-01, package: other}")
    (f,) = g(tmp_path, cp("kevpkg"), c)
    assert f.action == "block" and f.suppressed_by is None
    c = sup("{id: CVE-2020-0001, reason: ok, expires: 2027-01-01, ecosystem: npm}")
    (f,) = g(tmp_path, cp("kevpkg"), c)
    assert f.action == "block"


def test_apply_policy_direct(tmp_path):
    (f,) = g(tmp_path, cp("kevpkg"))
    out = apply_policy(replace(f, action="block"), "transitive",
                       cfg(tmp_path, "policy:\n  transitive_max_action: pass\n"), NOW)
    assert out.action == "pass"


def test_verdict_precedence(tmp_path):
    fs = [g(tmp_path, cp(n))[0] for n in ("kevpkg", "highpkg", "medpkg")]
    assert verdict(fs, [], True) == ("BLOCK", 1)
    assert verdict(fs[1:], [], True) == ("WARN", 0)
    assert verdict(fs[2:], [], True) == ("PASS", 0)
    assert verdict([], [], True) == ("PASS", 0)
    assert verdict(fs, [Denial("data_stale", "x")], True) == ("DENY", 2)


def test_fail_open_floor_warn(tmp_path):
    d = [Denial("data_stale", "x", enforced=False)]
    assert verdict([], d, False) == ("WARN", 0)
    assert verdict([], [Denial("data_stale", "x")], False) == ("WARN", 0)
    fs = g(tmp_path, cp("kevpkg"))
    assert verdict(fs, d, False) == ("BLOCK", 1)
    # a non-enforced denial never denies even when fail_closed
    assert verdict([], d, True) == ("WARN", 0)

import dataclasses

import pytest

from exposuregate.models import (
    ACTION_RANK,
    Denial,
    Finding,
    LockfileError,
    Pin,
    make_finding_id,
)


def test_action_rank():
    assert ACTION_RANK == {"pass": 0, "warn": 1, "block": 2}


def test_pin_key_and_frozen():
    p = Pin("PyPI", "a", "1.0", "direct")
    assert p.key == ("a", "1.0")
    assert Pin("PyPI", "a", "", "direct", unpinned_spec=">=1").key == ("a", ">=1")
    with pytest.raises(dataclasses.FrozenInstanceError):
        p.name = "b"  # type: ignore[misc]


def test_denial_to_dict():
    assert Denial("data_stale", "old").to_dict() == {
        "code": "data_stale", "detail": "old", "enforced": True}


def test_finding_to_dict_fields():
    f = Finding(
        finding_id="x", lockfile="uv.lock", ecosystem="PyPI", package="p", version="1",
        previous_version=None, dependency="direct", reason="graded", cve_id=None,
        advisory_ids=["GHSA-1"], exposure_tier=None, kev_listed=False, kev_date_added=None,
        epss_score=None, cvss_score=None, fixed_in=[], base_action="pass", action="pass",
        suppressed_by=None, notes=[],
    )
    d = f.to_dict()
    assert list(d) == [
        "finding_id", "lockfile", "ecosystem", "package", "version", "previous_version",
        "dependency", "reason", "cve_id", "advisory_ids", "exposure_tier", "kev_listed",
        "kev_date_added", "epss_score", "cvss_score", "fixed_in", "base_action", "action",
        "suppressed_by", "notes"]
    assert d["advisory_ids"] == ["GHSA-1"]


def test_lockfile_error_code():
    assert LockfileError("lockfile_parse", "bad").code == "lockfile_parse"


def test_finding_id_known_value():
    import hashlib
    expected = hashlib.sha256(b"l|E|p|1|C|r").hexdigest()
    assert make_finding_id("l", "E", "p", "1", "C", "r") == expected

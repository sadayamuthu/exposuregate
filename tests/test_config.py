from datetime import date
from pathlib import Path

import pytest

from exposuregate.config import Config, ConfigError, load_config


def write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / ".exposuregate.yml"
    p.write_text(text)
    return p


@pytest.fixture(autouse=True)
def _no_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("EXPOSUREGATE_DATA_DIR", raising=False)


def test_defaults_match_spec(tmp_path: Path) -> None:
    cfg = load_config(None, tmp_path)
    assert cfg.policy == {
        "CRITICAL": "block", "HIGH": "warn", "MEDIUM": "pass", "LOW": "pass",
        "not_in_oebc": "warn", "no_cve": "warn", "unparseable_version": "warn",
        "unpinned": "warn", "unsupported_lockfile": "warn",
    }
    assert cfg.transitive_max_action == "block"
    assert cfg.max_age_days == 7
    assert cfg.fail_closed is True
    assert cfg.report_formats == ["json", "markdown"]
    assert cfg.output_dir == ".exposuregate/reports"
    assert cfg.data_dir == Path("~/.cache/exposuregate").expanduser()
    assert "yarn.lock" in cfg.unsupported_globs
    assert cfg.lockfiles["uv"].globs == ["uv.lock"]
    assert cfg.lockfiles["requirements"].enabled is True
    assert cfg.excluded_paths == []
    assert cfg.suppressions == []


def test_reads_dot_exposuregate_yml_from_cwd(tmp_path: Path) -> None:
    write(tmp_path, "fail_closed: false\n")
    assert load_config(None, tmp_path).fail_closed is False


def test_explicit_path(tmp_path: Path) -> None:
    p = tmp_path / "other.yml"
    p.write_text("data: {max_age_days: 3}\n")
    assert load_config(p, tmp_path).max_age_days == 3


def test_missing_explicit_path_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.yml", tmp_path)


def test_deep_merge_keeps_unspecified_defaults(tmp_path: Path) -> None:
    write(tmp_path, "policy: {HIGH: block}\nlockfiles: {npm: {enabled: false}}\n")
    cfg = load_config(None, tmp_path)
    assert cfg.policy["HIGH"] == "block"
    assert cfg.policy["CRITICAL"] == "block"
    assert cfg.policy["LOW"] == "pass"
    assert cfg.lockfiles["npm"].enabled is False
    assert cfg.lockfiles["npm"].globs == ["package-lock.json"]


def test_transitive_max_action_in_policy_block(tmp_path: Path) -> None:
    write(tmp_path, "policy: {transitive_max_action: warn}\n")
    cfg = load_config(None, tmp_path)
    assert cfg.transitive_max_action == "warn"
    assert "transitive_max_action" not in cfg.policy


def test_unknown_top_level_key_rejected(tmp_path: Path) -> None:
    write(tmp_path, "bogus: 1\n")
    with pytest.raises(ConfigError, match="bogus"):
        load_config(None, tmp_path)


def test_unknown_nested_key_rejected(tmp_path: Path) -> None:
    write(tmp_path, "policy: {CRTICAL: block}\n")
    with pytest.raises(ConfigError, match="policy.CRTICAL"):
        load_config(None, tmp_path)


def test_unknown_lockfile_type_rejected(tmp_path: Path) -> None:
    write(tmp_path, "lockfiles: {yarn: {enabled: true}}\n")
    with pytest.raises(ConfigError, match="lockfiles.yarn"):
        load_config(None, tmp_path)


def test_invalid_action_rejected(tmp_path: Path) -> None:
    write(tmp_path, "policy: {HIGH: deny}\n")
    with pytest.raises(ConfigError, match="policy.HIGH"):
        load_config(None, tmp_path)


def test_invalid_format_rejected(tmp_path: Path) -> None:
    write(tmp_path, "reporting: {format: [html]}\n")
    with pytest.raises(ConfigError, match="reporting.format"):
        load_config(None, tmp_path)


@pytest.mark.parametrize(
    "text",
    [
        "fail_closed: yes_please\n",
        "data: {max_age_days: '7'}\n",
        "data: {max_age_days: true}\n",
        "data: {max_age_days: -1}\n",
        "data: {oebc_max_age_days: 1.5}\n",
        "exclusions: {paths: foo}\n",
        "reporting: {output_dir: 5}\n",
        "lockfiles: {uv: {globs: uv.lock}}\n",
        "unsupported_globs: [1]\n",
        "- a\n",
    ],
)
def test_wrong_types_rejected(tmp_path: Path, text: str) -> None:
    write(tmp_path, text)
    with pytest.raises(ConfigError):
        load_config(None, tmp_path)


def test_invalid_yaml_rejected(tmp_path: Path) -> None:
    write(tmp_path, "a: [unclosed\n")
    with pytest.raises(ConfigError):
        load_config(None, tmp_path)


def test_empty_file_gives_defaults(tmp_path: Path) -> None:
    write(tmp_path, "")
    assert load_config(None, tmp_path).max_age_days == 7


def test_suppression_parsed(tmp_path: Path) -> None:
    write(
        tmp_path,
        "suppressions:\n  - id: CVE-1\n    package: urllib3\n    ecosystem: PyPI\n"
        "    reason: nope\n    expires: 2027-01-31\n"
        "  - {id: CVE-2, reason: r, expires: '2027-02-01'}\n",
    )
    s = load_config(None, tmp_path).suppressions
    assert s[0].expires == date(2027, 1, 31)
    assert (s[0].package, s[0].ecosystem) == ("urllib3", "PyPI")
    assert s[1].expires == date(2027, 2, 1)
    assert s[1].package is None


@pytest.mark.parametrize(
    "entry",
    [
        "{id: CVE-1, expires: 2027-01-01}",
        "{id: CVE-1, reason: r}",
        "{reason: r, expires: 2027-01-01}",
        "{id: CVE-1, reason: '', expires: 2027-01-01}",
        "{id: CVE-1, reason: r, expires: tomorrow}",
        "{id: CVE-1, reason: r, expires: 5}",
        "{id: CVE-1, reason: r, expires: 2027-01-01, extra: 1}",
    ],
)
def test_suppression_requires_reason_and_expires(tmp_path: Path, entry: str) -> None:
    write(tmp_path, f"suppressions: [{entry}]\n")
    with pytest.raises(ConfigError, match="suppressions"):
        load_config(None, tmp_path)


def test_per_source_max_age_override(tmp_path: Path) -> None:
    write(tmp_path, "data: {oebc_max_age_days: 30}\n")
    cfg = load_config(None, tmp_path)
    assert cfg.max_age("oebc") == 30
    assert cfg.max_age("osv") == 7
    with pytest.raises(ValueError):
        cfg.max_age("other")


def test_env_overrides_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write(tmp_path, "data: {dir: /from/file}\n")
    monkeypatch.setenv("EXPOSUREGATE_DATA_DIR", str(tmp_path / "envdir"))
    cfg: Config = load_config(None, tmp_path)
    assert cfg.data_dir == tmp_path / "envdir"


def test_data_dir_expands_tilde(tmp_path: Path) -> None:
    write(tmp_path, "data: {dir: ~/x}\n")
    assert load_config(None, tmp_path).data_dir == Path("~/x").expanduser()

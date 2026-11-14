"""End-to-end tests: temp git repos, fixture data, the CLI run in-process."""

import json
import shutil
import subprocess
import urllib.request
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from exposuregate.__main__ import main
from exposuregate.store import build_index

ROOT = Path(__file__).resolve().parent.parent
FIX = Path(__file__).resolve().parent / "fixtures"
SCHEMA = json.loads((ROOT / "schemas" / "report.schema.json").read_text())
OEBC = FIX / "oebc" / "mini.json.gz"
OSV = FIX / "osv"
DATA = ["--oebc", str(OEBC), "--osv-dir", str(OSV), "--as-of", "2026-11-13"]


def validated(report: dict[str, Any]) -> dict[str, Any]:
    """Every E2E JSON report must validate against the shipped schema."""
    jsonschema.validate(report, SCHEMA)
    return report


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *args],
        cwd=cwd, check=True, capture_output=True, text=True,
    ).stdout.strip()


def uv_lock(**pins: str) -> str:
    """A uv.lock whose workspace root depends directly on every given package."""
    deps = ", ".join(f'{{ name = "{n}" }}' for n in pins)
    out = [
        "version = 1",
        'requires-python = ">=3.10"',
        "",
        "[[package]]",
        'name = "app"',
        'version = "0.1.0"',
        'source = { editable = "." }',
        f"dependencies = [{deps}]",
    ]
    for name, version in pins.items():
        out += [
            "",
            "[[package]]",
            f'name = "{name}"',
            f'version = "{version}"',
            'source = { registry = "https://pypi.org/simple" }',
        ]
    return "\n".join(out) + "\n"


@pytest.fixture(autouse=True)
def _no_user_data(tmp_path, monkeypatch):
    monkeypatch.setenv("EXPOSUREGATE_DATA_DIR", str(tmp_path / "no-data-here"))


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "user.name", "Test")
    git(r, "config", "user.email", "test@example.invalid")
    return r


def put(repo: Path, rel: str, text: str, *, stage: bool = True) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    if stage:
        git(repo, "add", rel)


def commit(repo: Path, msg: str = "c") -> str:
    git(repo, "commit", "-qm", msg)
    return git(repo, "rev-parse", "HEAD")


def scan(capsys, *args: str) -> tuple[int, dict[str, Any]]:
    code = main(["scan", *args, "--format", "json"])
    out = capsys.readouterr().out
    return code, validated(json.loads(out))


def by_package(report: dict[str, Any], name: str) -> list[dict[str, Any]]:
    return [f for f in report["findings"] if f["package"] == name]


# ---- git modes -------------------------------------------------------------


def test_precommit_kev_direct_blocks_exit_1(repo, capsys):
    put(repo, "uv.lock", uv_lock(requests="2.32.0"))
    commit(repo)
    put(repo, "uv.lock", uv_lock(requests="2.32.0", litellm="1.30.0"))
    code, r = scan(capsys, "--path", str(repo), *DATA)
    assert code == 1 and r["verdict"] == "BLOCK" and r["exit_code"] == 1
    (f,) = by_package(r, "litellm")
    assert f["cve_id"] == "CVE-2024-0010" and f["kev_listed"] is True
    assert f["dependency"] == "direct" and f["action"] == "block"
    assert f["fixed_in"] == ["1.40.0"]
    assert r["input"]["mode"] == "pre-commit"
    assert r["lockfiles"] == [
        {"path": "uv.lock", "type": "uv", "status": "graded",
         "pins_added_or_changed": 1, "pins_skipped": 0}
    ]
    assert by_package(r, "requests") == []  # unchanged pin is not graded


def test_precommit_first_commit_no_head(repo, capsys):
    put(repo, "uv.lock", uv_lock(requests="2.32.0", litellm="1.30.0"))
    code, r = scan(capsys, "--path", str(repo), *DATA)
    assert code == 1
    assert [d["code"] for d in r["denials"]] == []
    assert r["lockfiles"][0]["pins_added_or_changed"] == 2
    assert {f["package"] for f in r["findings"]} == {"litellm", "requests"}


def test_pr_mode_uses_merge_base(repo, capsys):
    put(repo, "requirements.txt", "litellm==1.30.0\n")
    commit(repo, "base")
    git(repo, "checkout", "-qb", "feature")
    put(repo, "requirements.txt", "litellm==1.30.0\nsix==1.16.0\n")
    commit(repo, "feature adds six")
    git(repo, "checkout", "-q", "main")
    put(repo, "requirements.txt", "litellm==1.50.0\n")
    commit(repo, "main upgrades litellm after the branch point")
    git(repo, "checkout", "-q", "feature")
    code, r = scan(capsys, "--mode", "pr", "--target-branch", "main", "--path", str(repo), *DATA)
    assert code == 0 and r["verdict"] == "PASS"
    assert by_package(r, "litellm") == []
    assert r["lockfiles"][0]["pins_added_or_changed"] == 1
    assert r["input"]["base"] == git(repo, "merge-base", "main", "HEAD")


def test_explicit_base_head(repo, capsys):
    put(repo, "requirements.txt", "six==1.16.0\n")
    base = commit(repo)
    put(repo, "requirements.txt", "six==1.16.0\nlitellm==1.30.0\n")
    head = commit(repo)
    put(repo, "requirements.txt", "six==1.16.0\n")
    commit(repo, "revert later")
    code, r = scan(capsys, "--base", base, "--head", head, "--path", str(repo), *DATA)
    assert code == 1
    assert r["input"] == {"mode": "explicit", "base": base, "head": head}
    assert [f["package"] for f in r["findings"]] == ["litellm"]


def test_full_mode_grades_all_current_pins(repo, capsys):
    put(repo, "requirements.txt", "litellm==1.30.0\n")
    put(repo, "sub/uv.lock", uv_lock(requests="2.32.0"))
    commit(repo)
    put(repo, "untracked/uv.lock", uv_lock(django="1.0"), stage=False)
    code, r = scan(capsys, "--mode", "full", "--path", str(repo), *DATA)
    assert code == 1
    assert {(lf["path"], lf["pins_added_or_changed"]) for lf in r["lockfiles"]} == {
        ("requirements.txt", 1), ("sub/uv.lock", 1)
    }
    assert {f["package"] for f in r["findings"]} == {"litellm", "requests"}
    assert all(f["previous_version"] is None for f in r["findings"])


def test_full_mode_walks_non_git_dir(tmp_path, capsys):
    d = tmp_path / "plain"
    (d / "node_modules" / "x").mkdir(parents=True)
    (d / "requirements.txt").write_text("litellm==1.30.0\n")
    (d / "node_modules" / "x" / "requirements.txt").write_text("django==1.0\n")
    code, r = scan(capsys, "--mode", "full", "--path", str(d), *DATA)
    assert code == 1
    assert [lf["path"] for lf in r["lockfiles"]] == ["requirements.txt"]


def test_git_mode_outside_repo_is_usage_error(tmp_path, capsys):
    assert main(["scan", "--path", str(tmp_path), *DATA]) == 2
    assert "git" in capsys.readouterr().err


# ---- file mode and usage errors ------------------------------------------


def test_old_new_files_mode(tmp_path, capsys):
    old = tmp_path / "old.txt"
    new = tmp_path / "new.txt"
    old.write_text("litellm==1.20.0\n")
    new.write_text("litellm==1.30.0\n")
    code, r = scan(
        capsys, "--old", str(old), "--new", str(new), "--lockfile-type", "requirements", *DATA
    )
    assert code == 1
    (f,) = r["findings"]
    assert f["previous_version"] == "1.20.0" and f["lockfile"] == str(new)
    assert r["input"]["mode"] == "files"
    # --old may be omitted
    code, r = scan(capsys, "--new", str(new), "--lockfile-type", "requirements", *DATA)
    assert code == 1 and r["findings"][0]["previous_version"] is None


def test_poetry_manifest_flag_tags_direct(tmp_path, capsys):
    src = FIX / "lockfiles" / "poetry" / "v1"
    args = ["--new", str(src / "poetry.lock"), "--lockfile-type", "poetry", *DATA]
    _, without = scan(capsys, *args)
    _, with_manifest = scan(capsys, *args, "--manifest", str(src / "pyproject.toml"))
    assert [f["dependency"] for f in by_package(without, "requests")] == ["unknown"]
    assert [f["dependency"] for f in by_package(with_manifest, "requests")] == ["direct"]


def test_poetry_manifest_read_from_same_ref_in_git_mode(repo, capsys):
    src = FIX / "lockfiles" / "poetry" / "v1"
    put(repo, "py/poetry.lock", (src / "poetry.lock").read_text())
    put(repo, "py/pyproject.toml", (src / "pyproject.toml").read_text())
    _, r = scan(capsys, "--path", str(repo), *DATA)
    assert [f["dependency"] for f in by_package(r, "requests")] == ["direct"]
    assert [lf["path"] for lf in r["lockfiles"]] == ["py/poetry.lock"]


@pytest.mark.parametrize(
    "argv",
    [
        ["--new", "x.txt"],
        ["--old", "a", "--lockfile-type", "requirements"],
        ["--mode", "pr", "--new", "x", "--lockfile-type", "uv"],
        ["--mode", "full", "--base", "a", "--head", "b"],
        ["--base", "a"],
        ["--replay"],
        ["--as-of", "2026-13-01"],
        ["--lockfile-type", "uv"],
        ["--archive", "a", "--oebc", "b"],
    ],
)
def test_usage_errors_exit_2(argv, capsys):
    assert main(["scan", *argv]) == 2
    assert capsys.readouterr().err


def test_new_without_type_is_usage_error(tmp_path, capsys):
    new = tmp_path / "requirements.txt"
    new.write_text("six==1.16.0\n")
    assert main(["scan", "--new", str(new), *DATA]) == 2
    assert "--lockfile-type" in capsys.readouterr().err


def test_unknown_config_key_exit_2(repo, capsys):
    put(repo, ".exposuregate.yml", "bogus: 1\n")
    put(repo, "requirements.txt", "six==1.16.0\n")
    assert main(["scan", "--path", str(repo), *DATA]) == 2
    assert "bogus" in capsys.readouterr().err


# ---- data handling ---------------------------------------------------------


def test_no_lockfile_change_passes_without_data(repo, capsys):
    put(repo, "README.md", "hi\n")
    code, r = scan(capsys, "--path", str(repo))
    assert code == 0 and r["verdict"] == "PASS"
    assert r["denials"] == [] and r["data"] == {"oebc": None, "osv": {}}


def test_unchanged_pins_need_no_data(repo, capsys):
    put(repo, "uv.lock", uv_lock(six="1.16.0"))
    commit(repo)
    put(repo, "uv.lock", uv_lock(six="1.16.0") + "# trailing comment\n")
    code, r = scan(capsys, "--path", str(repo))
    assert code == 0 and r["denials"] == []
    assert r["lockfiles"][0]["status"] == "unchanged"


def test_stale_data_denies_exit_2(repo, capsys):
    put(repo, "requirements.txt", "six==1.16.0\n")
    code, r = scan(
        capsys, "--path", str(repo), "--oebc", str(OEBC), "--osv-dir", str(OSV),
        "--as-of", "2026-11-20",
    )
    assert code == 2 and r["verdict"] == "DENY"
    assert {d["code"] for d in r["denials"]} == {"data_stale"}
    assert all(d["enforced"] for d in r["denials"])


def test_fail_open_warns_exit_0(repo, capsys):
    put(repo, "requirements.txt", "six==1.16.0\n")
    stale = ["--oebc", str(OEBC), "--osv-dir", str(OSV), "--as-of", "2026-11-20"]
    code, r = scan(capsys, "--path", str(repo), *stale, "--fail-open")
    assert code == 0 and r["verdict"] == "WARN"
    assert r["denials"] and all(d["enforced"] is False for d in r["denials"])


def test_config_fail_closed_false_warns(repo, capsys):
    put(repo, ".exposuregate.yml", "fail_closed: false\n")
    put(repo, "requirements.txt", "six==1.16.0\n")
    stale = ["--oebc", str(OEBC), "--osv-dir", str(OSV), "--as-of", "2026-11-20"]
    code, r = scan(capsys, "--path", str(repo), *stale)
    assert code == 0 and r["verdict"] == "WARN"
    assert all(d["enforced"] is False for d in r["denials"])


def test_cli_max_age_days_overrides_config(repo, capsys):
    put(repo, ".exposuregate.yml", "data:\n  max_age_days: 7\n")
    put(repo, "requirements.txt", "six==1.16.0\n")
    ten_days = ["--oebc", str(OEBC), "--osv-dir", str(OSV), "--as-of", "2026-11-20"]
    code, r = scan(capsys, "--path", str(repo), *ten_days)
    assert code == 2 and r["data"]["oebc"]["age_days"] == 10
    code, r = scan(capsys, "--path", str(repo), *ten_days, "--max-age-days", "30")
    assert code == 0 and r["denials"] == []


def test_cli_max_age_days_keeps_per_source_override(repo, capsys):
    put(repo, ".exposuregate.yml", "data:\n  oebc_max_age_days: 5\n")
    put(repo, "requirements.txt", "six==1.16.0\n")
    ten_days = ["--oebc", str(OEBC), "--osv-dir", str(OSV), "--as-of", "2026-11-20"]
    code, r = scan(capsys, "--path", str(repo), *ten_days, "--max-age-days", "30")
    assert code == 2
    assert [d["detail"].split()[0] for d in r["denials"]] == ["OEBC"]


def make_data_dir(tmp_path: Path) -> Path:
    data = tmp_path / "data"
    build_index(OEBC, {"PyPI": OSV / "PyPI.zip", "npm": OSV / "npm.zip"}, data / "index.sqlite")
    (data / "manifest.json").write_text(json.dumps({
        "oebc": {"url": "https://oebc.example/latest.json.gz"},
        "osv": {"PyPI": {"url": "https://osv.example/PyPI/all.zip"},
                "npm": {"url": "https://osv.example/npm/all.zip"}},
    }))
    return data


def test_data_dir_store_grades_and_reports_sources(repo, tmp_path, capsys, monkeypatch):
    data = make_data_dir(tmp_path)
    monkeypatch.setenv("EXPOSUREGATE_DATA_DIR", str(data))
    put(repo, "requirements.txt", "litellm==1.30.0\n")
    code, r = scan(capsys, "--path", str(repo), "--as-of", "2026-11-13")
    assert code == 1
    assert r["data"]["oebc"]["source"] == "https://oebc.example/latest.json.gz"
    assert r["data"]["osv"]["PyPI"]["source"] == "https://osv.example/PyPI/all.zip"


def test_cli_data_dir_overrides_env(repo, tmp_path, capsys):
    data = make_data_dir(tmp_path)
    put(repo, "requirements.txt", "litellm==1.30.0\n")
    code, r = scan(capsys, "--path", str(repo), "--data-dir", str(data), "--as-of", "2026-11-13")
    assert code == 1 and r["denials"] == []


def test_file_sources_reported(repo, capsys):
    put(repo, "requirements.txt", "litellm==1.30.0\n")
    _, r = scan(capsys, "--path", str(repo), *DATA)
    assert r["data"]["oebc"]["source"] == str(OEBC)
    assert r["data"]["osv"]["PyPI"]["source"] == str(OSV)
    assert all(s["source"] for s in r["data"]["osv"].values())


def test_missing_data_dir_denies_data_missing(repo, capsys):
    put(repo, "requirements.txt", "six==1.16.0\n")
    code, r = scan(capsys, "--path", str(repo), "--as-of", "2026-11-13")
    assert code == 2 and [d["code"] for d in r["denials"]] == ["data_missing"]


def test_corrupt_index_denies_data_invalid(repo, tmp_path, capsys):
    data = tmp_path / "bad"
    data.mkdir()
    (data / "index.sqlite").write_bytes(b"this is not sqlite" * 100)
    put(repo, "requirements.txt", "six==1.16.0\n")
    code, r = scan(capsys, "--path", str(repo), "--data-dir", str(data), "--as-of", "2026-11-13")
    assert code == 2 and [d["code"] for d in r["denials"]] == ["data_invalid"]


@pytest.mark.parametrize("use_index", [False, True])
def test_as_of_drops_later_published_advisories(repo, tmp_path, capsys, use_index):
    # PYSEC-4 (requests) was published 2026-06-01.
    put(repo, "requirements.txt", "requests==2.0.0\n")
    if use_index:
        src = ["--data-dir", str(make_data_dir(tmp_path))]
    else:
        src = ["--oebc", str(OEBC), "--osv-dir", str(OSV)]
    _, now = scan(capsys, "--path", str(repo), *src, "--as-of", "2026-11-13")
    assert [f["advisory_ids"] for f in by_package(now, "requests")] == [["PYSEC-4"]]
    _, past = scan(capsys, "--path", str(repo), *src, "--as-of", "2026-05-01")
    assert by_package(past, "requests") == []
    assert "data_from_future" in {d["code"] for d in past["denials"]}


def test_scan_never_uses_network(repo, capsys, monkeypatch):
    def no_network(*a, **k):
        raise AssertionError("scan must not use the network")

    monkeypatch.setattr(urllib.request, "urlopen", no_network)
    put(repo, "uv.lock", uv_lock(litellm="1.30.0"))
    code, r = scan(capsys, "--path", str(repo), *DATA)
    assert code == 1 and r["findings"]


# ---- lockfile statuses -----------------------------------------------------


def test_parse_error_on_old_side_denies(repo, capsys):
    put(repo, "uv.lock", "this is [[ not toml\n")
    commit(repo)
    put(repo, "uv.lock", uv_lock(six="1.16.0"))
    code, r = scan(capsys, "--path", str(repo), *DATA)
    assert code == 2
    (d,) = r["denials"]
    assert d["code"] == "lockfile_parse" and "uv.lock" in d["detail"] and "old" in d["detail"]
    assert r["lockfiles"][0]["status"] == "parse_error"


def test_unreadable_blob_denies_git_error(repo, capsys):
    put(repo, "uv.lock", uv_lock(six="1.0"))
    commit(repo)
    sha = git(repo, "rev-parse", "HEAD:uv.lock")
    (repo / ".git" / "objects" / sha[:2] / sha[2:]).unlink()
    put(repo, "uv.lock", uv_lock(six="1.16.0"))
    code, r = scan(capsys, "--path", str(repo), *DATA)
    assert code == 2
    (d,) = r["denials"]
    assert d["code"] == "git_error" and "uv.lock" in d["detail"] and "old" in d["detail"]


def test_deleted_lockfile_contributes_nothing(repo, capsys):
    put(repo, "uv.lock", uv_lock(litellm="1.30.0"))
    commit(repo)
    git(repo, "rm", "-q", "uv.lock")
    code, r = scan(capsys, "--path", str(repo))
    assert code == 0 and r["findings"] == [] and r["denials"] == []
    assert r["lockfiles"][0]["pins_added_or_changed"] == 0


def test_unsupported_lockfile_warns(repo, capsys):
    put(repo, "web/yarn.lock", "# yarn\n")
    code, r = scan(capsys, "--path", str(repo))
    assert code == 0 and r["verdict"] == "WARN"
    assert r["lockfiles"] == [{"path": "web/yarn.lock", "type": None, "status": "unsupported"}]
    (f,) = r["findings"]
    assert f["reason"] == "unsupported_lockfile" and f["lockfile"] == "web/yarn.lock"


def test_manifest_only_listed_no_finding(repo, capsys):
    put(repo, "pyproject.toml", "[project]\nname='x'\n")
    put(repo, "web/package.json", "{}")
    put(repo, "web/package-lock.json", json.dumps(
        {"name": "w", "lockfileVersion": 3, "packages": {"": {"name": "w"}}}
    ))
    code, r = scan(capsys, "--path", str(repo))
    assert code == 0 and r["findings"] == []
    statuses = {lf["path"]: lf["status"] for lf in r["lockfiles"]}
    assert statuses["pyproject.toml"] == "manifest_only"
    assert "web/package.json" not in statuses  # its lockfile changed alongside


def test_excluded_and_disabled_listed(repo, capsys):
    put(repo, ".exposuregate.yml",
        "lockfiles:\n  npm: {enabled: false, globs: [package-lock.json]}\n"
        "exclusions:\n  paths: ['vendor/*']\n")
    put(repo, "vendor/uv.lock", uv_lock(litellm="1.30.0"))
    put(repo, "vendor/README.md", "x")
    put(repo, "package-lock.json", "{}")
    code, r = scan(capsys, "--path", str(repo))
    assert code == 0 and r["findings"] == []
    assert sorted((lf["path"], lf["type"], lf["status"]) for lf in r["lockfiles"]) == [
        ("package-lock.json", "npm", "disabled"),
        ("vendor/uv.lock", "uv", "excluded"),
    ]


# ---- output ---------------------------------------------------------------


def test_default_formats_json_then_markdown(repo, capsys):
    put(repo, "README.md", "hi\n")
    assert main(["scan", "--path", str(repo)]) == 0
    out = capsys.readouterr()
    assert out.out.lstrip().startswith("{")
    assert "# " in out.out.split("\n}\n", 1)[1]
    assert "PASS" in out.err


def test_output_dir_writes_both_reports(repo, tmp_path, capsys):
    put(repo, "uv.lock", uv_lock(litellm="1.30.0"))
    out = tmp_path / "out"
    code = main(["scan", "--path", str(repo), *DATA, "--output-dir", str(out)])
    assert code == 1
    report = validated(json.loads((out / "report.json").read_text()))
    assert report["verdict"] == "BLOCK"
    assert "BLOCK" in (out / "report.md").read_text()
    capsys.readouterr()


def test_report_has_timing_ms_keys(repo, capsys):
    put(repo, "uv.lock", uv_lock(litellm="1.30.0"))
    _, r = scan(capsys, "--path", str(repo), *DATA)
    assert set(r["timing_ms"]) == {"load_data", "read_lockfiles", "match", "total"}
    assert all(isinstance(v, int) and v >= 0 for v in r["timing_ms"].values())


def test_hook_and_action_files_exist():
    hooks = (ROOT / ".pre-commit-hooks.yaml").read_text()
    assert "entry: exposuregate scan --mode pre-commit" in hooks
    assert "pass_filenames: false" in hooks
    action = (ROOT / "docs" / "github-action.yml").read_text()
    assert "fetch-depth: 0" in action and "exposuregate update-data" in action
    assert "--target-branch ${{ github.base_ref }}" in action


def test_copy_of_repo_fixture_lockfile_grades(repo, capsys):
    shutil.copy(FIX / "lockfiles" / "uv" / "single" / "uv.lock", repo / "uv.lock")
    git(repo, "add", "uv.lock")
    code, r = scan(capsys, "--path", str(repo), *DATA)
    assert r["lockfiles"][0]["status"] == "graded" and code in (0, 1)

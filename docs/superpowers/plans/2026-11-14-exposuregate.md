# ExposureGate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build ExposureGate v0.1.0, a pre-commit / PR gate that grades every dependency version a change adds or changes in `requirements*.txt`, `poetry.lock`, `uv.lock` and `package-lock.json` using OSV (package → CVE) and OEBC (CVE → exposure tier), and returns PASS / WARN / BLOCK / DENY.

**Architecture:** Pure Python, offline at scan time. Lockfile parsers produce `Pin` sets; old and new sets are diffed; each changed pin is matched against OSV advisories from a `DataStore` (SQLite index built by `update-data`, or in-memory from pinned files / the archive); CVE aliases are graded with OEBC; policy, suppressions and freshness denials produce a verdict, a JSON report (schema-validated) and a Markdown report.

**Tech Stack:** Python ≥ 3.10, `pyyaml`, `packaging`, `tomli` (3.10 only); dev: `pytest`, `pytest-cov`, `ruff`, `mypy`, `jsonschema`. setuptools `src/` layout like ControlGate.

**Spec:** `docs/superpowers/specs/2026-11-14-exposuregate-design.md` (read it; section numbers below refer to it).

## Global Constraints

- Package `exposuregate`, version `0.1.0`, console script `exposuregate`, MIT, author "Karthikeyan Sadayamuthu", `requires-python = ">=3.10"`.
- Runtime deps only `pyyaml`, `packaging`, `tomli; python_version < "3.11"`. HTTP only via `urllib.request`, only in `update-data`.
- No network access in `scan`, ever (tests enforce by monkeypatching `urllib.request.urlopen` to raise in scan tests).
- Exit codes: 0 PASS/WARN, 1 BLOCK, 2 DENY or usage/config error (§4.2). Precedence DENY > BLOCK > WARN > PASS.
- Actions are lowercase `block|warn|pass` in config and findings; verdicts uppercase `PASS|WARN|BLOCK|DENY`.
- Default `max_age_days` = 7; default policy table exactly as §7.3 / §8.
- Every config key must change behaviour and have a test; unknown keys → exit 2 (anti-goal, §2).
- Every advisory match appears in the report, including `pass` and suppressed ones (anti-goal).
- Reports go to stdout (JSON then Markdown per `--format` order); progress to stderr.
- Commit messages: conventional style, **no AI co-author trailers**.
- `ruff check` and `mypy src` clean at the end of every task.

## Review Focus

1. **Lockfile that changed only in hashes/metadata** (e.g. `uv lock --upgrade` with no version moves, npm `resolved` URL change): expect zero changed pins and PASS, not findings for every package. → test in Task 7.
2. **Package renamed by case/punctuation between sides** (`PyYAML` → `pyyaml`, `zope.interface` → `zope-interface`): same normalized name, same version → not a change. → test in Task 7.
3. **Huge npm lockfile** (thousands of entries, same package at several nested paths): one pin per `(name, version)` with all paths merged, not one finding per path. → test in Task 6.
4. **Advisory affecting the package under a differently-cased/punctuated name in OSV** (`Django` vs `django`): matched after PEP 503 normalisation on both sides. → test in Task 8.
5. **Lockfile added in the first commit of a repo (no `HEAD`)** in pre-commit mode: old side empty, every pin graded, no `git_error`. → test in Task 13.

---

### File structure

```
pyproject.toml, README.md, LICENSE, CHANGELOG.md, .pre-commit-hooks.yaml
docs/github-action.yml
schemas/report.schema.json
src/exposuregate/
  __init__.py          __version__
  __main__.py          argparse CLI, main(argv) -> int
  models.py            Pin, ChangedPin, Skipped, ParsedLockfile, Finding, Denial, LockfileEntry, errors
  versions.py          name normalisation, PEP 440 / SemVer comparison
  config.py            Config, Suppression, load_config, ConfigError
  lockfiles/__init__.py   classify(path, cfg) and parse(type, text, manifest_text)
  lockfiles/requirements.py, poetry.py, uv.py, npm.py
  diffing.py           changed_pins(old, new)
  osv.py               cve_ids(record), match(record, ...)
  store.py             SourceMeta, DataMeta, DataStore protocol, MemoryStore, SqliteStore, build_index
  update.py            update-data / data-info
  freshness.py         check(...)
  grading.py           grade(...), apply_policy(...), verdict(...)
  report.py            build_report(...), to_json, to_markdown
  gitio.py             changed_files(...), read_blob(...)
  scan.py              run_scan(...) orchestration
  rebuild.py           rebuild-oebc
  archive.py           ArchiveStore (reads the paper/eval/archive layout)
tests/ (mirrors modules) + tests/fixtures/{lockfiles,osv,oebc,planted}/
```

---

### Task 1: Scaffold, models, version comparison

**Files:**
- Create: `pyproject.toml`, `LICENSE`, `README.md` (stub), `src/exposuregate/__init__.py`, `src/exposuregate/models.py`, `src/exposuregate/versions.py`
- Test: `tests/test_versions.py`, `tests/test_models.py`

**Interfaces:**
- Produces (`models.py`):
  - `ACTION_RANK = {"pass": 0, "warn": 1, "block": 2}`
  - `@dataclass(frozen=True) Pin(ecosystem: str, name: str, version: str, dependency: str, paths: tuple[str, ...] = (), source: str | None = None, marker: str | None = None, dev_only: bool = False, unpinned_spec: str | None = None)` — `name` already normalized; `dependency` ∈ `direct|transitive|unknown`; unpinned requirements have `version == ""` and `unpinned_spec` set. `Pin.key -> tuple[str, str]` = `(name, version or unpinned_spec)`.
  - `@dataclass(frozen=True) ChangedPin(pin: Pin, previous_version: str | None)`
  - `@dataclass(frozen=True) Skipped(package: str, reason: str)` (reason like `source:git`)
  - `@dataclass ParsedLockfile(type: str, ecosystem: str, pins: list[Pin], skipped: list[Skipped])`
  - `@dataclass Denial(code: str, detail: str, enforced: bool = True)`; `to_dict()`
  - `@dataclass Finding` with exactly the §9 finding fields (`finding_id, lockfile, ecosystem, package, version, previous_version, dependency, reason, cve_id, advisory_ids, exposure_tier, kev_listed, kev_date_added, epss_score, cvss_score, fixed_in, base_action, action, suppressed_by, notes`); `to_dict()`; `finding_id` = sha256 hex of `"|".join([lockfile, ecosystem, package, version, cve_id or advisory_id or "", reason])`, computed by `make_finding_id(...) -> str`.
  - `class LockfileError(Exception)` with `.code` ∈ `lockfile_parse|lockfile_unsupported`.
- Produces (`versions.py`): `normalize_name(ecosystem: str, name: str) -> str`; `parse_version(ecosystem: str, v: str) -> object` (raises `InvalidVersion`, re-export of `packaging.version.InvalidVersion`, for both ecosystems); `compare(ecosystem: str, a: str, b: str) -> int`.

- [ ] **Step 1: Write failing tests**

```python
def test_normalize_pypi():
    assert normalize_name("PyPI", "Zope.Interface__x") == "zope-interface-x"
def test_normalize_npm_keeps_case_and_scope():
    assert normalize_name("npm", "@Scope/Pkg") == "@Scope/Pkg"
def test_pep440_order():
    assert compare("PyPI", "1.0rc1", "1.0") < 0 and compare("PyPI", "1.0.post1", "1.0") > 0
def test_semver_prerelease_precedence():
    # SemVer 2.0.0 §11 example chain
    chain = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
             "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"]
    assert all(compare("npm", a, b) < 0 for a, b in zip(chain, chain[1:]))
def test_semver_build_metadata_ignored_and_v_prefix():
    assert compare("npm", "v1.2.3+abc", "1.2.3") == 0
def test_invalid_versions_raise():
    with pytest.raises(InvalidVersion): parse_version("npm", "1.2")
    with pytest.raises(InvalidVersion): parse_version("PyPI", "not a version")
def test_finding_id_stable():
    a = make_finding_id("uv.lock", "PyPI", "starlette", "0.1", "CVE-1", "graded")
    assert a == make_finding_id("uv.lock", "PyPI", "starlette", "0.1", "CVE-1", "graded") and len(a) == 64
```

- [ ] **Step 2: Run** `pytest -q` → FAIL (modules missing).
- [ ] **Step 3: Implement** pyproject (deps per Global Constraints; `[project.optional-dependencies] dev`; `[project.scripts] exposuregate = "exposuregate.__main__:main"`; package data includes `schemas/`), models, versions. SemVer: own parser of `MAJOR.MINOR.PATCH[-pre][+build]`, strip leading `v`, ordering key per SemVer §11 (numeric identifiers < alphanumeric; shorter pre-release list < longer when prefix equal; release > any pre-release).
- [ ] **Step 4: Run** `pip install -e '.[dev]' && pytest -q` → PASS.
- [ ] **Step 5: Commit** `feat: scaffold package, models and version ordering`

---

### Task 2: Configuration

**Files:** Create `src/exposuregate/config.py`; Test `tests/test_config.py`

**Interfaces:**
- Produces: `@dataclass Suppression(id: str, reason: str, expires: date, package: str | None = None, ecosystem: str | None = None)`; `@dataclass Config` with fields mirroring §8: `fail_closed: bool`, `data_dir: Path`, `max_age_days: int`, `oebc_max_age_days: int | None`, `osv_max_age_days: int | None`, `policy: dict[str, str]`, `transitive_max_action: str`, `lockfiles: dict[str, LockfileTypeConfig(enabled: bool, globs: list[str])]`, `unsupported_globs: list[str]`, `excluded_paths: list[str]`, `suppressions: list[Suppression]`, `report_formats: list[str]`, `output_dir: str | None`; `Config.max_age(source: str) -> int` (`"oebc"` or `"osv"`); `load_config(path: Path | None, cwd: Path) -> Config`; `class ConfigError(Exception)`.
- Default `unsupported_globs`: `["yarn.lock", "pnpm-lock.yaml", "Pipfile.lock", "bun.lock", "bun.lockb", "Cargo.lock", "go.sum", "Gemfile.lock", "composer.lock", "gradle.lockfile"]` (top-level key `unsupported_globs`, §5.5).
- `data.dir` default `~/.cache/exposuregate`, overridden by env `EXPOSUREGATE_DATA_DIR` (env beats file default, CLI beats both — CLI applied in Task 13).

- [ ] **Step 1: Failing tests:** `test_defaults_match_spec` (assert full policy dict `{"CRITICAL":"block","HIGH":"warn","MEDIUM":"pass","LOW":"pass","not_in_oebc":"warn","no_cve":"warn","unparseable_version":"warn","unpinned":"warn","unsupported_lockfile":"warn"}`, `transitive_max_action == "block"`, `max_age_days == 7`, `fail_closed is True`, `report_formats == ["json","markdown"]`, `output_dir == ".exposuregate/reports"`); `test_reads_dot_exposuregate_yml_from_cwd`; `test_deep_merge_keeps_unspecified_defaults`; `test_unknown_top_level_key_rejected`; `test_unknown_nested_key_rejected` (`policy: {CRTICAL: block}`); `test_invalid_action_rejected` (`HIGH: deny`); `test_suppression_requires_reason_and_expires` (each missing → ConfigError); `test_per_source_max_age_override` (`oebc_max_age_days: 30` → `max_age("oebc") == 30`, `max_age("osv") == 7`); `test_env_overrides_data_dir`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.** Validate against a nested dict of allowed keys/types derived from the defaults dict; error messages name the offending key path (e.g. `policy.CRTICAL`).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: config loading with strict validation`

---

### Task 3: `requirements*.txt` parser (§5.1)

**Files:** Create `src/exposuregate/lockfiles/__init__.py` (empty `PARSERS` registry for now), `src/exposuregate/lockfiles/requirements.py`; Test `tests/lockfiles/test_requirements.py`, fixtures `tests/fixtures/lockfiles/requirements/*.txt`

**Interfaces:** Produces `parse_requirements(text: str) -> ParsedLockfile` (type `requirements`, ecosystem `PyPI`). Raises `LockfileError("lockfile_parse")` only on undecodable input; malformed requirement lines become unpinned pins (spec: anything not `==`/`===`).

- [ ] **Step 1: Failing tests** (fixture = a real `pip-compile` output with hashes and `# via` blocks):
  - `test_pinned_with_extras_and_hashes` → `Pin("PyPI","requests","2.32.0","direct")` from `requests[socks]==2.32.0 \` + `--hash=...` continuation.
  - `test_triple_equals_pinned`.
  - `test_marker_recorded` → `marker == 'python_version < "3.11"'`.
  - `test_via_only_package_is_transitive` (`# via requests` → `urllib3` transitive).
  - `test_via_with_dash_r_is_direct_even_with_packages` (`# via\n    #   -r requirements.in\n    #   foo` → direct).
  - `test_no_via_is_direct`.
  - `test_unpinned_forms` → `requests>=2`, bare `flask`, `-e .`, `git+https://...#egg=x` each yield a pin with `version == ""` and `unpinned_spec` set to the stripped line.
  - `test_option_lines_ignored` (`-i`, `--index-url`, `--extra-index-url`, `-r other.txt`, `-c c.txt` produce nothing).
  - `test_name_normalized` (`PyYAML==6.0` → `pyyaml`).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** with `packaging.requirements.Requirement` for name/extras/marker/specifier; join `\` continuations before parsing; associate `# via` comment blocks with the preceding requirement.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: requirements.txt parser`

---

### Task 4: `poetry.lock` parser (§5.2)

**Files:** Create `src/exposuregate/lockfiles/poetry.py`; Test `tests/lockfiles/test_poetry.py`; fixtures: a real `poetry.lock` + `pyproject.toml` pair (Poetry 1.x style) and one with `[project.dependencies]` (Poetry 2 style).

**Interfaces:** Produces `parse_poetry(text: str, manifest_text: str | None) -> ParsedLockfile`.

- [ ] **Step 1: Failing tests:** `test_direct_from_tool_poetry_dependencies` (excludes `python`); `test_direct_from_groups_and_dev_dependencies`; `test_direct_from_project_dependencies_pep508` (`"fastapi[all]>=0.110"` → `fastapi` direct); `test_others_transitive`; `test_no_manifest_all_unknown`; `test_git_directory_file_url_sources_skipped` (each → `Skipped(name, "source:git")` etc., not in pins); `test_legacy_source_graded_with_source_field` (`source == "legacy"`); `test_invalid_toml_raises_lockfile_parse`; `test_missing_version_raises_lockfile_parse`.
- [ ] **Step 2–4:** run FAIL → implement with `tomllib`/`tomli` → run PASS.
- [ ] **Step 5: Commit** `feat: poetry.lock parser`

---

### Task 5: `uv.lock` parser (§5.3)

**Files:** Create `src/exposuregate/lockfiles/uv.py`; Test `tests/lockfiles/test_uv.py`; fixtures: real `uv.lock` from a project depending on `fastapi` (so `starlette` is transitive), and a two-member workspace lock.

**Interfaces:** Produces `parse_uv(text: str) -> ParsedLockfile`.

- [ ] **Step 1: Failing tests:** `test_registry_packages_graded`; `test_root_dependencies_direct_rest_transitive` (`fastapi` direct, `starlette` transitive); `test_optional_and_dev_dependencies_direct` (both `optional-dependencies` and `dev-dependencies` tables); `test_workspace_members_are_roots_not_pins` (editable/virtual → not pins; recorded as `Skipped(name, "source:workspace")`); `test_git_path_directory_url_skipped`; `test_same_name_two_versions_two_pins`; `test_invalid_toml_raises`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** `feat: uv.lock parser`

---

### Task 6: `package-lock.json` parser (§5.4)

**Files:** Create `src/exposuregate/lockfiles/npm.py`; Test `tests/lockfiles/test_npm.py`; fixtures: real v3 lock (with nested `node_modules/a/node_modules/b`, an alias `"name"` entry, a `link: true` workspace, a `git+` resolved entry, a `dev: true` entry), a v2 lock, a v1 lock.

**Interfaces:** Produces `parse_npm(text: str) -> ParsedLockfile`.

- [ ] **Step 1: Failing tests:** `test_v3_names_from_key_last_segment`; `test_alias_uses_name_field`; `test_direct_requires_top_level_key_and_root_declaration` (same package nested under another package → transitive pin for that version); `test_same_name_version_at_many_paths_is_one_pin_with_all_paths` (Review Focus 3: three paths → one `Pin` whose `paths` has 3 entries; direct if any path is direct); `test_link_skipped`; `test_non_registry_resolved_skipped` (`git+`, `file:`); `test_dev_only_recorded`; `test_in_bundle_graded`; `test_workspace_root_declarations_count_as_direct`; `test_v2_supported`; `test_v1_raises_lockfile_unsupported`; `test_missing_lockfile_version_raises_lockfile_unsupported`; `test_invalid_json_raises_lockfile_parse`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** `feat: package-lock.json parser`

---

### Task 7: Lockfile classification and diffing (§4.1, §5, §5.5)

**Files:** Modify `src/exposuregate/lockfiles/__init__.py`; Create `src/exposuregate/diffing.py`; Test `tests/test_classify.py`, `tests/test_diffing.py`

**Interfaces:**
- Produces: `classify(path: str, cfg: Config) -> str` returning one of `requirements|poetry|uv|npm|unsupported|manifest|excluded|disabled|ignore` (match on basename with `fnmatch`; `excluded` checked first against `cfg.excluded_paths` on the repo-relative path; `manifest` for basename `pyproject.toml` / `package.json`); `parse(type: str, text: str, manifest_text: str | None = None) -> ParsedLockfile` dispatching to Tasks 3–6; `ECOSYSTEM = {"requirements":"PyPI","poetry":"PyPI","uv":"PyPI","npm":"npm"}`.
- Produces: `changed_pins(old: ParsedLockfile | None, new: ParsedLockfile) -> list[ChangedPin]` — pins in new whose `key` is not among old keys; `previous_version` = lowest old version with the same name and a different version (PEP 440 / SemVer ordering via `versions.compare`; if unparseable, lexicographic), else `None`. Output sorted by `(name, version)`.

- [ ] **Step 1: Failing tests:** `test_classify_default_globs` (`a/b/requirements-dev.txt` → requirements; `uv.lock`, `poetry.lock`, `package-lock.json`); `test_classify_unsupported` (`web/yarn.lock`); `test_classify_manifest`; `test_classify_excluded_beats_type`; `test_classify_disabled_type`; `test_custom_globs`; `test_new_file_all_pins_changed` (old None); `test_version_bump_has_previous_version`; `test_removed_pins_ignored`; `test_unchanged_relock_yields_nothing` (Review Focus 1: same pins, different hashes/resolved URLs → `[]`); `test_name_case_change_is_not_a_change` (Review Focus 2: `PyYAML==6.0` → `pyyaml==6.0` → `[]`); `test_unpinned_spec_change_is_a_change`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** `feat: lockfile classification and pin diffing`

---

### Task 8: OSV matching and CVE extraction (§7.1, §7.2)

**Files:** Create `src/exposuregate/osv.py`; Test `tests/test_osv.py`; fixtures `tests/fixtures/osv/*.json` (hand-made minimal records plus 3 real records copied from the archive: a PYSEC with CVE alias, a GHSA for `starlette`, an npm GHSA for `vite`).

**Interfaces:**
- Produces: `CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")`; `cve_ids(record: dict) -> list[str]` (sorted, unique; from `id` and `aliases`); `@dataclass Match(advisory_id: str, fixed_in: list[str])`; `match(record: dict, ecosystem: str, name: str, version: str, now: date) -> Match | None` — raises `InvalidVersion` if the pin version is unparseable and the record has ranges to evaluate for this package.
- Range evaluation (OSV schema "Evaluation"), per `ECOSYSTEM`/`SEMVER` range, versions compared with `versions.compare`; `"0"` is below everything:

```python
def in_range(v, events, cmp):
    affected = False
    for e in sorted(events, key=event_sort_key):      # by the event's version
        if "introduced" in e and (e["introduced"] == "0" or cmp(v, e["introduced"]) >= 0):
            affected = True
        elif "fixed" in e and cmp(v, e["fixed"]) >= 0:
            affected = False
        elif "last_affected" in e and cmp(v, e["last_affected"]) > 0:
            affected = False
    limits = [e["limit"] for e in events if "limit" in e]
    if limits and all(cmp(v, l) >= 0 for l in limits):
        affected = False
    return affected
```

- [ ] **Step 1: Failing tests:** `test_versions_list_hit`; `test_versions_list_compared_as_pep440` (`1.0` matches listed `1.0.0`); `test_range_introduced_fixed` (below/at/inside/at fixed); `test_introduced_zero`; `test_last_affected_inclusive`; `test_multiple_ranges_union`; `test_limit`; `test_git_range_ignored`; `test_withdrawn_before_now_skipped` and `test_withdrawn_after_now_still_matches`; `test_other_ecosystem_ignored`; `test_name_normalized_both_sides` (Review Focus 4: OSV `Django`, pin `django`); `test_fixed_in_collected`; `test_unparseable_pin_version_raises`; `test_cve_ids_from_id_and_aliases` (GHSA with `["CVE-2026-48710","PYSEC-x"]` → `["CVE-2026-48710"]`; record whose id is a CVE); `test_cve_ids_empty_when_none`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** `feat: OSV advisory matching and CVE extraction`

---

### Task 9: Data store, OEBC loading, `update-data`, `data-info` (§6.1, §6.2)

**Files:** Create `src/exposuregate/store.py`, `src/exposuregate/update.py`; Test `tests/test_store.py`, `tests/test_update.py`; fixtures `tests/fixtures/oebc/mini.json.gz` (OEBC-shaped, ~10 CVEs covering every tier and `kev_listed`), `tests/fixtures/osv/PyPI.zip`, `npm.zip` (small zips of fixture records).

**Interfaces:**
- `@dataclass SourceMeta(source: str, date: datetime, count: int, extra: dict)` — OEBC `date` = `generated_at_utc`; OSV `date` = max `modified`; `extra` holds OEBC `project_version` and `rules`.
- `@dataclass DataMeta(oebc: SourceMeta | None, osv: dict[str, SourceMeta], replay: dict | None = None)`.
- `class DataStore(Protocol)`: `meta: DataMeta`; `advisories(ecosystem: str, name: str) -> list[dict]` (full OSV records with an `affected` entry for that normalized name); `oebc(cve_id: str) -> dict | None` (keys `exposure_tier, kev_listed, kev_date_added, epss_score, cvss_score`).
- `MemoryStore.from_files(oebc_path: Path | None, osv_sources: list[Path], published_before: date | None = None) -> MemoryStore` — `osv_sources` may be zips or directories of JSON; ecosystem taken from each record's `affected[].package.ecosystem`; `published_before` drops records with `published > that date`.
- `build_index(oebc_path: Path, osv_zips: dict[str, Path], out: Path) -> DataMeta` writes SQLite (tables `advisory(ecosystem, name, record_json)`, `oebc(cve_id PRIMARY KEY, ...)`, `meta(key, value_json)`), via temp file + `os.replace`.
- `SqliteStore(path: Path)`; raises `DataMissing` if file absent; `DataInvalid` if tables/meta missing.
- `update.update_data(data_dir: Path, ecosystems: list[str], urls: dict | None = None) -> DataMeta`; validates (§6.2: OEBC `len(vulnerabilities) == count`; zip opens; every record parses; ≥1 record per ecosystem); writes `index.sqlite` + `manifest.json`; on any failure raises and leaves previous files untouched. `update.data_info(data_dir) -> str`.

- [ ] **Step 1: Failing tests:** `test_memory_store_lookup_by_normalized_name`; `test_memory_store_published_before_filters`; `test_oebc_fields`; `test_meta_dates` (OEBC from `generated_at_utc`, OSV = max `modified`); `test_sqlite_roundtrip_equals_memory` (same answers for every fixture query); `test_sqlite_missing_raises_data_missing`; `test_update_data_from_file_urls` (`file://` URLs to fixtures; manifest records URLs, dates, counts); `test_update_data_failure_keeps_previous_index` (second run with corrupt zip raises, old `index.sqlite` bytes unchanged); `test_update_rejects_oebc_count_mismatch`; `test_data_info_prints_dates`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** `feat: data store, OEBC/OSV loading and update-data`

---

### Task 10: Freshness (§6.3, §6.4 replay rules)

**Files:** Create `src/exposuregate/freshness.py`; Test `tests/test_freshness.py`

**Interfaces:** Produces `check(meta: DataMeta | None, needed_ecosystems: set[str], now: date, cfg: Config, replay: bool) -> list[Denial]`. Codes: `data_missing` (meta None, OEBC None, or a needed ecosystem absent), `data_stale` (`(now - date.date()).days > cfg.max_age(src)`), `data_from_future` (non-replay: any source date after `now`; replay: OEBC date after `now`). In replay mode OSV staleness and OSV future checks are skipped. Detail strings name source, date, age and limit, e.g. `"OEBC generated 2026-06-14 is 153 days old (max 7)"`.

- [ ] **Step 1: Failing tests:** `test_fresh_no_denials`; `test_oebc_stale_message_exact` (the string above with `now=2026-11-14`); `test_osv_stale_only_for_needed_ecosystem` (stale npm, only PyPI needed → none); `test_missing_store`; `test_missing_needed_ecosystem`; `test_per_source_override`; `test_future_non_replay`; `test_replay_skips_osv_checks`; `test_replay_still_rejects_future_oebc`; `test_boundary_exactly_max_age_is_fresh` (age 7, max 7 → none).
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** `feat: data freshness checks`

---

### Task 11: Grading, policy, suppressions, verdict (§7.3)

**Files:** Create `src/exposuregate/grading.py`; Test `tests/test_grading.py`

**Interfaces:**
- `grade(lockfile: str, changes: list[ChangedPin], store: DataStore, cfg: Config, now: date) -> list[Finding]`:
  - unpinned pin → one finding reason `unpinned`.
  - `InvalidVersion` from `osv.match` → one finding per pin reason `unparseable_version` (deduplicate across advisories).
  - per matched advisory: CVE ids → one finding per `(pin, CVE)` with `advisory_ids` merged across advisories; CVE in OEBC → reason `graded`, base action `cfg.policy[tier]`; not in OEBC → `not_in_oebc`; no CVE → one finding per `(pin, advisory)` reason `no_cve`.
  - then `apply_policy(f, dependency, cfg, now)`.
- `unsupported_finding(lockfile: str, cfg: Config) -> Finding` (reason `unsupported_lockfile`, package/version empty).
- `apply_policy(finding: Finding, dependency: str, cfg: Config, now: date) -> Finding`: cap `transitive` at `cfg.transitive_max_action` (by `ACTION_RANK`); then first matching suppression (`id` equals `cve_id` or is in `advisory_ids`; `package`/`ecosystem` if given must match): unexpired (`expires >= now`) → `action = "pass"`, `suppressed_by = id`; expired → unchanged and caller records it.
- `expired_suppressions(findings_matched: ..., cfg, now) -> tuple[list[dict], list[Finding]]` → list for the report and one `suppression_expired` WARN finding per expired entry that matched something.
- `verdict(findings: list[Finding], denials: list[Denial], fail_closed: bool) -> tuple[str, int]` — enforced denials (when `fail_closed`) → `("DENY", 2)`; else worst action → BLOCK 1 / WARN 0 / PASS 0; with `fail_closed=False` and any denial, floor is WARN (and denials get `enforced=False`, set by caller).

- [ ] **Step 1: Failing tests** (use `MemoryStore` over fixtures): one per §7.3 table row (`test_kev_cve_blocks`, `test_high_warns`, `test_medium_low_pass_but_reported`, `test_not_in_oebc_warns`, `test_no_cve_warns`, `test_unparseable_version_warns_once`, `test_unpinned_warns`, `test_unsupported_finding_warns`); `test_two_advisories_same_cve_one_finding_merged_ids`; `test_policy_overrides_apply` (set `HIGH: block` → block — guards ControlGate flaw 2); `test_transitive_cap` (`transitive_max_action: warn` → KEV transitive becomes warn, `base_action` stays block; direct unaffected); `test_suppression_unexpired`; `test_suppression_expired_reported_and_warns`; `test_suppression_package_mismatch_no_effect`; `test_verdict_precedence` (DENY > BLOCK > WARN > PASS); `test_fail_open_floor_warn`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** `feat: grading, policy, suppressions and verdict`

---

### Task 12: Reports (§9)

**Files:** Create `schemas/report.schema.json`, `src/exposuregate/report.py`; Test `tests/test_report.py`

**Interfaces:**
- `build_report(*, verdict: str, exit_code: int, as_of: date, input: dict, meta: DataMeta | None, cfg: Config, lockfiles: list[dict], findings: list[Finding], skipped: list[dict], denials: list[Denial], expired: list[dict], timing_ms: dict[str, int]) -> dict` — keys and nesting exactly as §9 (plus `data.replay` when replaying); `summary` counts `block/warn/pass/denials`; findings sorted by action rank desc, then lockfile, package, version.
- `to_json(report: dict) -> str` (indent 2, `ensure_ascii=False`); `to_markdown(report: dict) -> str` containing: verdict line, denials list, findings table (action, package, version, dependency, CVE/advisory, tier, KEV, fixed in), data dates line, skipped/unsupported lockfiles.
- `lockfiles[]` entries: `{"path", "type", "status"}` where status ∈ `graded|unchanged|unsupported|manifest_only|disabled|excluded|parse_error`, plus `pins_added_or_changed`, `pins_skipped` when graded.

- [ ] **Step 1: Failing tests:** `test_report_validates_against_schema` (jsonschema, a report with one of every reason); `test_schema_rejects_unknown_verdict`; `test_markdown_contains_verdict_denials_and_rows`; `test_ordering_block_first`; `test_report_records_snapshot_dates`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** `feat: JSON and Markdown reports with schema`

---

### Task 13: Git inputs, scan orchestration, CLI (§4.1, §4.2, §10)

**Files:** Create `src/exposuregate/gitio.py`, `src/exposuregate/scan.py`, `src/exposuregate/__main__.py`; Test `tests/test_gitio.py`, `tests/test_cli_e2e.py` (temp git repos via `git init`, fixtures copied in)

**Interfaces:**
- `gitio.changed_files(mode: str, cwd: Path, target_branch: str = "main", base: str | None = None, head: str | None = None) -> tuple[list[str], str | None, str]` → `(paths, old_ref, new_ref)`; pre-commit: `old_ref="HEAD"` or `None` when no commits, `new_ref=":"` (index); pr: `old_ref = merge-base`, `new_ref="HEAD"`; explicit: given refs. Raises `GitError`.
- `gitio.read_blob(ref: str | None, path: str, cwd: Path) -> str | None` (`None` if ref None or path absent at ref; `":"` reads the index as `git show :path`).
- `scan.run_scan(opts: ScanOptions, cfg: Config) -> tuple[dict, int]`; `@dataclass ScanOptions(mode, target_branch, base, head, old_file, new_file, lockfile_type, manifest_file, path, data_dir, oebc_file, osv_dir, as_of, replay, archive, fail_open, formats, output_dir)`.
  Flow: collect changed paths → `classify` each → parse old/new (manifest at the same ref from the same directory for poetry) catching `LockfileError` → denial with path and side → `changed_pins` → if no graded lockfile has changes: skip data loading and freshness (§10) → else open store (`--archive` → Task 14 `ArchiveStore`; `--oebc/--osv-dir` → `MemoryStore` with `published_before=as_of` whenever `--as-of` is given (§6.3); else `SqliteStore(data_dir/index.sqlite)`, filtering advisories with `published > as_of` when `--as-of` is given; `DataMissing` → denial `data_missing`, `DataInvalid` → denial `data_invalid`) → `freshness.check` → `grade` → unsupported findings → expired suppressions → `verdict` → `build_report` → time each phase into `timing_ms` (`load_data, read_lockfiles, match, total`).
  `manifest_only` status: `pyproject.toml`/`package.json` changed and no graded lockfile in the same directory changed.
- `__main__.main(argv: list[str] | None = None) -> int`; subcommands `scan`, `update-data`, `data-info`, `rebuild-oebc` (wired in Task 14); flags exactly §4.1; mutually exclusive input groups (usage error exit 2 when combined, when `--replay` lacks `--as-of`, when `--new` lacks `--lockfile-type`); `ConfigError` / `GitError` in a git mode outside a repo → stderr message, exit 2. Writes `report.json` / `report.md` into `output_dir` when set.
- `.pre-commit-hooks.yaml` and `docs/github-action.yml` exactly as §10.

- [ ] **Step 1: Failing E2E tests** (each builds a temp repo, uses `--oebc/--osv-dir` fixtures with `--as-of` set to fixture dates so data is fresh):
  - `test_precommit_kev_direct_blocks_exit_1` (stage a `uv.lock` adding the fixture's KEV-listed `litellm` version).
  - `test_precommit_first_commit_no_head` (Review Focus 5: repo with no commits, staged lockfile → graded, no `git_error`).
  - `test_pr_mode_uses_merge_base` (commit on main after branching must not be attributed to the PR).
  - `test_explicit_base_head`.
  - `test_old_new_files_mode` and `test_new_without_type_is_usage_error`.
  - `test_no_lockfile_change_passes_without_data` (no data dir at all → PASS exit 0).
  - `test_stale_data_denies_exit_2` and `test_fail_open_warns_exit_0` (denial `enforced: false`).
  - `test_parse_error_on_old_side_denies`.
  - `test_deleted_lockfile_contributes_nothing`.
  - `test_unsupported_lockfile_warns`; `test_manifest_only_listed_no_finding`; `test_excluded_and_disabled_listed`.
  - `test_unknown_config_key_exit_2`.
  - `test_scan_never_uses_network` (monkeypatch `urllib.request.urlopen` to raise; full scan still succeeds).
  - `test_output_dir_writes_both_reports`; `test_report_has_timing_ms_keys`.
  - `test_full_mode_grades_all_current_pins` (`--mode full --path repo`, old side empty).
  - `test_cli_max_age_days_overrides_config` (data 10 days old, `--max-age-days 30` → no denial).
  - `test_corrupt_index_denies_data_invalid`.
  - `test_as_of_drops_later_published_advisories` (non-replay).
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** `feat: scan command with git modes, CLI and hooks`

---

### Task 14: Replay — `rebuild-oebc` and archive reader (§6.4, §6.5)

**Files:** Create `src/exposuregate/rebuild.py`, `src/exposuregate/archive.py`; Modify `src/exposuregate/__main__.py`, `src/exposuregate/scan.py`; Test `tests/test_rebuild.py`, `tests/test_archive.py`; fixtures: tiny KEV JSON, two EPSS files `epss_scores-YYYY-MM-DD.csv.gz` (first line `#model_version:...,score_date:...`, then `cve,epss,percentile`), mini OEBC for CVSS, and a two-day archive tree in the layout documented in `paper/eval/archive/archive.py`.

**Interfaces:**
- `rebuild.tier(kev_listed: bool, epss: float | None, cvss: float | None, high: float = 0.10, medium: float = 0.01) -> str` — identical rule to OEBC `compute_exposure_tier` (KEV → CRITICAL; EPSS ≥ high or CVSS ≥ 9.0 → HIGH; EPSS ≥ medium or CVSS ≥ 7.0 → MEDIUM; else LOW; None never qualifies).
- `rebuild.rebuild_oebc(as_of: date, kev: Path, epss_dir: Path, oebc: Path, out: Path) -> dict` — KEV entries with `dateAdded <= as_of`; EPSS file for `as_of` or nearest earlier (none → error); CVSS from `oebc`; output OEBC-shaped (`generated_at_utc = as_of T00:00:00Z`, `vulnerabilities[]` with the five fields, `count`, `rules`) plus `rebuilt_from` listing each input path, date and sha256. CVE universe = union of OEBC CVEs and EPSS CVEs.
- `archive.ArchiveStore.open(root: Path, as_of: date) -> MemoryStore` — uses `days/<D>.json` for the latest D ≤ as_of with no errors for the needed source; OEBC from its blob; OSV state per §6.5 (ids in `index-D`, each record from the latest `delta-*` ≤ D with matching `(id, modified)`); `meta.replay = {"osv_mode": "archived", "archive_day": D}`.
- In `scan`: `--replay` with `--oebc` (a rebuilt catalog) and `--osv-dir` sets `meta.replay = {"osv_mode": "current_filtered", ...}` and `published_before = as_of`; report `data.replay` = that dict with `replay: true`.
- CLI `rebuild-oebc` per §4.1.

- [ ] **Step 1: Failing tests:** `test_tier_matches_oebc_rule` (table of 8 cases including boundaries 0.10, 0.01, 9.0, 7.0 and None); `test_rebuild_excludes_kev_added_after_as_of` (KEV added the day after → not CRITICAL); `test_rebuild_uses_nearest_earlier_epss_and_records_it`; `test_rebuild_no_epss_before_date_errors`; `test_rebuild_output_loads_in_memory_store`; `test_archive_reconstructs_modified_record_as_of_each_day` (record modified on day 2: day-1 replay sees old ranges, day-2 sees new); `test_archive_uses_latest_day_not_after_as_of`; `test_archive_skips_day_with_error_for_source`; `test_replay_report_flags_osv_mode`; `test_replay_does_not_deny_on_osv_future_dates`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** `feat: historical replay via rebuilt OEBC and snapshot archive`

---

### Task 15: Planted-exposure set, README, release hygiene (§11, §13)

**Files:** Create `tests/fixtures/planted/` (frozen data + per-case old/new lockfiles), `scripts/freeze_fixtures.py`, `tests/test_planted.py`; Modify `README.md`, `CHANGELOG.md`; outside this repo, modify `../README.md` (agreed-design section) and `../paper/main.tex` limitations sentence.

**Interfaces:** Consumes everything above via `exposuregate scan --old/--new --oebc --osv-dir --as-of`.

- `scripts/freeze_fixtures.py --archive ~/data/exposuregate-archive --day 2026-11-13 --out tests/fixtures/planted/data` copies the OSV records for the named packages and the OEBC records for their CVE aliases into a small frozen OSV dir + OEBC file, so the tests never change with upstream data.
- Cases (one `old`/`new` pair each; pick concrete versions from the frozen records' `affected` data, and record the chosen version and CVE in `tests/fixtures/planted/cases.json` with the expected verdict and tags):
  - uv: direct KEV `litellm` → BLOCK; transitive KEV `starlette` via `fastapi` → BLOCK tagged `transitive`; HIGH-tier pick → WARN; LOW-tier pick → PASS; benign bump to a fixed version → PASS.
  - poetry: direct KEV `langflow` → BLOCK; transitive `starlette` → BLOCK `transitive`; benign → PASS.
  - requirements (pip-compile style): direct KEV `litellm` → BLOCK; `starlette` via `fastapi` → BLOCK `transitive`; benign → PASS.
  - npm: direct KEV `vite` → BLOCK; transitive KEV `jquery` (nested under another package) → BLOCK `transitive`; HIGH → WARN; benign → PASS.
  - Note: the frozen OEBC is the 2026-06-14 build. A KEV CVE added after that (e.g. `brotli`, KEV 2026-10-27) is `not_in_oebc` or not CRITICAL there; add one such case expecting WARN with reason `not_in_oebc` or the stale tier, which documents the staleness effect for the paper.

- [ ] **Step 1: Write** `scripts/freeze_fixtures.py` and run it; commit the frozen data (expect < 2 MB; if larger, trim to the named packages only).
- [ ] **Step 2: Write** `tests/test_planted.py` parametrized over `cases.json`, asserting verdict, exit code, and for each expected finding `(package, cve_id, dependency, action)`.
- [ ] **Step 3: Run** `pytest tests/test_planted.py -v` → all cases PASS (fix tool bugs found here in their owning module, with a regression test there).
- [ ] **Step 4: README** (install, `update-data`, pre-commit and Action usage, config reference generated from Task 2 defaults, exit codes, replay, limitations) and CHANGELOG 0.1.0.
- [ ] **Step 5: Run** `pytest -q --cov=exposuregate --cov-report=term-missing`, `ruff check .`, `mypy src` → all pass; coverage ≥ 90%.
- [ ] **Step 6: Commit** `test: planted-exposure set; docs: README and changelog`
- [ ] **Step 7: Outside this repo** (papers repo, separate commit): update `unassessed-by-design/README.md` agreed-design section (transitive decision, exit 2, `not_in_oebc` → WARN, replay A + archive, pointer to this spec) and the `paper/main.tex` limitations sentence ("as specified it sees only locked, direct dependencies" → it grades every locked version a change adds or changes, direct and transitive). Commit `unassessed-by-design: record ExposureGate spec decisions`.

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-14

First release.

### Added

#### Grading
- `exposuregate scan` grades every locked version that a change adds or changes in
  `requirements*.txt`, `poetry.lock`, `uv.lock` and `package-lock.json` (v2/v3), direct and
  transitive. Versions are matched to OSV advisories, advisories to CVE IDs, and CVE IDs to the
  OEBC `exposure_tier`.
- Default policy: CRITICAL (KEV-listed) blocks; HIGH, `not_in_oebc`, `no_cve`,
  `unparseable_version`, `unpinned` and `unsupported_lockfile` warn; MEDIUM and LOW pass.
  Also `transitive_max_action`, and suppressions that must have a reason and an expiry date.
- Input modes: pre-commit (the default), `--mode pr` (`--target-branch` falls back to
  `origin/<branch>`), `--base/--head`, `--mode full`, `--old/--new`.
- Exit codes: 0 PASS/WARN, 1 BLOCK, 2 DENY or usage/config error. Fails closed on missing,
  stale, future-dated or invalid data, on lockfile parse failures and on git errors. `--fail-open`
  and `fail_closed: false` turn these into unenforced denials.
- JSON report (with a JSON Schema) and Markdown report, including every advisory match, skipped
  sources, data snapshot dates and per-phase timings.
- Strict configuration (`.exposuregate.yml`): unknown keys and invalid values are errors.

#### Data
- `update-data` (the only command that uses the network) downloads OEBC and the OSV PyPI and
  npm exports into a validated SQLite index. `data-info` shows what is in it.
- Historical replay: `rebuild-oebc` rebuilds OEBC as of a date from KEV, EPSS and CVSS.
  `--replay` filters OSV by publication date. `--archive` reads the daily snapshot archive.

#### Integrations
- Pre-commit hook (`.pre-commit-hooks.yaml`).
- Composite GitHub Action (`action.yml`): installs ExposureGate, caches the data per day, runs
  `update-data` and `scan --mode pr`, exposes the verdict and report paths as outputs and exits
  with the scan's exit code. `docs/github-action.yml` is the same workflow as raw steps.
- Skills for AI coding agents (Antigravity, Claude Code, Codex, Cursor) in `skills/`.

#### Project
- Planted-exposure set: 24 cases across the four lockfile types, run against OSV/OEBC data
  frozen from the 2026-11-13 archive.
- `CONTRIBUTING.md`, `SECURITY.md`, `CITATION.cff`, a `Makefile`, CI on Python 3.10–3.12 with
  a 90% coverage floor, release to PyPI and GitHub on a new version, and weekly grouped
  Dependabot updates.

[Unreleased]: https://github.com/sadayamuthu/exposuregate/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sadayamuthu/exposuregate/releases/tag/v0.1.0

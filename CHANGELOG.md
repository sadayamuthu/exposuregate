# Changelog

## 0.1.0 - 2026-11-14

First release.

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
- `update-data` (the only command that uses the network) downloads OEBC and the OSV PyPI and
  npm exports into a validated SQLite index. `data-info` shows what is in it.
- Historical replay: `rebuild-oebc` rebuilds OEBC as of a date from KEV, EPSS and CVSS.
  `--replay` filters OSV by publication date. `--archive` reads the daily snapshot archive.
- Strict configuration (`.exposuregate.yml`): unknown keys and invalid values are errors.
- Pre-commit hook (`.pre-commit-hooks.yaml`) and an example GitHub Actions workflow.
- Planted-exposure set: 24 cases across the four lockfile types, run against OSV/OEBC data
  frozen from the 2026-11-13 archive.

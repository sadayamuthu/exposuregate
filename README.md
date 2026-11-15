<div align="center">

# ExposureGate

<h3>Exploited-Vulnerability Gate for Lockfiles</h3>

<p>Pre-Commit & Pull-Request Dependency Exposure Gate</p>

[![CI](https://img.shields.io/github/actions/workflow/status/sadayamuthu/exposuregate/ci.yml?branch=main&label=CI&style=flat-square)](https://github.com/sadayamuthu/exposuregate/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue?style=flat-square)](https://www.python.org/downloads/)
[![License](https://img.shields.io/github/license/sadayamuthu/exposuregate?style=flat-square)](https://github.com/sadayamuthu/exposuregate/blob/main/LICENSE)
[![PyPI](https://img.shields.io/pypi/v/exposuregate?style=flat-square)](https://pypi.org/project/exposuregate/)

---

[Quick Start](#quick-start) · [How It Works](#how-it-works) · [What It Grades](#what-it-grades) · [Installation](#installation) · [Configuration](#configuration) · [CLI Usage](#cli-usage)

</div>

---

## What is ExposureGate?

ExposureGate is a pre-commit hook and pull-request check. It stops a change from adding a
dependency version that has a known, exploited vulnerability. It is the counterpart of
[ControlGate](https://github.com/sadayamuthu/controlgate): ControlGate grades control findings in
a diff against OCBC, and ExposureGate grades the dependency versions a diff adds against OEBC.

OEBC (the Open Exposure Baseline Catalog) says which CVEs are being exploited: KEV-listed CVEs
are CRITICAL, and EPSS and CVSS set the lower tiers. OEBC has no package names or version ranges,
so ExposureGate joins it to a local export of the OSV database (see [Data Sources](#data-sources)).

---

## Quick Start

```bash
# Install
pip install exposuregate

# Download the OEBC catalog and the OSV PyPI and npm exports (the only network step)
exposuregate update-data
exposuregate data-info

# Pre-commit (the default): grade the staged lockfiles against HEAD
git add uv.lock
exposuregate scan

# Pull request: grade HEAD against its merge-base with main
exposuregate scan --mode pr --target-branch main
```

Exit code 0 is PASS or WARN, 1 is BLOCK, 2 is DENY or a usage error. See
[Exit codes](#exit-codes).

---

## How It Works

```
git commit / pull request
       ↓
lockfile diff (requirements*.txt, poetry.lock, uv.lock, package-lock.json)
       ↓
added or changed (package, version) pins, direct and transitive
       ↓
OSV advisories that affect each version → their CVE aliases
       ↓
OEBC exposure_tier for each CVE (CRITICAL = KEV-listed, then EPSS and CVSS)
       ↓
policy: block / warn / pass per finding, then transitive cap and suppressions
       ↓
Verdict: DENY / BLOCK / WARN / PASS
```

`scan` never uses the network. It reads the local data snapshot written by `update-data`, and
fails closed when that data is missing, stale, from the future or invalid.

---

## What It Grades

| Type | Files (by basename, anywhere in the repo) | Ecosystem |
|---|---|---|
| `requirements` | `requirements*.txt` (pip-compile style, `==` pins) | PyPI |
| `poetry` | `poetry.lock` (dependency kind from the `pyproject.toml` next to it) | PyPI |
| `uv` | `uv.lock` | PyPI |
| `npm` | `package-lock.json` (lockfileVersion 2 or 3) | npm |

It grades every locked version that a change adds or changes, direct and transitive. Each
finding is tagged `direct`, `transitive` or `unknown`. Packages the change leaves alone are not
graded, except with `--mode full`. Git, path, URL, editable and workspace sources are listed under
`skipped` and are not graded.

---

## Installation

Python 3.10 or later. The only runtime dependencies are `pyyaml`, `packaging`, and `tomli` on
Python 3.10.

### From PyPI

```bash
pip install exposuregate
```

[View ExposureGate on PyPI](https://pypi.org/project/exposuregate/)

### From source

```bash
pip install git+https://github.com/sadayamuthu/exposuregate
# or, from a checkout
pip install .
```

### As a Pre-Commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/sadayamuthu/exposuregate
    rev: v0.1.0
    hooks:
      - id: exposuregate
```

The hook runs `exposuregate scan --mode pre-commit` with `always_run: true` and `verbose: true`.
A `files` regex would bypass your configured globs (custom `lockfiles.*.globs`,
`unsupported_globs`) and pre-commit hides the output of passing hooks, which would hide WARN
reports. The scan itself decides what matters: a commit that changes no graded lockfile needs no
data and exits quickly with PASS.

Run `exposuregate update-data` regularly (daily) so the hook is not denied for stale data. A
commit that changes no graded lockfile never checks data freshness, so it is never blocked by
stale data.

### As a GitHub Action

There are two ways to run ExposureGate on pull requests. Both check out with `fetch-depth: 0`,
cache the data directory keyed on the date, run `update-data` and then
`scan --mode pr --target-branch <base branch>`. The base branch usually exists only as
`origin/<branch>` in the checkout, and `--target-branch` falls back to that.

**Option 1: the composite action.** [`action.yml`](https://github.com/sadayamuthu/exposuregate/blob/main/action.yml) at the root of this repository
installs ExposureGate with pip, from the action's own checkout by default, so the tool always
matches the action ref (`@v0.1.0` runs ExposureGate 0.1.0). It then runs the scan:

```yaml
# .github/workflows/exposuregate.yml
name: exposuregate
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write   # only for the PR comment step

jobs:
  exposuregate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - id: exposuregate
        uses: sadayamuthu/exposuregate@v0.1.0

      - name: Upload report.json
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: exposuregate-report
          path: exposuregate-report/report.json

      - name: Post report.md as a PR comment
        if: always() && hashFiles('exposuregate-report/report.md') != ''
        continue-on-error: true   # fork PRs get a read-only token and cannot comment
        env:
          GH_TOKEN: ${{ github.token }}
        run: gh pr comment ${{ github.event.pull_request.number }} --body-file exposuregate-report/report.md
```

| Input | Default | Meaning |
|---|---|---|
| `target-branch` | the PR's base branch, else the repository's default branch, else `main` | Passed to `--target-branch` |
| `data-dir` | `~/.cache/exposuregate` | Data directory (`--data-dir`), cached per day; `~` is the home directory and a relative path is relative to the workspace |
| `update-data` | `true` | `false` skips the cache restore, `update-data` and the cache save, for example when `args` passes `--oebc`/`--osv-dir` files |
| `ecosystems` | `PyPI npm` | OSV exports for `update-data --ecosystems` |
| `config` | none | Config file (`--config`); otherwise `.exposuregate.yml` in `working-directory` |
| `output-dir` | `exposuregate-report` | Where `report.json` and `report.md` are written (`--output-dir`) |
| `args` | none | Extra `scan` arguments, such as `--fail-open` or `--max-age-days 200`. Split on whitespace with no quoting, so no argument may contain a space. `--mode`, `--target-branch`, `--path`, `--data-dir`, `--output-dir` and `--format` are set by the action and rejected here (use the inputs) |
| `version` | the action's own checkout | Set an exact version such as `0.1.0`, or `latest`, to install that release from PyPI instead |
| `python-version` | `3.12` | Python for `actions/setup-python` |
| `working-directory` | `.` | The repository to scan (`--path`) |

| Output | Meaning |
|---|---|
| `verdict` | `PASS`, `WARN`, `BLOCK` or `DENY`; empty when the scan failed before writing a report |
| `json` | Absolute path of `report.json` |
| `markdown` | Absolute path of `report.md` |
| `exit-code` | The scan's exit code |

The action fails the step with the scan's own exit code: 1 for BLOCK, 2 for DENY or a usage
error, so a WARN does not fail the job. It also writes the Markdown report to the job summary.
The day's data is saved to the cache right after `update-data`, before the scan, so a BLOCK or
DENY still caches it. If `update-data` fails, the step only warns, and the scan uses the cached
data or is denied for missing or stale data.

On pull requests from forks, `GITHUB_TOKEN` is read-only, so the PR comment step cannot post;
it is marked `continue-on-error` and the report is still in the artifact and the job summary.

**Option 2: raw steps.** [`docs/github-action.yml`](https://github.com/sadayamuthu/exposuregate/blob/main/docs/github-action.yml) is a ready-to-copy
workflow that does the same with plain `run:` steps, if you would rather not depend on the
action. It installs ExposureGate from PyPI, uploads `report.json` and posts `report.md` as a PR
comment (skipped when there is no report, and allowed to fail on fork PRs).

---

## Data: `update-data`

`scan` never uses the network. Download the data first:

```bash
exposuregate update-data            # OEBC catalog + OSV PyPI and npm exports
exposuregate update-data --ecosystems PyPI
exposuregate data-info              # what is in the local snapshot, and how old it is
```

The data goes into `~/.cache/exposuregate`. You can change this with `data.dir` in the config,
`EXPOSUREGATE_DATA_DIR` or `--data-dir`. The download is validated and indexed into
`index.sqlite`. The new index is written to a temporary file and renamed into place, so a failed
update leaves the old data as it was.

Freshness: data older than `data.max_age_days` (7 by default) is **stale**, and a scan that needs
it is denied (exit 2). This is checked per source (OEBC, and OSV for each ecosystem) and only for
ecosystems the change touches.

> **Operational note.** OEBC's newest published catalog is from 2026-06-14. Until OEBC's daily
> build is fixed, every scan that needs OEBC is denied as `data_stale` under the defaults. This is
> the intended fail-closed behaviour. The explicit escape hatches are `--max-age-days N` (or
> `data.oebc_max_age_days`) and `--fail-open`.

---

## Configuration

ExposureGate reads `.exposuregate.yml` from the directory given by `--path` (default: the
current directory), or the file given by `--config`. The file is deep-merged over the defaults
below, and lists replace the default list. An unknown key, a wrong type or an invalid value is a
usage error (exit 2). Every key changes behaviour. CLI flags override the config.

These are the defaults. `tests/test_readme.py` checks this block against
`exposuregate.config.DEFAULTS`, so the two cannot drift apart.

<!-- config-defaults:start -->
```yaml
fail_closed: true            # false: report denials with enforced: false, verdict floor WARN
data:
  dir: ~/.cache/exposuregate # overridden by EXPOSUREGATE_DATA_DIR, then --data-dir
  max_age_days: 7            # limit for both sources; --max-age-days sets this one
  oebc_max_age_days: null    # per-source override
  osv_max_age_days: null     # per-source override
policy:                      # actions: block | warn | pass
  CRITICAL: block
  HIGH: warn
  MEDIUM: pass
  LOW: pass
  not_in_oebc: warn
  no_cve: warn
  unparseable_version: warn
  unpinned: warn
  unsupported_lockfile: warn
  transitive_max_action: block   # cap for transitive findings (warn = transitive is advisory)
lockfiles:                   # globs match the file's basename
  requirements: { enabled: true, globs: ["requirements*.txt"] }
  poetry: { enabled: true, globs: ["poetry.lock"] }
  uv: { enabled: true, globs: ["uv.lock"] }
  npm: { enabled: true, globs: ["package-lock.json"] }
unsupported_globs: [yarn.lock, pnpm-lock.yaml, Pipfile.lock, bun.lock, bun.lockb,
                    Cargo.lock, go.sum, Gemfile.lock, composer.lock, gradle.lockfile]
exclusions:
  paths: []                  # fnmatch globs on the full repo-relative path
suppressions: []
reporting:
  format: [json, markdown]
  output_dir: .exposuregate/reports   # relative to --path; null to disable
```
<!-- config-defaults:end -->

`exclusions.paths` is matched against the **full repo-relative path**, not the basename. To
exclude `examples/demo/uv.lock`, write `examples/*/uv.lock` or `examples/*` (`*` also matches
`/`). A bare `uv.lock` matches only the root lockfile. Matching is case-sensitive. Excluded files
are listed in the report with status `excluded`.

### Suppressions

```yaml
suppressions:
  - id: CVE-2024-12345          # CVE or advisory ID (required)
    package: urllib3            # optional, normalized name
    ecosystem: PyPI             # optional
    reason: "not reachable: we never call X"   # required, non-empty
    expires: 2027-01-31         # required
```

An expired suppression does not apply. It is listed under `expired_suppressions` and produces a
`suppression_expired` WARN finding.

### Default policy

| Reason | Condition | Action |
|---|---|---|
| `graded` | CVE in OEBC with tier CRITICAL (KEV-listed) | block |
| `graded` | tier HIGH | warn |
| `graded` | tier MEDIUM or LOW | pass |
| `not_in_oebc` | the advisory's CVE is not in the OEBC snapshot | warn |
| `no_cve` | the advisory has no CVE alias | warn |
| `unparseable_version` | the version does not parse in its ecosystem's scheme | warn |
| `unpinned` | a requirements line that is not `==`/`===` | warn |
| `unsupported_lockfile` | `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, ... changed | warn |

After that, `policy.transitive_max_action` caps the action of transitive findings. Then a
matching, unexpired suppression sets the action to `pass` and records `suppressed_by`. Every
advisory match appears in the report, including passed and suppressed ones.

---

## CLI Usage

```bash
# pre-commit (the default): staged lockfiles vs HEAD
exposuregate scan

# pull request: HEAD vs merge-base with the target branch
exposuregate scan --mode pr --target-branch main

# explicit refs, for replaying a historical PR (no merge-base is taken)
exposuregate scan --base <sha> --head <sha>

# everything currently pinned
exposuregate scan --mode full

# two files directly (reproducible evaluation)
exposuregate scan --old old/uv.lock --new new/uv.lock --lockfile-type uv \
    --oebc oebc.json.gz --osv-dir osv/ --as-of 2026-11-13

# data management
exposuregate update-data
exposuregate data-info

# rebuild OEBC as of a past date (see "Replaying a past date")
exposuregate rebuild-oebc --as-of 2026-03-01 --kev known_exploited_vulnerabilities.json \
    --epss-dir epss/ --oebc latest.json.gz --out oebc-2026-03-01.json.gz
```

In `--mode pr`, `--target-branch` (default `main`) falls back to `origin/<branch>` when there is
no local branch of that name, as in a CI checkout. `--manifest FILE` supplies the
`pyproject.toml` for poetry direct/transitive tagging in `--old/--new` mode.

### Exit codes

| Verdict | Meaning | Exit |
|---|---|---|
| `PASS` | no finding with action `warn` or `block` | 0 |
| `WARN` | the worst finding action is `warn` | 0 |
| `BLOCK` | at least one finding with action `block` | 1 |
| `DENY` | a fail-closed condition (data missing, stale, from the future or invalid; a lockfile that will not parse; a git error) with `fail_closed: true` | 2 |
| (none) | usage or config error: bad flags, unknown config key, not a git repo when a git mode is asked for | 2 |

Precedence is DENY > BLOCK > WARN > PASS. When a scan is denied, ExposureGate still grades
everything it can, so the report shows the findings next to the denial reasons. With
`fail_closed: false` or `--fail-open`, denials are reported with `enforced: false` and the
verdict comes from the findings, but a scan with any denial is never better than WARN.

---

## Output Formats

| Format | Use Case |
|--------|----------|
| `json` | Programmatic consumption, agents, dashboards; conforms to [`schemas/report.schema.json`](https://github.com/sadayamuthu/exposuregate/blob/main/schemas/report.schema.json) |
| `markdown` | PR comments, job summaries, terminal output |

Reports go to stdout, JSON first and then Markdown, or in the order given by
`--format json markdown`. If `reporting.output_dir` or `--output-dir` is set, they are also
written there as `report.json` and `report.md`. Progress lines go to stderr.

The default `output_dir` writes reports inside the repository, so add `.exposuregate/` to your
`.gitignore`.

Each finding records the lockfile, package, version and previous version, whether the dependency
is `direct` or `transitive`, the reason, the CVE and advisory IDs, the OEBC tier with its KEV,
EPSS and CVSS data, the `fixed_in` versions from OSV, the action before and after the transitive
cap and suppressions, and `suppressed_by`.

---

## Replaying a past date

For evaluation, a PR can be graded as it would have been graded on date D. OEBC serves only
`latest` and OSV's export is current-only, so there are two ways to do this:

**Option A: rebuild OEBC as of D.**

```bash
exposuregate rebuild-oebc --as-of 2026-03-01 --kev known_exploited_vulnerabilities.json \
    --epss-dir epss/ --oebc latest.json.gz --out oebc-2026-03-01.json.gz
exposuregate scan --base <sha> --head <sha> --as-of 2026-03-01 --replay \
    --oebc oebc-2026-03-01.json.gz --osv-dir osv/
```

`rebuild-oebc` applies OEBC's tier rule to the KEV entries with `dateAdded <= D`. Every one of
them is CRITICAL, even when OEBC and EPSS do not list it. It uses the EPSS daily file
`epss_scores-D.csv.gz`, or the nearest earlier one, and CVSS from the current catalog. The output
records each input's path, date and sha256 under `rebuilt_from`. `--replay` drops OSV advisories
published after D, and the report records `osv_mode: current_filtered`. Advisory ranges and
aliases are still today's, which is a known leak. OSV staleness and `data_from_future` checks are
not enforced in replay.

**Option B: the snapshot archive.**

```bash
exposuregate scan --base <sha> --head <sha> --as-of 2026-11-13 \
    --archive ~/data/exposuregate-archive --max-age-days 200
```

`--archive DIR` reads the daily snapshot archive written by the paper's daily archive script,
which lives in the papers repository, not in this one. It
uses the OEBC catalog and the OSV state as archived on the latest day on or before `--as-of`
(`osv_mode: archived`), so nothing from later leaks in. `--archive` needs `--as-of` and cannot be
combined with `--oebc`/`--osv-dir`. The archived OEBC is still checked for freshness against
`--as-of`. Until OEBC's daily build is fixed, every archived catalog is the 2026-06-14 build, so an
archive replay is denied as stale unless you pass `--max-age-days`, as in the example.

---

## Planted-Exposure Set

`tests/test_planted.py` runs 24 planted cases against data frozen from the 2026-11-13 archive
day (OEBC built 2026-06-14). The cases cover every lockfile type: a direct KEV pin (BLOCK), a
transitive KEV pin (BLOCK, tagged `transitive`), a HIGH pin (WARN), a LOW pin (PASS) and a benign
bump (PASS). Further cases document OEBC staleness: CVEs that were KEV-listed after the OEBC build
grade as `not_in_oebc` or LOW. The cases, the chosen versions and the reason for each choice are in
`tests/fixtures/planted/cases.json`. `scripts/freeze_fixtures.py` regenerates the frozen data
from the archive and checks it.

---

## Limitations

- **No reachability.** A vulnerable version is flagged whether or not the vulnerable code is
  called.
- **Lockfiles only.** Manifests are not resolved. A `pyproject.toml` or `package.json` change
  without its lockfile is listed as `manifest_only` and not graded. `yarn.lock`,
  `pnpm-lock.yaml`, `Pipfile.lock`, `package-lock.json` v1, Go, Maven and Cargo are not graded.
  A changed unsupported lockfile gives a WARN, and a v1 `package-lock.json` is denied.
- **Requirements markers are ignored.** A pin is graded even when its environment marker means
  it would never be installed. The marker is recorded on the finding, but this is a known source of
  false positives. `-r`/`-c` includes are not followed.
- **OEBC tiers are used as published.** A CVE KEV-listed after the OEBC snapshot was built is
  `not_in_oebc` (WARN) or carries its older tier until OEBC is rebuilt. With OEBC's build stalled
  at 2026-06-14, this already matters: see the `stale_oebc` planted cases.
- **Replay leakage (option A).** OSV ranges and aliases are as of today. CVSS comes from the
  current OEBC catalog.
- **Matching** uses OSV `versions` lists and `ECOSYSTEM`/`SEMVER` ranges. `GIT` ranges are
  ignored. A range with an unparseable event version is skipped.

---

## Development

```bash
make install-dev    # Install with dev dependencies
make test           # Run tests
make test-cov       # Run tests with coverage (fails under 90%)
make lint           # Lint with ruff
make format         # Apply ruff's automatic lint fixes
make typecheck      # Type check with mypy (strict)
make check          # Run all checks (lint + typecheck + test)
make build          # Build distribution packages
```

Or without `make`:

```bash
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest -q --cov=exposuregate --cov-report=term-missing
.venv/bin/ruff check . && .venv/bin/mypy src
```

---

## AI Agent Skills

ExposureGate provides skills for popular AI coding assistants. They teach the agent to run
`exposuregate scan` before committing a lockfile change, read the JSON report, and fix a finding
by moving the package to a version in its `fixed_in` list, never by adding a suppression without a
reason and an expiry date.

The agent prompts and workflows are located in the [`skills/`](https://github.com/sadayamuthu/exposuregate/tree/main/skills) directory:

- **Antigravity**: Full workflow definitions available in `skills/antigravity/exposuregate/`
- **Cursor**: Repository rules available in `skills/cursor/.cursorrules`
- **Claude Code**: System prompt instructions in `skills/claude_code/.clauderules`
- **Codex**: Integration prompts in `skills/codex/instructions.md`

---

## Data Sources

ExposureGate joins two public data sets, both downloaded by `exposuregate update-data`:

- **[OEBC](https://github.com/sadayamuthu/oebc)**, the Open Exposure Baseline Catalog, published
  by [OpenAstra](https://openastra.org): one `exposure_tier` per CVE, from CISA KEV (CRITICAL),
  FIRST EPSS and CVSS. Downloaded from `https://openastra.org/oebc/catalog/v0.1/latest.json.gz`.
- **[OSV](https://osv.dev)**: the per-ecosystem exports of the OSV database
  (`https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`, for `PyPI` and
  `npm`), which map package versions to advisories and advisories to CVE aliases.

`exposuregate data-info` shows the OEBC build date and the OSV export dates in the local
snapshot, and every report records them under `data`.

---

## Contributing

Bug reports, wrong or missed findings and new lockfile parsers are welcome. See
[CONTRIBUTING.md](https://github.com/sadayamuthu/exposuregate/blob/main/CONTRIBUTING.md) for the development setup, the tests and how to add a lockfile
parser.

---

## Security

Please report security problems privately, not in a public issue. See
[SECURITY.md](https://github.com/sadayamuthu/exposuregate/blob/main/SECURITY.md).

---

## License

[MIT License](https://github.com/sadayamuthu/exposuregate/blob/main/LICENSE). See [CHANGELOG.md](https://github.com/sadayamuthu/exposuregate/blob/main/CHANGELOG.md) for release notes.

---

<div align="center">

**ExposureGate is an open-source exploited-vulnerability gate for dependency lockfiles**

ExposureGate is managed by [OpenAstra](https://openastra.org).

[PyPI](https://pypi.org/project/exposuregate/) · [GitHub](https://github.com/sadayamuthu/exposuregate) · [OEBC](https://github.com/sadayamuthu/oebc) · [ControlGate](https://github.com/sadayamuthu/controlgate)

</div>

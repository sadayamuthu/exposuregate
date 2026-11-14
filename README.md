# ExposureGate

ExposureGate is a pre-commit hook and pull-request check. It stops a change from adding a
dependency version that has a known, exploited vulnerability. It is the counterpart of
ControlGate: ControlGate grades control findings in a diff against OCBC, and ExposureGate grades
the dependency versions a diff adds against OEBC.

OEBC (the Open Exposure Baseline Catalog) says which CVEs are being exploited: KEV-listed CVEs
are CRITICAL, and EPSS and CVSS set the lower tiers. OEBC has no package names or version ranges,
so ExposureGate joins it to a local export of the OSV database:

```
lockfile diff -> added or changed (package, version) -> OSV advisories -> CVE aliases
              -> OEBC exposure_tier -> block / warn / pass -> verdict
```

## What it grades

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

## Install

Python 3.10 or later.

```sh
pip install git+https://github.com/sadayamuthu/exposuregate
# or, from a checkout
pip install .
```

The only runtime dependencies are `pyyaml`, `packaging`, and `tomli` on Python 3.10.

## Data: `update-data`

`scan` never uses the network. Download the data first:

```sh
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

## Usage

```sh
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
```

In `--mode pr`, `--target-branch` (default `main`) falls back to `origin/<branch>` when there is
no local branch of that name, as in a CI checkout. `--manifest FILE` supplies the
`pyproject.toml` for poetry direct/transitive tagging in `--old/--new` mode.

Reports go to stdout, JSON first and then Markdown, or in the order given by
`--format json markdown`. If `reporting.output_dir` or `--output-dir` is set, they are also
written there as `report.json` and `report.md`. Progress lines go to stderr. The JSON report
conforms to [`schemas/report.schema.json`](schemas/report.schema.json).
The default `output_dir` writes reports inside the repository, so add `.exposuregate/` to your
`.gitignore`.

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

## Pre-commit

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

## GitHub Action

[`docs/github-action.yml`](docs/github-action.yml) is a ready-to-copy workflow. It checks out
with `fetch-depth: 0`, caches the data directory keyed on the date, and runs `update-data` and
then `scan --mode pr --target-branch ${{ github.base_ref }}`. It uploads `report.json` and posts
`report.md` as a PR comment. The base branch usually exists only as `origin/<branch>` in the
checkout, and `--target-branch` falls back to that.

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
`/`). A bare `uv.lock` matches only the root lockfile. Matching is case-sensitive. Excluded files are listed in the report with status `excluded`.

Suppressions:

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

## Replaying a past date

For evaluation, a PR can be graded as it would have been graded on date D. OEBC serves only
`latest` and OSV's export is current-only, so there are two ways to do this:

**Option A: rebuild OEBC as of D.**

```sh
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

```sh
exposuregate scan --base <sha> --head <sha> --as-of 2026-11-13 \
    --archive ~/data/exposuregate-archive --max-age-days 200
```

`--archive DIR` reads the daily snapshot archive written by `paper/eval/archive/archive.py`. It
uses the OEBC catalog and the OSV state as archived on the latest day on or before `--as-of`
(`osv_mode: archived`), so nothing from later leaks in. `--archive` needs `--as-of` and cannot be
combined with `--oebc`/`--osv-dir`. The archived OEBC is still checked for freshness against
`--as-of`. Until OEBC's daily build is fixed, every archived catalog is the 2026-06-14 build, so an
archive replay is denied as stale unless you pass `--max-age-days`, as in the example.

## Planted-exposure set

`tests/test_planted.py` runs 24 planted cases against data frozen from the 2026-11-13 archive
day (OEBC built 2026-06-14). The cases cover every lockfile type: a direct KEV pin (BLOCK), a
transitive KEV pin (BLOCK, tagged `transitive`), a HIGH pin (WARN), a LOW pin (PASS) and a benign
bump (PASS). Further cases document OEBC staleness: CVEs that were KEV-listed after the OEBC build
grade as `not_in_oebc` or LOW. The cases, the chosen versions and the reason for each choice are in
`tests/fixtures/planted/cases.json`. `scripts/freeze_fixtures.py` regenerates the frozen data
from the archive and checks it.

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

## Development

```sh
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest -q --cov=exposuregate --cov-report=term-missing
.venv/bin/ruff check . && .venv/bin/mypy src
```

MIT licensed. See [CHANGELOG.md](CHANGELOG.md).

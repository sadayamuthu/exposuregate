# ExposureGate: design spec

Date: 2026-11-14. Status: draft for approval.
Source of the agreed design: `unassessed-by-design/README.md`, "ExposureGate: agreed design".
Paper: *Unassessed by Design* (`unassessed-by-design/paper/main.tex`), §"ExposureGate: exposures a diff introduces (specification)".

## 1. Intent

ExposureGate stops a code change from introducing a dependency version with a known, exploited
vulnerability. It is ControlGate's counterpart: ControlGate grades control findings in a diff
with OCBC; ExposureGate grades the dependency versions a diff introduces with OEBC.

OEBC says which CVEs are being exploited (KEV → CRITICAL, then EPSS/CVSS tiers) but has no
package names, version ranges or CPEs, so it cannot say which CVEs a dependency change brings
in. ExposureGate bridges that with a local export of the OSV database: package version → OSV
advisories → CVE aliases → OEBC `exposure_tier` → BLOCK / WARN / PASS.

Why now: the paper currently submits ExposureGate as "specified only" (scope option 2). This
spec is for option 1, the later version that builds ExposureGate and evaluates its detection,
false positives and overhead, including on real pull requests. The tool must therefore be both
usable as a gate and *measurable*: deterministic, offline, replayable at a past date, and
explicit about every decision it makes.

## 2. Goals, non-goals, anti-goals

**Goals**
- G1. Run as a pre-commit hook and as a pull-request check, like ControlGate.
- G2. Grade every package version that a change adds or changes in a supported lockfile,
  direct **and** transitive (decided 2026-11-14), tagging each finding `direct`,
  `transitive` or `unknown`.
- G3. Default policy: BLOCK on CRITICAL (KEV-listed), WARN on HIGH, PASS otherwise; advisory
  with no CVE alias → WARN.
- G4. Fail closed (configurable): deny when OSV or OEBC data is missing or stale, or a
  lockfile will not parse.
- G5. Fully offline at scan time; reports record the date of every data snapshot used.
- G6. Reproducible evaluation: scan an explicit pair of lockfiles or two git refs, with pinned
  data snapshots and an `--as-of` date, and record per-phase timings.

**Non-goals (v1)**
- Reachability: whether the vulnerable code is called. (Paper limitation; stays.)
- Resolving manifests. ExposureGate reads lockfiles; if `pyproject.toml` or `package.json`
  changes without its lockfile, nothing is graded.
- Other ecosystems/formats: Go, Maven, Cargo, `yarn.lock`, `pnpm-lock.yaml`, `Pipfile.lock`,
  `package-lock.json` v1. (v1 lockfiles are denied, see §5.4.)
- SARIF output, license checks, auto-remediation PRs.
- Recomputing OEBC tiers. ExposureGate uses `exposure_tier` exactly as OEBC published it.
- Grading packages that a change leaves untouched (except in `--mode full`).

**Anti-goals** (would make it a failure even if it "works"). These are the ControlGate flaws
the paper documents; ExposureGate must not repeat them.
- A silent PASS when data is missing, stale or unreadable, or a lockfile is skipped.
- Config keys that are parsed but not applied. Every config key must change behaviour and be
  covered by a test; unknown keys are an error.
- Findings dropped without a trace. Every advisory match appears in the report, including
  PASS and suppressed ones, with the reason for its action.
- Depending on the network during a scan.

## 3. Approaches considered

1. **Pure Python, own lockfile parsing and OSV matching** (chosen). Parse the four lockfile
   formats, diff old vs new pins, match against a local OSV export using the enumerated
   `versions` lists and `ECOSYSTEM`/`SEMVER` range events. Self-contained like ControlGate,
   offline, every decision traceable and testable, which the evaluation needs. Cost: four
   parsers and the matcher are ours to write and test.
2. **Wrap Google's `osv-scanner`** in offline mode on old and new lockfiles and diff results.
   Mature matching, but adds an external Go binary, ties paper results to a tool version we
   don't control, and makes fail-closed depend on its error reporting. Rejected.
3. **A new gate inside ControlGate.** ControlGate's gates are regexes over added diff lines;
   lockfile diffing doesn't fit, and the README already makes ExposureGate its own tool and
   repo. Rejected.

## 4. Shape of the tool

- Python ≥ 3.10, package `exposuregate`, console script `exposuregate`, `src/` layout, MIT,
  same tooling as ControlGate (setuptools, pytest, ruff, mypy).
- Runtime dependencies: `pyyaml`, `packaging`, `tomli` on Python 3.10 (`tomllib` on 3.11+).
  No HTTP library needed beyond `urllib.request` (used only by `update-data`).
- npm version ordering: implement SemVer 2.0.0 precedence for concrete versions (OSV range
  events are concrete versions, so no range-expression parsing is needed).

### 4.1 Commands

```
exposuregate scan        [--mode pre-commit|pr|full] [--target-branch BRANCH]
                         [--base REF --head REF]
                         [--old FILE] [--new FILE] [--lockfile-type TYPE] [--manifest FILE]
                         [--path DIR] [--config FILE] [--format json markdown ...] [--output-dir DIR]
                         [--data-dir DIR] [--oebc FILE] [--osv-dir DIR]
                         [--as-of YYYY-MM-DD] [--replay] [--archive DIR]
                         [--max-age-days N] [--fail-open]
exposuregate update-data [--data-dir DIR] [--ecosystems PyPI npm]
exposuregate rebuild-oebc --as-of YYYY-MM-DD --kev FILE --epss-dir DIR --oebc FILE --out FILE
exposuregate data-info   [--data-dir DIR]
```

Input selection for `scan` (exactly one of):
- `--mode pre-commit` (default): old = `HEAD:<path>` (absent if no `HEAD` or file new),
  new = index `:<path>` (absent if deleted). Changed files from `git diff --cached --name-only`.
- `--mode pr`: base = `git merge-base <target-branch> HEAD`; old = `<base>:<path>`, new =
  `HEAD:<path>`. Changed files from `git diff --name-only <base> HEAD`.
- `--base REF --head REF`: as `pr` but with explicit refs (merge-base not taken). For replaying
  historical PRs.
- `--mode full`: every supported lockfile tracked by git under `--path` (or walked if not a git
  repo); old = empty. Grades everything currently pinned.
- `--old FILE --new FILE --lockfile-type requirements|poetry|uv|npm`: compare two files
  directly; `--old` may be omitted (empty). `--manifest` supplies the `pyproject.toml` for
  poetry direct/transitive tagging.

A lockfile whose new side is absent (deleted) contributes nothing. A lockfile that changed but
whose new side contains no added or changed pins contributes nothing.

### 4.2 Exit codes and verdicts

| Verdict | Meaning | Exit |
|---|---|---|
| PASS | no finding with action WARN or BLOCK | 0 |
| WARN | worst finding action is WARN | 0 |
| BLOCK | at least one finding with action BLOCK | 1 |
| DENY | fail-closed condition (§7) and `fail_closed: true` | 2 |
| — | usage error (bad flags, not a git repo when a git mode is asked) | 2 |

Precedence: DENY > BLOCK > WARN > PASS. ExposureGate still parses and grades everything it
can when a denial occurs, so the report shows findings alongside the denial reasons. With
`fail_closed: false` (or `--fail-open`), denial conditions are reported under `denials` with
`enforced: false` and the verdict is computed from findings, with WARN as its floor.

Note: ControlGate exits 1 for both BLOCK and errors. ExposureGate deliberately separates them
so the evaluation can count denials apart from blocks.

## 5. Lockfiles

Files are recognised by basename, anywhere in the repo, minus `exclusions.paths`:

| Type | Default globs | Ecosystem |
|---|---|---|
| `requirements` | `requirements*.txt` | PyPI |
| `poetry` | `poetry.lock` | PyPI |
| `uv` | `uv.lock` | PyPI |
| `npm` | `package-lock.json` | npm |

Globs are configurable per type (`lockfiles.<type>.globs`). Each lockfile is graded on its own;
the same package version in two lockfiles produces two findings.

A **pin** is `(ecosystem, normalized name, version, dependency kind)` plus provenance (lockfile
path, and for npm the install path(s)). **Added or changed pins** = pins in new whose
`(name, version)` is not in old. `previous_version` is reported when old had the same name at
a different version (lowest such version if several).

Name normalisation: PyPI per PEP 503 (lowercase, runs of `-_.` → `-`); npm names as written
(case-sensitive, scopes kept).

Non-registry sources (git, path/directory, file, URL, editable, workspace member, npm `link`)
are not graded; each is listed in the report's `skipped` with its reason and has no effect on
the verdict.

### 5.1 `requirements*.txt`
- One requirement per logical line (join `\` continuations; strip `#` comments, but keep
  pip-compile `# via` annotations for tagging).
- Graded: `name==version` or `name===version`, extras stripped, environment markers ignored
  (graded regardless of marker; a known false-positive source, reported as `marker` on the
  finding).
- Options lines (`-i`, `--index-url`, `--extra-index-url`, `--hash`, `-c`, `-r`, …) are ignored.
  `-r`/`-c` includes are **not** followed; an included requirements file that also changed is
  graded on its own if it matches a glob.
- Unpinned requirements (any other specifier, bare name, URL, `-e`): newly added or changed
  ones are reported as findings with reason `unpinned` and action from `policy.unpinned`
  (default `warn`).
- Dependency kind: pip-compile `# via` block names at least one `-r <file>` / `-c <file>`
  entry → `direct` (even if packages are also listed, e.g. `# via -r requirements.in, foo`);
  names only packages → `transitive`; no `# via` → `direct`. This matches the other formats,
  which tag by declaration, not by whether something else also requires the package.

### 5.2 `poetry.lock`
- TOML `[[package]]` entries: `name`, `version`, optional `[package.source]`. Source type `git`,
  `directory`, `file`, `url` → skipped. Type `legacy` (private index) → graded under PyPI, with
  `source: legacy` on the finding.
- Dependency kind from the `pyproject.toml` in the same directory (at the same git ref as the
  lockfile side being read): names in `[tool.poetry.dependencies]` (minus `python`),
  `[tool.poetry.group.*.dependencies]`, `[tool.poetry.dev-dependencies]`,
  `[project.dependencies]`, `[project.optional-dependencies]` (PEP 508 names) → `direct`;
  others → `transitive`. No readable `pyproject.toml` → `unknown` (not a denial).

### 5.3 `uv.lock`
- TOML `[[package]]` entries with `name`, `version`, `source`. `source.registry` → graded;
  `git`, `path`, `directory`, `url`, `editable`, `virtual` → skipped. Packages with
  `editable`/`virtual` source are workspace members (roots).
- Dependency kind: names listed in any root's `dependencies`, `optional-dependencies.*`,
  `dev-dependencies.*` → `direct`; others → `transitive`.
- The same name may appear at several versions (resolution forks); each is its own pin.

### 5.4 `package-lock.json`
- `lockfileVersion` 2 or 3: read `packages`. Key `""` is the root. For other keys, name = the
  `name` field if present (aliases), else the segment after the last `node_modules/`.
- Skipped: `link: true`; `resolved` not an `https://` registry tarball (e.g. `git+`, `file:`).
  Entries with `inBundle` are graded.
- Dependency kind: key exactly `node_modules/<name>` and `<name>` in the root's
  `dependencies`, `devDependencies`, `optionalDependencies` or `peerDependencies` → `direct`;
  else `transitive`. Workspace roots (`packages` entries that are workspace folders) count as
  roots too.
- `dev: true` is recorded on the finding (`dev_only`), not used for policy in v1.
- `lockfileVersion` 1 or missing → parse failure (denial `lockfile_unsupported`).

### 5.5 Unsupported, disabled and excluded dependency files
So that nothing is skipped silently, `scan` also looks for changed files that it recognises but
does not grade, and lists each in `lockfiles[]` with a status:
- `unsupported`: `yarn.lock`, `pnpm-lock.yaml`, `Pipfile.lock`, `bun.lock`, `bun.lockb`,
  `Cargo.lock`, `go.sum`, `Gemfile.lock`, `composer.lock`, `gradle.lockfile` (list is
  configurable as `unsupported_globs`). Each produces a finding with reason
  `unsupported_lockfile`, action from `policy.unsupported_lockfile` (default `warn`).
- `manifest_only`: `pyproject.toml` or `package.json` changed while no lockfile in the same
  directory changed. Listed with a note; no finding (the lockfile, when regenerated, is graded).
- `disabled` (type turned off in config) and `excluded` (matches `exclusions.paths`): listed;
  no finding. These are the user's explicit choice.

### 5.6 Parse failures
Any of: invalid TOML/JSON, missing required fields, unsupported lockfile version, unreadable
git object → denial `lockfile_parse` (or `lockfile_unsupported`) naming the file and side
(old/new). A failure on the **old** side is also a denial (we cannot tell what changed).

## 6. Data

### 6.1 Sources
- **OEBC**: `https://openastra.org/oebc/catalog/v0.1/latest.json.gz` (constant
  `OEBC_CATALOG_URL` in OEBC's `urls.py`), or a local `.json` / `.json.gz` via `--oebc`. Used
  fields per record: `cve_id`, `exposure_tier`, `kev_listed`, `kev_date_added`, `epss_score`,
  `cvss_score`. Catalog-level: `generated_at_utc`, `project_version`, `rules`, `count`.
- **OSV**: per-ecosystem bulk exports
  `https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip` and `.../npm/all.zip`, or a
  local directory of OSV JSON files / those zips via `--osv-dir`.

### 6.2 `update-data`
Downloads both sources into `data_dir` (default `~/.cache/exposuregate`, overridable by config,
`EXPOSUREGATE_DATA_DIR` or `--data-dir`), validates them (OEBC: `vulnerabilities` present and
`len == count`; OSV: zip opens, every record parses, ≥ 1 record per ecosystem), and builds a
local index (SQLite) mapping `(ecosystem, normalized name)` → advisories and `cve_id` → OEBC
grading fields. The new index is written to a temp file and renamed into place, so a failed
update leaves the previous data intact. A `manifest.json` records source URLs, download time,
OEBC `generated_at_utc`, and per-ecosystem OSV `as_of` (max `modified` across records) and
record counts. This is the only command that uses the network.

`scan` with `--oebc`/`--osv-dir` builds the same index in memory (or a temp file) from the given
files instead of using `data_dir`; this is the reproducible-evaluation path.

### 6.3 Freshness
- OEBC date = `generated_at_utc`. OSV date per ecosystem = max `modified` across its records.
- "Now" = `--as-of` if given, else the current UTC date.
- Stale if `now - date > max_age_days` (default 7, configurable globally and per source).
  Stale or missing data for an ecosystem the scan needs → denial `data_stale` /
  `data_missing`. An ecosystem not needed by any changed lockfile is not checked.
- `--as-of` also drops OSV advisories whose `published` is after the as-of date, and rejects
  an OEBC snapshot generated after it (denial `data_from_future`), so historical replays don't
  use knowledge from later.

### 6.4 Replay at a past date (decided 2026-11-14: option A now, B archiving started)

Neither source publishes dated history: OEBC serves only `latest`, OSV's export is current-only.
For replaying a past PR at date D (`--as-of D --replay`):

- **OEBC is rebuilt as of D** by `exposuregate rebuild-oebc --as-of D`, applying OEBC's tier
  rule (`oebc/src/oebc/generate.py`, `compute_exposure_tier`, default thresholds unless given)
  to: KEV entries with `dateAdded <= D`; the EPSS daily score file for D (or the nearest earlier
  day available, recorded); CVSS from the current OEBC catalog (CVSS rarely changes; a stated
  limitation). Same inputs as the paper's existing `paper/eval/rq3/fetch.py`. Output is an
  OEBC-shaped catalog with `generated_at_utc = D` and a `rebuilt_from` block listing every input
  file, its date and sha256. CRITICAL (the BLOCK signal) therefore depends only on KEV dates,
  which are exact.
- **OSV**: current export, minus advisories with `published > D`. Advisory ranges and aliases
  are as of today (OSV corrections after D leak in). This is reported as `osv_mode:
  current_filtered` and is a threat to validity the paper must state.
- **Freshness in replay**: the OEBC check runs against the rebuilt date (always D, so fresh).
  The OSV staleness and `data_from_future` checks are not enforced; the report records
  `replay: true` and each source's real date. `--replay` without `--as-of` is a usage error.
- **When archived snapshots cover D** (§6.5), `--archive DIR` uses them instead: OEBC/KEV as
  archived on D, OSV reconstructed as of D (`osv_mode: archived`), no leakage.

### 6.5 Snapshot archive (option B, running since 2026-11-14)

A daily job (`paper/eval/archive/archive.py`, scheduled locally) records the sources so that
future evaluations can replay PRs without leakage:
- KEV JSON and the OEBC catalog: stored once per distinct sha256, with a per-day manifest
  pointing to the blob that was current that day (and OEBC's `generated_at_utc`).
- OSV per ecosystem (PyPI, npm): stored as deltas, because full daily zips are ~260 MB. Each
  day writes `index-D.jsonl.gz` (every `id` with its `modified`) and `delta-D.jsonl.gz` (only
  records whose `(id, modified)` was not seen before; day one holds everything). The state at
  D = for each id in `index-D`, the latest record version with `modified` ≤ that index entry.
- `exposuregate` v1 must be able to read this layout via `--archive DIR` (§6.4). Format
  details are in the script's docstring.

Operational note: OEBC's newest catalog is from 2026-06-14, so with defaults every scan that
needs OEBC is currently denied until OEBC's daily build is fixed. That is the intended
fail-closed behaviour; `max_age_days` or `--fail-open` is the explicit escape hatch.

## 7. Matching and grading

### 7.1 Advisory matching
For each added/changed pin, consider every OSV advisory with an `affected[]` entry whose
`package.ecosystem` equals the pin's ecosystem and whose normalized `package.name` equals the
pin's name. Skip advisories with `withdrawn` set (at or before "now"). The pin is affected if:
- its version is in that entry's `versions` list (PyPI: compared as parsed PEP 440 versions;
  npm: string equality after stripping a leading `v`), **or**
- it falls in any `ECOSYSTEM` or `SEMVER` range per the OSV schema's evaluation rules
  (`introduced`, `fixed`, `last_affected`, `limit`; `introduced: "0"` = from the start).
  PyPI ordering: `packaging.version.Version`. npm ordering: SemVer 2.0.0 precedence.
  `GIT` ranges are ignored.

A pin version that does not parse in its ecosystem's scheme cannot be matched against ranges:
it gets one finding with reason `unparseable_version`, action `warn`. `fixed_in` on a finding
lists the `fixed` events of the matching ranges.

### 7.2 From advisory to CVE
CVE IDs of an advisory = its `id` if it matches `^CVE-\d{4}-\d{4,}$`, plus every alias that
matches. One finding per `(pin, CVE)`, listing all advisory IDs that led to that CVE. An
advisory with no CVE ID → one finding per `(pin, advisory)` with reason `no_cve`.

### 7.3 Grading and policy
Per finding:

| Reason | Condition | Default action |
|---|---|---|
| `graded` | CVE found in OEBC, tier CRITICAL | block |
| `graded` | tier HIGH | warn |
| `graded` | tier MEDIUM / LOW | pass |
| `not_in_oebc` | CVE ID not in OEBC | warn |
| `no_cve` | advisory has no CVE alias | warn |
| `unparseable_version` | §7.1 | warn |
| `unpinned` | §5.1 | warn |
| `unsupported_lockfile` | §5.5 | warn |

Then, in order:
1. `policy.transitive_max_action` (default `block`, i.e. no change) caps the action of
   `transitive` findings (e.g. set `warn` to make transitive findings advisory).
2. Suppressions (§8.2): a matching, unexpired entry sets the action to `pass` and records
   `suppressed_by`. Expired entries don't apply and are listed in `expired_suppressions`
   (and are themselves a WARN-level finding, reason `suppression_expired`).

Verdict = worst action across findings, then DENY if any enforced denial.

## 8. Configuration

`.exposuregate.yml` in the repo root, or `--config`. Deep-merged over defaults. Unknown keys,
wrong types or invalid values → exit 2 with a message (not a DENY verdict, a usage error).

```yaml
fail_closed: true
data:
  dir: ~/.cache/exposuregate
  max_age_days: 7          # default for both
  oebc_max_age_days: null  # override
  osv_max_age_days: null   # override
policy:
  CRITICAL: block
  HIGH: warn
  MEDIUM: pass
  LOW: pass
  not_in_oebc: warn
  no_cve: warn
  unparseable_version: warn
  unpinned: warn
  unsupported_lockfile: warn
  transitive_max_action: block
lockfiles:
  requirements: { enabled: true, globs: ["requirements*.txt"] }
  poetry:       { enabled: true, globs: ["poetry.lock"] }
  uv:           { enabled: true, globs: ["uv.lock"] }
  npm:          { enabled: true, globs: ["package-lock.json"] }
exclusions:
  paths: []                # fnmatch globs on repo-relative paths
suppressions: []           # see 8.2
reporting:
  format: [json, markdown]
  output_dir: .exposuregate/reports
```

CLI flags override config. Actions are `block | warn | pass`.

### 8.2 Suppressions
```yaml
suppressions:
  - id: CVE-2024-12345          # CVE or advisory ID (required)
    package: urllib3            # optional; normalized name
    ecosystem: PyPI             # optional
    reason: "not reachable: we never call X"   # required, non-empty
    expires: 2027-01-31         # required
```
Missing `reason` or `expires` → config error (exit 2).

## 9. Reports

JSON is the source of truth; a JSON Schema ships at `schemas/report.schema.json` and the tests
validate every report against it. Markdown renders the same content for humans and PR comments.
Both go to stdout (JSON first) and, if `output_dir` is set, to `report.json` / `report.md`.
Human progress lines go to stderr.

```json
{
  "tool": {"name": "exposuregate", "version": "0.1.0"},
  "verdict": "BLOCK",
  "exit_code": 1,
  "timestamp": "2026-11-14T10:00:00Z",
  "as_of": "2026-11-14",
  "input": {"mode": "pr", "base": "<sha>", "head": "<sha>"},
  "data": {
    "oebc": {"source": "...", "generated_at": "...", "age_days": 3, "count": 0,
             "project_version": "...", "rules": {}},
    "osv": {"PyPI": {"source": "...", "as_of": "...", "age_days": 0, "advisories": 0},
            "npm":  {"source": "...", "as_of": "...", "age_days": 0, "advisories": 0}}
  },
  "policy": {},
  "lockfiles": [{"path": "uv.lock", "type": "uv", "status": "graded",
                 "pins_added_or_changed": 5, "pins_skipped": 0}],
  "findings": [{
    "finding_id": "sha256 of lockfile|ecosystem|package|version|cve_id-or-advisory_id|reason",
    "lockfile": "uv.lock", "ecosystem": "PyPI", "package": "urllib3",
    "version": "1.26.4", "previous_version": null, "dependency": "transitive",
    "reason": "graded", "cve_id": "CVE-...", "advisory_ids": ["GHSA-...", "PYSEC-..."],
    "exposure_tier": "CRITICAL", "kev_listed": true, "kev_date_added": "...",
    "epss_score": 0.0, "cvss_score": 0.0, "fixed_in": ["1.26.5"],
    "base_action": "block", "action": "block", "suppressed_by": null,
    "notes": []
  }],
  "skipped": [{"lockfile": "uv.lock", "package": "mylib", "reason": "source:path"}],
  "denials": [{"code": "data_stale", "detail": "OEBC generated 2026-06-14 is 153 days old (max 7)",
               "enforced": true}],
  "expired_suppressions": [],
  "summary": {"block": 1, "warn": 0, "pass": 0, "denials": 1},
  "timing_ms": {"load_data": 0, "read_lockfiles": 0, "match": 0, "total": 0}
}
```

Denial codes: `data_missing`, `data_stale`, `data_from_future`, `data_invalid`,
`lockfile_parse`, `lockfile_unsupported`, `git_error`.

## 10. Integration

- `.pre-commit-hooks.yaml`: hook `exposuregate`, `entry: exposuregate scan --mode pre-commit`,
  `language: python`, `pass_filenames: false`, `files` regex matching the default globs.
- `docs/github-action.yml` example: checkout with `fetch-depth: 0`, cache `data_dir` keyed on
  date, run `exposuregate update-data` then `exposuregate scan --mode pr --target-branch
  ${{ github.base_ref }}`, upload `report.json`, post `report.md`.
- With no graded lockfile changed, `scan` does not check data freshness, so unrelated commits
  are never blocked by stale data. The verdict is PASS, or WARN if an unsupported lockfile
  changed (§5.5).

## 11. Testing (TDD)

Unit tests with fixtures, no network:
- Each parser: a realistic old/new fixture pair per format, covering direct vs transitive
  tagging, skipped sources, multiple versions of one name, npm aliases and nested
  `node_modules`, requirements `# via` blocks, markers, unpinned lines, continuation lines,
  and each parse-failure path (including package-lock v1).
- Matcher: `versions` list hit; `ECOSYSTEM` range with `introduced`/`fixed`; `last_affected`;
  `introduced: "0"`; multiple ranges; withdrawn; GIT range ignored; PEP 440 pre/post/local
  versions; SemVer pre-release precedence; unparseable version.
- CVE extraction: CVE as id, as alias, several aliases, several advisories → one CVE, no CVE.
- Grading/policy: every row of §7.3; `transitive_max_action`; suppressions (match, expiry,
  missing fields); every config key changes behaviour; unknown key rejected.
- Freshness: stale, missing, future, per-source overrides, `--as-of` filtering of `published`.
- Reports validate against the JSON Schema.

End-to-end in a temp git repo: pre-commit and pr modes, explicit refs, `--old/--new`, deleted
and newly added lockfiles, no lockfile changed (PASS without data), exit codes 0/1/2,
`--fail-open`.

Out of scope for this spec: the paper's real-PR evaluation harness (corpus selection,
ground-truth labelling, batch replay scripts). That will live in `paper/eval/` like the
existing RQ scripts and gets its own spec. The tool supports it through `--base/--head`,
`--old/--new`, pinned data (`--oebc`, `--osv-dir`), `--as-of`, the stable `finding_id`, and
`timing_ms`.

Planted-exposure set for the paper (mirrors ControlGate's RQ1 planted violations): for each
lockfile type, a commit that pins a known KEV-listed version (expect BLOCK), a HIGH-tier one
(WARN), a LOW one (PASS), a transitive KEV pin (BLOCK, tagged transitive), and a benign bump
(PASS). Fixture data for these is a frozen OSV + OEBC subset committed to the repo, so results
don't drift.

## 12. Left to the builder

- Module layout, class names, SQLite schema, how the in-memory index is built.
- Markdown report layout (must contain verdict, denials, findings table, data dates).
- Progress-line wording on stderr.
- Performance work. Target (for the paper's overhead RQ): a pre-commit scan with no lockfile
  change < 0.5 s; with a changed lockfile and an existing index < 3 s on a laptop. Measure,
  don't guess, and report via `timing_ms`.

## 13. Related changes outside this repo

- Paper, limitations: "as specified it sees only locked, direct dependencies" → it grades every
  locked version a change adds or changes, direct and transitive. Update when the paper moves
  to option 1 (or now, since the spec decision is made).
- `unassessed-by-design/README.md` "agreed design": add the transitive decision, exit code 2,
  `not_in_oebc` → WARN, and a pointer to this spec.

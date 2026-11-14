# Contributing to ExposureGate

Thanks for helping. ExposureGate is only useful if its verdicts can be
trusted, so most of this guide is about keeping it precise: every change in
behaviour comes with a test that proves it, and the suite has to stay at or
above 90% coverage.

- [Ways to help](#ways-to-help)
- [Reporting a wrong or missed finding](#reporting-a-wrong-or-missed-finding)
- [Development setup](#development-setup)
- [Tests](#tests)
- [Code layout](#code-layout)
- [Adding a lockfile parser](#adding-a-lockfile-parser)
- [Pull requests](#pull-requests)
- [Security](#security)
- [License](#license)

## Ways to help

- **Report a wrong or missed finding.** This is the most useful
  contribution. See the next section.
- **Run it on your repository** (`exposuregate scan --mode full`) and tell us
  what it found, in an issue. Real-world results guide what to fix next.
- **Pick up an issue** labelled
  [`good first issue`](https://github.com/sadayamuthu/exposuregate/labels/good%20first%20issue)
  or [`help wanted`](https://github.com/sadayamuthu/exposuregate/labels/help%20wanted).
- **Close a known gap** from the [Limitations](README.md#limitations) section
  of the README, or add a lockfile parser.

For anything larger than a small fix, open an issue first so we can agree on
the approach before you write the code.

## Reporting a wrong or missed finding

Please include:

1. `pip show exposuregate` output (the version) and `exposuregate data-info`
   output (the OEBC build date and the OSV export dates, since findings
   depend on them).
2. The command you ran, your `.exposuregate.yml` if you have one, and the
   JSON report (`report.json` from `--output-dir`, or `--format json`). The
   report records the data snapshot, the policy, every lockfile and every
   advisory match, so it usually shows where the verdict came from.
3. What you expected instead, and why. For a missed or wrong match, name the
   package, the version, and the OSV advisory or CVE you think applies (or
   should not).
4. A minimal reproduction: the old and new lockfile. `exposuregate scan
   --old old/uv.lock --new new/uv.lock --lockfile-type uv` runs on two files
   without git, so a pair of small lockfiles is the easiest thing to attach,
   and it becomes the test.

If the lockfile is private, reduce it to the few packages that still show the
problem.

## Development setup

You need **Python 3.10** or newer and **git**.

```sh
git clone https://github.com/sadayamuthu/exposuregate.git
cd exposuregate
python3 -m venv .venv && . .venv/bin/activate
make install-dev      # pip install -e ".[dev]"
```

The test suite needs no network: it runs against fixtures under
`tests/fixtures/`, including OSV and OEBC data frozen for the
planted-exposure set. To try the CLI on a real repository, download the data
once with `make update-data` (or `exposuregate update-data`) and check it
with `make data-info`.

Before pushing, run what CI runs (`.github/workflows/ci.yml`, on Python
3.10, 3.11 and 3.12):

```sh
python -m ruff check .
python -m mypy src
python -m pytest -q --cov=exposuregate --cov-report=term-missing
```

`make check` runs lint, typecheck and tests together, and `make format`
applies ruff's automatic lint fixes. On pull requests, CI also fails if the
version in `pyproject.toml` hasn't changed.

## Tests

Tests live in [`tests/`](tests) and use pytest. Coverage must stay at or
above 90% (`fail_under = 90` in `pyproject.toml`). mypy runs in strict mode
over `src/`.

| Path | What it covers |
|------|----------------|
| `tests/lockfiles/test_<type>.py` | One file per lockfile parser, against `tests/fixtures/lockfiles/<type>/` |
| `tests/test_classify.py`, `tests/test_diffing.py` | Lockfile classification by glob and the added/changed pin diff |
| `tests/test_versions.py`, `tests/test_osv.py` | Version ordering and OSV advisory matching |
| `tests/test_grading.py` | Policy, the transitive cap, suppressions and the verdict |
| `tests/test_store.py`, `tests/test_update.py`, `tests/test_freshness.py` | The data index, `update-data`/`data-info`, freshness checks |
| `tests/test_rebuild.py`, `tests/test_archive.py` | `rebuild-oebc` and the snapshot archive reader |
| `tests/test_gitio.py`, `tests/test_cli_e2e.py` | Git inputs and the `exposuregate` command line, end to end |
| `tests/test_report.py`, `tests/test_models.py` | JSON and Markdown reports, against `schemas/report.schema.json` |
| `tests/test_config.py`, `tests/test_readme.py` | Strict config loading; the README config block matches `DEFAULTS` |
| `tests/test_planted.py` | The planted-exposure set in `tests/fixtures/planted/cases.json` |

**Every behaviour change needs a test.** For a bug fix, add a test that fails
before your change and passes after it. For a false positive, add a test that
the offending lockfile change produces no blocking finding. If you change a
config default, update the block between the `config-defaults` markers in
the README too; `tests/test_readme.py` checks that they match.

The planted data under `tests/fixtures/planted/data/` is frozen by
`scripts/freeze_fixtures.py` from the snapshot archive. Don't edit it by hand;
refreeze it, and the script checks every expected finding in `cases.json`
against the new data.

## Code layout

| Path | What it does |
|------|--------------|
| `src/exposuregate/__main__.py` | CLI entry point: `scan`, `update-data`, `data-info`, `rebuild-oebc` |
| `src/exposuregate/scan.py` | Scan orchestration: inputs, lockfiles, data, grading, report, exit code |
| `src/exposuregate/gitio.py` | Changed paths and blob reads at a ref or the index |
| `src/exposuregate/lockfiles/` | One parser per lockfile type; `__init__.py` holds `PARSERS`, `ECOSYSTEM` and `classify()` |
| `src/exposuregate/diffing.py` | Diffs two parsed lockfiles into added and changed pins |
| `src/exposuregate/versions.py` | Name normalisation and version ordering (PEP 440, SemVer) |
| `src/exposuregate/osv.py` | OSV advisory matching and CVE extraction |
| `src/exposuregate/grading.py` | Policy, suppressions and the verdict |
| `src/exposuregate/store.py`, `update.py`, `freshness.py` | The SQLite data index, its download (the only network code), freshness |
| `src/exposuregate/rebuild.py`, `archive.py` | Historical replay |
| `src/exposuregate/config.py` | `.exposuregate.yml` loading, `DEFAULTS` and strict validation |
| `src/exposuregate/report.py` | JSON and Markdown reports |
| `schemas/report.schema.json` | JSON Schema for the report |
| `action.yml`, `docs/github-action.yml` | The composite GitHub Action and the raw-steps example workflow |
| `.pre-commit-hooks.yaml` | The pre-commit hook |
| `skills/` | Instructions for AI coding agents |

## Adding a lockfile parser

1. Add `src/exposuregate/lockfiles/<type>.py` with a `parse_<type>(text)`
   function that returns a `ParsedLockfile` (`models.py`): one `Pin` per
   locked package, with its normalised name (`versions.normalize_name`), its
   exact version and `dependency` set to `direct`, `transitive` or
   `unknown`. Sources that can't be graded (git, path, URL, editable,
   workspace) go into `skipped` with a reason, not into `pins`. Raise
   `LockfileError` on a file that doesn't parse, so the scan denies it
   instead of guessing.
2. Register it in `PARSERS` and `ECOSYSTEM` in `lockfiles/__init__.py`.
   `--lockfile-type` takes its choices from `PARSERS`.
3. Add a `lockfiles.<type>` entry (`enabled`, `globs`) to `DEFAULTS` in
   `config.py`, remove its basename from `unsupported_globs` if it's there,
   and update the README config block to match.
4. If it's a new ecosystem, version ordering in `versions.py`, OSV matching
   and `update-data --ecosystems` need it too.
5. Add fixtures under `tests/fixtures/lockfiles/<type>/` (real files from
   the tool's current format versions, kept small) and
   `tests/lockfiles/test_<type>.py` with direct, transitive, skipped-source
   and malformed cases. Add planted cases for the new type to
   `tests/fixtures/planted/cases.json`, and document it in the README's
   "What It Grades" table.

When a lockfile can't say whether a package is direct or transitive, tag it
`unknown` rather than guessing; when it can't be parsed with confidence,
fail closed rather than grade part of it.

## Pull requests

- Keep each PR to one change; small PRs get reviewed faster.
- Use the commit message style in the history: `type: summary`, for example
  `fix: robust OSV withdrawn date parsing`. Types in use: `feat`, `fix`,
  `test`, `docs`, `ci`, `build`, `chore`.
- Bump the version in `pyproject.toml` and `__version__` in
  `src/exposuregate/__init__.py`, and add an entry to
  [CHANGELOG.md](CHANGELOG.md). A new version on `main` is published to PyPI
  and tagged by CI.
- CI must pass.
- Update README.md when you change behaviour a user can see.

## Security

Please don't report security problems in a public issue. Use
[**Report a vulnerability**](https://github.com/sadayamuthu/exposuregate/security/advisories/new)
on the repository's Security tab instead. See [SECURITY.md](SECURITY.md) for
what to include and what's in scope.

## License

ExposureGate is licensed under the [MIT License](LICENSE). By contributing,
you agree that your contributions are licensed under the same license.

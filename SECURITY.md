# Security Policy

## Reporting a vulnerability

Please don't report security problems in a public issue, pull request or
discussion. Use
[**Report a vulnerability**](https://github.com/sadayamuthu/exposuregate/security/advisories/new)
on the repository's Security tab instead. Only the maintainer can see the
report.

Include what you can of:

- the output of `pip show exposuregate` and `exposuregate data-info`, your
  Python version and your OS
- how ExposureGate was run: the CLI (`scan`, `update-data`, `data-info`,
  `rebuild-oebc`), the pre-commit hook, the composite GitHub Action
  (`action.yml`) or the example workflow (`docs/github-action.yml`)
- steps to reproduce, ideally a small repository, a pair of lockfiles or a
  script that builds one
- what happened and what you expected

You'll get a reply when the report has been read, and again when a fix is
ready. A fix ships as a patch release; the advisory names you unless you'd
rather it didn't.

## Supported versions

ExposureGate is pre-1.0. Fixes land in the latest release only; please
upgrade before reporting.

## What counts

ExposureGate reads lockfiles you may not trust, such as those in a pull
request from a fork. It parses them as text (TOML, JSON or requirements
lines); it never runs a package manager, installs anything, or imports the
code it grades. Anything that breaks one of the following is a security
issue:

- **Scanning only reads, and never uses the network.** `exposuregate scan`
  reads lockfiles and manifests from git (the index, or a ref) or from the
  files given with `--old`/`--new`, plus `.exposuregate.yml` and the local
  data snapshot. The only files it writes are its reports, under the
  configured output directory (`.exposuregate/reports/` by default). A
  lockfile, file name, branch name, ref or `.exposuregate.yml` that makes it
  run a command, pass options of an attacker's choosing to `git`, write
  anywhere else, change the repository, or make a network call is in scope.
- **Parsing is safe.** Input that makes a parser or the version matcher hang,
  or use memory far beyond the size of the input, is in scope.
- **Failing closed.** A lockfile or data snapshot crafted so that a scan
  returns PASS or WARN, with exit code 0, where the documented behaviour is
  BLOCK or DENY (for example, a parse failure or malformed data that is
  silently ignored instead of denied) is in scope.
- **The data download.** `exposuregate update-data` is the only command that
  uses the network. It downloads the OEBC catalog from `openastra.org` and
  the OSV exports from `osv-vulnerabilities.storage.googleapis.com` over
  HTTPS, validates them, and writes the index into the data directory with
  an atomic rename. A way to make it fetch from another location, write
  outside the data directory, or behave unsafely on a malformed download is
  in scope.
- **The GitHub Action and the example workflow** (`action.yml`,
  `docs/github-action.yml`). They run on pull requests, and the example
  workflow posts the Markdown report as a pull request comment with
  `pull-requests: write`. Script injection through branch names, file names,
  action inputs or report text, or report content that can do more than
  display in the comment or the job summary, is in scope.

A wrong verdict that the data explains, such as a vulnerable version OSV
doesn't list, or a CVE whose OEBC tier is out of date, is a bug or a data
issue, not a vulnerability. Report it in a normal issue; see
[CONTRIBUTING.md](CONTRIBUTING.md).

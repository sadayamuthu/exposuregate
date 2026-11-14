---
description: How to run ExposureGate on a lockfile change and fix exploited-vulnerability findings
---

# Workflow: Scan and Fix with ExposureGate

This workflow defines the standard operating procedure for using ExposureGate to find and fix vulnerable dependency versions before a lockfile change is committed.

1. **Refresh the Data:**
   Use the `run_command` tool to make sure the local OSV and OEBC snapshot exists and is current.
   ```bash
   exposuregate update-data
   exposuregate data-info
   ```

2. **Stage and Scan:**
   Pre-commit mode grades the staged lockfiles, so stage the lockfile, then scan.
   // turbo
   ```bash
   git add uv.lock poetry.lock requirements*.txt package-lock.json 2>/dev/null
   exposuregate scan --output-dir .exposuregate/reports
   ```

3. **Check the Verdict:**
   Read `.exposuregate/reports/report.json`. Exit code `0` is PASS or WARN, `1` is BLOCK, `2` is DENY or a usage error.
   - On `DENY`, read `denials[]`. For `data_stale` or `data_missing`, run `exposuregate update-data` and go back to step 2. If it is still denied, stop and tell the user; do not add `--fail-open` or `--max-age-days` yourself.

4. **List What to Fix:**
   From `findings[]`, take each finding whose `action` is `block`, then each whose `action` is `warn`. Note its `lockfile`, `package`, `version`, `dependency`, `cve_id`, `kev_listed` and `fixed_in`.

5. **Pick the Fixed Version:**
   Choose the lowest version in `fixed_in` that is newer than `version`, preferring the same major version. If `fixed_in` is empty, stop and tell the user that no fixed release is known.

6. **Update the Lockfile:**
   Use the package manager that owns the lockfile, never a hand edit:
   - uv: `uv lock --upgrade-package <package>==<fixed version>`
   - Poetry: `poetry add "<package>>=<fixed version>"` (direct) or `poetry update <package>` (transitive)
   - pip-compile: `pip-compile --upgrade-package "<package>==<fixed version>"`
   - npm: `npm install <package>@<fixed version>` (direct), or an `overrides` entry in `package.json` and `npm install` (transitive)

7. **Verify the Fix:**
   Stage the updated lockfile and re-run the scan until no `block` findings remain.
   // turbo
   ```bash
   exposuregate scan --output-dir .exposuregate/reports
   ```

8. **Report:**
   Summarize the version moves to the user, the CVEs each one resolved and whether they were KEV-listed. List any remaining `warn` findings for the user to decide on. Never resolve a finding by adding a suppression; if the user wants one, it must have a `reason` and an `expires` date.

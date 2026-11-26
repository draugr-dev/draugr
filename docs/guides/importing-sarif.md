---
title: Import another scanner's SARIF
description: Read a SARIF file that CodeQL, Checkmarx, Bandit or any other tool wrote into one of Draugr's controls, so its findings are ranked and gated with the rest.
section: Guides
order: 27
---

# Import another scanner's SARIF

A component can read a SARIF 2.1.0 file that another tool wrote. The file's findings join the
control the descriptor names: they take the component's exposure and criticality into their
priority, count toward the gate, and appear in **Fix first** beside the findings of Draugr's own
scanners. Draugr does not run the tool. It reads the file an earlier pipeline step left behind.
Trivy's, govulncheck's, Grype's and OSV-Scanner's own JSON can be imported the same way, and keeps
more than their SARIF does ([Import a tool's own JSON](#import-a-tools-own-json)).
A repository's GitHub code-scanning and Dependabot alerts can be read from GitHub with no
file at all ([Import GitHub's alerts](#import-githubs-alerts)).

The steps below use Bandit, which writes no commit into its SARIF, so they include binding the file
to the commit it scanned. Another tool's file follows the same steps, with its own export command and
quirks ([Import each tool's file](importing-each-tool.md)) and the limits
[Before you import](../../internal/scanners/sarif-import.md#before-you-import) lists. The ones a
first import meets:

- **A finding the control's own scanner also reports is counted once.** Semgrep's file imported
  into `sast` beside Draugr's Semgrep run, or Trivy's into `sca` beside `trivy-fs`, lists each
  finding once and names both scanners. A dependency finding merges on its advisory and package, a
  code finding on its rule, file and line. In a component with several repositories, a file merges
  only where its `versionControlProvenance` names the repository it scanned.
  [Merging with the control's scanners](../../internal/scanners/sarif-import.md#merging-with-the-controls-scanners)
  lists what stays apart, such as Bandit's rule beside Semgrep's on the same line.
- **Severity comes from `security-severity`, written as a string or a number, then from the tool's
  own rating, then from the level.** Draugr reads the rating Bandit, gosec, CodeQL, Fortify Static
  Code Analyzer, OWASP dependency-check and Snyk Open Source write
  ([each tool's own rating](../../internal/scanners/sarif-import.md#each-tools-own-rating)). For
  another tool, name the property it rates in with the import's
  [`severity`](../reference/saga-schema.md#componentsimports). A file rated by level alone never
  yields critical, and one that writes only `warning` ranks P2 at most, below the default gate,
  unless KEV or EPSS raises a finding whose rule id is a CVE.
- **A dependency finding's package and fix are read where the tool states them**, for Trivy's,
  Grype's and OSV-Scanner's files, so their findings in one package become one upgrade to the
  release that clears them. [Dependency findings](../../internal/scanners/sarif-import.md#dependency-findings)
  lists where each tool puts them. A file that names no package, as most code scanners' do, gets a
  "Fix <rule>" action per rule.
- **KEV and EPSS need a CVE**, in the rule id or listed by the file beside it, as OSV-Scanner lists
  an advisory's other identifiers. Grype's SARIF names its findings by GitHub and Go advisory and
  lists no CVE, so neither reaches them; [import Grype's JSON](#import-a-tools-own-json) instead.
  **Signals** counts the imported findings that name no CVE.
- **Paths are read relative to the repository's root.** An absolute path or `file://` URI inside the
  component's repository, when its `url` is a local path, is made relative to it. Any other absolute
  path is kept as written: its finding still counts, the scan lists the path under `unread-files`,
  and [`config.exclude`](../reference/saga-schema.md#configexclude) paths and links to the line do
  not match it. A component whose `url` is a remote address has no local directory to compare
  against, so write the file's paths relative to the repository root.
- **The repository's `paths:` and `ignore:` apply to the file.** A finding outside them is left out
  of the component, so one file written for a whole monorepo splits between the components that
  import it. A left-out finding is not counted, and **Measured against** says how many, as `left
  out: 3 findings outside paths, not counted`. In a component with several repositories, a file that
  names none of them, or more than one, isn't scoped and shows as `not scoped`: name the repository
  in its `versionControlProvenance` ([several repositories](#in-a-component-with-several-repositories))
  to scope it.
  [Paths and ignore](../../internal/scanners/sarif-import.md#paths-and-ignore) has the rules.
- **The file's own suppressions hold.** A result the tool suppressed stays in the report, set
  aside, on an **Accepted** row named for the tool, and `--evidence` lists where the tool suppressed
  each and why, as
  [Findings an imported tool suppressed](../reference/saga-schema.md#findings-an-imported-tool-suppressed)
  shows. A suppression whose `status` is `rejected` or `underReview` leaves the finding counting.
  To count one file's suppressed findings, set `suppressions: count` on its import; to count a
  single finding, remove its suppression in the tool and export the file again.

## 1. Write the SARIF file

Run the tool in a step before the scan. Bandit writes SARIF only with its `sarif` extra installed,
and `--exit-zero` leaves the verdict to Draugr's gate, since Bandit otherwise exits non-zero when it
finds something:

```bash
pipx install 'bandit[sarif]'
bandit -r app -f sarif -o bandit.sarif --exit-zero
```

Where a CI step already writes or uploads SARIF, or the repository holds a `.sarif` file,
[`draugr init`](../reference/cli.md#draugr-init-dir) proposes the import in step 3 for you,
commented out, with the control the tool's findings go in.

## 2. Name the commit the file describes

A SARIF file left from an earlier run reads exactly like a current one. Name the commit the tool
scanned with the import's `commit`, and Draugr holds the file to the commit this run reads:

```yaml
imports:
  - control: sast
    file: reports/bandit.sarif
    commit: ${{ GITHUB_SHA }}
```

- **The same commit:** the file is read, and the report names the commit.
- **A different commit:** the run stops with an error naming both. Run the tool again on this
  commit, or remove the import.
- **No commit:** the file is read, and the report lists it under **Caveats** as `unbound-imports`.

The variable each CI sets to the commit it checked out:

- GitHub Actions: `${{ GITHUB_SHA }}`
- GitLab CI: `${{ CI_COMMIT_SHA }}`
- Azure Pipelines: `${{ BUILD_SOURCEVERSION }}`

On a `pull_request` run, `GITHUB_SHA` is the merge commit `actions/checkout` checks out by default.
A workflow that checks out the pull request's head commit instead sets `GIT_SHA:
${{ github.event.pull_request.head.sha }}` in its `env:`, and the import names `${{ GIT_SHA }}`.

Where the variable is not set, as on a laptop, the file is read unbound and **Measured against**
reads `commit: not stated, ${{ GITHUB_SHA }} is not set`.

A tool that writes the commit into the file, in `runs[].versionControlProvenance`, needs no
`commit`. To see whether a tool does:

```bash
jq '.runs[].versionControlProvenance' bandit.sarif
```

Bandit's prints `null`. Where the file and `commit` both name a commit and they differ, the run
stops naming both: fix `commit`, or run the tool again.

### In a component with several repositories

With several repositories, the file names the one the tool scanned, in `versionControlProvenance`.
A file that names none of them, or more than one, stays unbound. Add the repository and the commit
from the checkout the tool ran in:

```bash
mkdir -p reports
jq --arg uri "$(git remote get-url origin)" --arg rev "$(git rev-parse HEAD)" \
  '.runs[].versionControlProvenance = [{repositoryUri: $uri, revisionId: $rev}]' \
  bandit.sarif > reports/bandit.sarif
```

`git remote get-url origin` prints the address as the remote holds it. Where that address carries a
credential, as `https://user:token@host/…` does, pass the address without it, since the SARIF file is
often kept as a pipeline artifact. A checkout with no remote has no address to print; pass the
repository's address as Draugr's descriptor names it. The address has to name one of the
component's repositories.

## 3. Declare the import

```yaml
components:
  - name: api
    exposure: public
    criticality: important
    imports:
      - control: sast
        file: reports/bandit.sarif   # relative to where Draugr runs
```

`control` names the control that reports the findings, such as `sast` or `sca`, and `commit` is
step 2's, where the pipeline sets it. A finding in the file belongs to the component that imports it
where its path is inside the `paths:` and `ignore:` of the component's repository. A component can
import several files, one entry each.

## 4. Scan

```console
$ draugr scan --controls sast --components api --top 3
DRAUGR  FAIL  draugr-demo 1.0  8.172s

 9 P1 6 P2 6 P3 0 P4
 Scoped to 1 of 3 components and the sast control.

CONTROLS
  sast  FAIL   9 P1 6 P2 6 P3

MEASURED AGAINST
  sast  sarif-import · tool: Bandit 1.9.4 · file: reports/bandit.sarif · written: 2026-10-11
        04:57 UTC · severity: issue_severity and issue_confidence · commit: not stated ·
        component: api · sha256:
        989dfee1ddac26aab9d76c86197c84eb29af9d5a375cd4fa923873fcf61bc6a2

CAVEATS  do not fail the run · config.gate.failOnCaveats lists the kinds that do
  unbound-imports · api
    reports/bandit.sarif  names no commit, so nothing ties its findings to this code

COMPONENTS
  api         FAIL   9 P1 6 P2 6 P3
  storefront  not scanned
  platform    not scanned

SIGNALS
  KEV   nothing listed
  EPSS  nothing raised

FIX FIRST  3 of 21 findings, by priority
  P1  critical  python.lang.security.dangerous-system-call.dangerous-system-call
      Found user-controlled data used in a system call. This could allow a malicious actor to…
      Run the command as an argument list, without a shell
      scanner semgrep oss · fix change the code
      app/app.py:16 · impact high · likelihood high

  P1  high      B605
      Starting a process with a shell, possible injection detected, security issue.
      Run the command as an argument list, without a shell
      scanner bandit · fix change the code
      app/app.py:16 · issue_severity high

  P1  high      B602
      subprocess call with shell=True identified, security issue.
      Run the command as an argument list, without a shell
      scanner bandit · fix change the code
      app/app.py:23 · issue_severity high

… and 18 more findings, not listed.

TRY
  --top 0                                  every one of them, not the first three
  --report json,sarif,html -o .draugr/out  every finding in one searchable page
  --view compact                           one line each, to see how much there is
  --view actions                           the same findings as a list of things to do
  config.exclude                           set aside; findings stay, suppressed
    - rules: [<full rule id>]
      paths: [<file without :line>]
      reason: <why it is set aside>
      expires: <YYYY-MM-DD>
  draugr explain <rule>                    what a rule means and how to fix it, from .draugr/out
```

This run is [`draugr-demo`](https://github.com/draugr-dev/draugr-demo), whose `api` component
declares the step 3 import and is `exposure: public` and `criticality: important`, so Bandit's
high-severity findings rank P1. Draugr did not run Bandit, so **Measured against** states what the
file says about itself: the tool and version, when it was written, where severities came from, the
commit it was checked against, and its SHA-256. Neither the file nor the import names a commit, so
the run reads `commit: not stated` and lists the file under **Caveats** as `unbound-imports`, which
does not fail the run. Step 5 makes it fail; the GitHub Actions example below names the commit.

## 5. Require the commit

To make a file that names no commit fail the run, list the caveat kind in the gate:

```yaml
config:
  gate:
    failOnCaveats: [unbound-imports]
```

The run then fails with the caveat marked `✗` and its component marked `ERROR`, and
`--allow-scan-errors` accepts it. `--fail-on-caveats unbound-imports` sets the same for one run.

## In GitHub Actions

```yaml
steps:
  - uses: actions/checkout@v4
  - name: Bandit
    run: |
      pipx install 'bandit[sarif]'
      mkdir -p reports
      bandit -r app -f sarif -o reports/bandit.sarif --exit-zero
  - uses: draugr-dev/draugr@v0
    with:
      saga: draugr.saga.yaml
      tools: true
```

The import names `commit: ${{ GITHUB_SHA }}`, as in [step 2](#2-name-the-commit-the-file-describes).

## Import a tool's own JSON

Trivy's SARIF states each finding's package and fixed version only in prose, and often scores it by
severity alone (5.5 for MEDIUM) where its JSON carries the CVSS score. govulncheck's has no call
path, Grype's lists no CVE, so KEV and EPSS can't reach its findings, and OSV-Scanner's carries no
score. Their own JSON keeps all of it, so import that instead and name the format:

```bash
trivy fs --format json -o reports/trivy.json .
govulncheck -format json ./... > reports/govulncheck.json    # one file per Go module, see below
grype dir:. -o json=reports/grype.json    # a directory scan; an image scan is refused
osv-scanner scan --format json . > reports/osv-scanner.json    # an image scan is refused
```

```yaml
imports:
  - control: sca
    file: reports/trivy.json
    format: trivy-json
    commit: ${{ GITHUB_SHA }}
  - control: sca
    file: reports/govulncheck.json
    format: govulncheck-json
    commit: ${{ GITHUB_SHA }}
  - control: sca
    file: reports/grype.json
    format: grype-json
    commit: ${{ GITHUB_SHA }}
  - control: sca
    file: reports/osv-scanner.json
    format: osv-scanner-json
    commit: ${{ GITHUB_SHA }}
```

Draugr reads each file with the parser its own `trivy-fs`, `govulncheck` and `grype-fs` scanners
use, so an imported finding carries the package, the installed and fixed versions and, from
govulncheck, the reachability verdict with its call path, as a native run's does. Draugr does not
run OSV-Scanner, and reads its file into findings of the same shape. A Grype or OSV-Scanner finding
carries its CVE, so it merges with another scanner's finding of that CVE. A govulncheck verdict
moves the priority of the `trivy-fs` finding for the same advisory, as a native run's verdict does.
What differs from a SARIF import:

- **Severity is the native run's**, and the import takes no `severity` mapping:
  - Trivy: the CVSS score, else Trivy's severity.
  - Grype: the CVSS score, else Grype's severity.
  - govulncheck: medium, since its database publishes none.
  - OSV-Scanner: the CVSS score it gives the vulnerability, else the advisory's severity, else
    medium.
- **govulncheck analyzes the one Go module it runs in.** In a repository with several, run it in
  each, `govulncheck -C <dir> -format json ./... > reports/govulncheck-<dir>.json`, and import each
  file. A module no imported file analyzed appears under `unread-files`, and its findings keep their
  manifest scanner's band, with no reachability verdict.
- **Only `commit` binds the file**, since none of the tools writes a commit into its JSON. A
  govulncheck file that is not bound lowers nothing: its unreachable verdicts are read as
  undetermined, and its reachable ones still apply.
- **Grype's file is a scan of a directory**, `grype dir:<path>`. An image scan is about the image,
  not the component's repositories, so it is refused.
- **OSV-Scanner's file holds lockfiles and SBOMs**, each placed by its path in the repository. A
  container image's or a git repository's results are refused.
- **What OSV-Scanner's `osv-scanner.toml` ignores is not in its file**, so Draugr never sees or
  counts it, and nothing in Draugr's report records that it was ignored, by whom, or why. The
  reason appears only on OSV-Scanner's standard error, as OSV-Scanner 2.7.1 printed it:
  `GHSA-29mw-wpgm-hmr9 and 1 alias have been filtered out because: test`. To keep such a decision
  in the report, with its reason, set the finding aside in the descriptor's `config.exclude`
  instead. An `osv-scanner-json` import takes no `suppressions`.
- **The JSON names no repository.** In a component of several repositories, its findings merge with
  no native copy and are not scoped by `paths:` and `ignore:`, and `commit` cannot bind the file.
  Import it into a component of one repository.

[A tool's own JSON](../../internal/scanners/sarif-import.md#a-tools-own-json) lists what each format
carries and what is left out.

## Import Veracode Pipeline Scan

Veracode writes no SARIF of its own. Pipeline Scan writes its results as JSON when it runs with
`-jo true` (`json_output`), to `results.json` unless `json_output_file` names another file. Run
Pipeline Scan that way in the job, then import the file it writes into `sast`:

```yaml
imports:
  - control: sast
    file: results.json
    format: veracode-pipeline-json
    commit: ${{ GITHUB_SHA }}
```

- **Each flaw is a finding** at its file and line, under its CWE, as `CWE-89`, with Veracode's
  explanation as its detail.
- **Rated by Veracode's severity:** 5 (Very High) as critical, 4 (High) as high, 3 (Medium) as
  medium, and 2, 1 and 0 (Low, Very Low, Informational) as low.
- **A Java class is named by its bare file name.** Where the component has one local checkout,
  Draugr places it at the one file there whose path ends with that name. If no file or several
  match, the finding keeps the name as written. A JavaScript file is named by its path already.
- **Import `results.json`, not `filtered_results.json`.** Pipeline Scan writes the second with only
  the flaws that violate its pass-fail criteria, and a flaw missing from the file is one Draugr never
  counts.
- **A scan whose `scan_status` is not `SUCCESS` is refused**, since its file may hold some of the
  flaws or none.
- **The import takes no `severity` mapping and no `suppressions`**: the file states its own rating
  and records no suppression.

## Import GitLab's security reports

GitLab's analyzers write their findings in GitLab's security report format rather than SARIF, and
other tools write it for GitLab too, such as Semgrep with `--gitlab-sast`. Draugr reads two of its
schemas, at version 15.x:

- **`gitlab-sast`**, the `gl-sast-report.json` of a SAST scan, for `sast`;
- **`gitlab-dependency-scanning`**, the `gl-dependency-scanning-report.json` of a dependency scan, for
  `sca`.

```bash
semgrep scan --config p/default --gitlab-sast -o gl-sast-report.json
```

```yaml
imports:
  - control: sast
    file: gl-sast-report.json
    format: gitlab-sast
    commit: ${{ CI_COMMIT_SHA }}
  - control: sca
    file: gl-dependency-scanning-report.json
    format: gitlab-dependency-scanning
    commit: ${{ CI_COMMIT_SHA }}
```

- **A SAST vulnerability is a finding** at its file and line, under its first identifier, whatever
  its type, such as `python_flask_rule-flask-tainted-sql-string`. Its `cwe` identifiers give its
  CWE, and its description is the detail.
- **A SAST finding names the scanner the vulnerability states**, such as `Find Security Bugs` in a
  SpotBugs report.
- **A dependency vulnerability is a finding** in the package at the version installed, in the file
  the report names. Its rule is its first CVE, so KEV and EPSS reach it, else its first GHSA id,
  else its first identifier. Its other CVE and GHSA ids are its aliases.
- **The fixed version is read from `solution`** in the two forms Gemnasium writes,
  `Upgrade to version 0.3.3 or above.` and `Upgrade to v1.9.0 or greater.` A solution in any other
  form leaves the finding with no fixed version, and its text is kept in the finding's detail.
- **Go and npm packages get a package URL and ecosystem**: those in `go.mod`, `go.sum`,
  `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` and `pnpm-lock.yaml`. A
  package in any other file has neither.
- **Rated by the severity the report states:** `Critical`, `High`, `Medium` and `Low` as their
  bands, and `Info` as low. `Unknown`, or no severity, ranks high, and the finding says so:
  `not scored yet` on a dependency, `not rated, so ranked high` on code.
- **Only `commit` binds the file**, since a GitLab report names no commit.
- **A report is refused** when its schema version or scan type is another, when its `status` is
  `failure`, when a severity is not one of GitLab's, or when a vulnerability names no file,
  identifier or package. Each error says which.
- **The import takes no `severity` mapping and no `suppressions`**: the report states its own rating
  and records no suppression.

## Import JFrog Xray

`jf audit` writes SARIF, but it folds each dependency finding's CVE, package and version into the
rule id, such as `CVE-2020-8203_lodash_4.17.0`, and gives the fixed version only in a property. Its
`simple-json` keeps each as a field, so import that into `sca`:

```bash
jf audit --format simple-json > reports/jfrog.json
```

```yaml
imports:
  - control: sca
    file: reports/jfrog.json
    format: jfrog-simple-json
    commit: ${{ GITHUB_SHA }}
```

- **Each vulnerable package is a finding** at the version installed, in each manifest that declares a
  direct dependency bringing it in. Its rule is its first CVE, so KEV and EPSS reach it, else Xray's own
  id, such as `XRAY-609848`. Its other CVEs and Xray's id are its aliases, and its detail names the
  direct dependency that brings it in.
- **The fixed version is read where Xray names a single version**, `[4.17.19]`. Several such versions
  are joined with commas, as Trivy's are. A fix written as a range, such as `(,1.2.0)`, leaves the finding with
  no fixed version, and the range is kept in its detail.
- **Go and npm packages get a package URL.** Every package keeps the type Xray names, such as `npm`
  or `Maven`, as its ecosystem.
- **Rated by Xray's severity:** `Critical`, `High`, `Medium` and `Low` as their bands, and
  `Information` as low. `Unknown`, or no severity, ranks high, and the finding says `not scored yet`.
- **JFrog's contextual analysis is kept in the detail and changes no priority.** A finding JFrog
  marks `Not Applicable` ranks as any other does.
- **A violation a watch raised is read as well**, and a vulnerability listed in both places is one
  finding.
- **With `--watches`, `--project` or `--repo-path`**, also pass `--vuln`, or the file holds only what
  Xray's policies flag. Pass `--fail=false` too: a matched Fail build rule otherwise exits 3 and stops
  the pipeline before Draugr reads the file.
- **Only the dependency scan is read.** The file's SAST, secrets and IaC findings are left out.
  Reading them is tracked in https://github.com/draugr-dev/draugr/issues/2477.
- **Only `commit` binds the file**, since it names no commit.
- **A file is refused** when its dependency scan did not run or failed, when it lists an error, when
  a severity is not one of Xray's, or when a vulnerability names no package, advisory id or manifest.
  Each error says which.
- **The import takes no `severity` mapping and no `suppressions`**: the file states its own rating
  and records no suppression.

## Import GitHub's alerts

Where a repository's code scanning or Dependabot already runs on GitHub, Draugr can read its alerts
straight from GitHub's REST API, with no file and no step that writes one. Name the source in place
of a file:

```yaml
components:
  - name: api
    repositories:
      - url: https://github.com/acme/api
    imports:
      - control: sast
        source: github-code-scanning
      - control: sca
        source: github-dependabot
```

Then scan with a token that can read the repository's security alerts in `GITHUB_TOKEN`: a classic
token with `security_events`, or `public_repo` for a public repository. In GitHub Actions,
`GITHUB_TOKEN` reads them where the workflow grants `permissions: security-events: read` for code
scanning and `vulnerability-alerts: read` for Dependabot. A token in another variable is named
with `tokenEnv`, and the pipeline lists that variable in `$DRAUGR_TOKEN_ENVS`:

```bash
DRAUGR_TOKEN_ENVS=GH_TOKEN GH_TOKEN=$(gh auth token) draugr scan
```

```yaml
      - control: sca
        source: github-dependabot
        tokenEnv: GH_TOKEN
```

What to expect:

- **A component of several repositories names one per import** with `repository: owner/name`.
- **An alert a person dismissed in GitHub is set aside**, on an `ACCEPTED` row named for the service
  and the tool, with who dismissed it and why. `suppressions: count` counts it instead.
- **An alert a bot dismissed counts either way**, since a workflow is not a person's decision about
  the finding, and so does one Dependabot dismissed by its own rules. Its detail names who dismissed
  it and gives the `config.exclude` entry that sets it aside here.
- **Code-scanning alerts are ranked from less than a score**: GitHub returns a severity bucket and no
  score, package or fixed version. Dependabot alerts carry the CVE, a CVSS score, the package and
  the first patched version, so they become upgrades and reach KEV and EPSS.
- **Dependabot names no commit**, so its import is always listed under **Caveats** as
  `unbound-imports`. A code-scanning analysis GitHub last ran at another commit, such as a weekly
  Scorecard run, makes the import unbound too.
- **GitHub's refusals stop the run**: a repository without GitHub Code Security, one with
  Dependabot alerts off, a token GitHub refuses, or a repository it cannot see. None reads as a
  repository with no alerts.

[GitHub's alerts](../../internal/scanners/sarif-import.md#githubs-alerts) has how each alert is read,
the binding to a commit, and every error.

A tool that writes neither SARIF nor a JSON Draugr reads, such as `npm audit`, reaches a scan
through a converter your pipeline runs on its output: [Write a converter](writing-a-converter.md).

## See also

- [Import each tool's file](importing-each-tool.md): the export command, the control and the quirks
  for CodeQL, Snyk, Checkmarx One, Fortify, Semgrep, Checkov, KICS, gosec and others.
- [`components[].imports`](../reference/saga-schema.md#componentsimports) in the Saga reference.
- The [`sarif-import` scanner](../../internal/scanners/sarif-import.md): how severities are read,
  every field under **Measured against**, and the errors a file can produce.
- [The verdict and the gate](../concepts/verdict-and-gating.md), for caveats and
  `failOnCaveats`.

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
file at all ([Import GitHub's alerts](#import-githubs-alerts)), and so can a SonarQube project's
security issues ([Import SonarQube](#import-sonarqube)).

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
`simple-json` keeps each as a field. The same file holds JFrog's SAST, secrets and IaC findings, so
import it once into each control it covers:

```bash
jf audit --format simple-json > reports/jfrog.json
```

```yaml
imports:
  - control: sca
    file: reports/jfrog.json
    format: jfrog-simple-json
    commit: ${{ GITHUB_SHA }}
  - control: sast
    file: reports/jfrog.json
    format: jfrog-simple-json
    commit: ${{ GITHUB_SHA }}
  - control: secrets
    file: reports/jfrog.json
    format: jfrog-simple-json
    commit: ${{ GITHUB_SHA }}
  - control: iac
    file: reports/jfrog.json
    format: jfrog-simple-json
    commit: ${{ GITHUB_SHA }}
```

Each import reads only its control's findings, and an import of a control whose scan the file does
not record is refused, so drop the ones your `jf audit` does not run.

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
- **A violation a watch raised is read as well**, and a finding listed in both places is one finding.
- **With `--watches`, `--project` or `--repo-path`**, also pass `--vuln`, or the file holds only what
  Xray's policies flag. Pass `--fail=false` too: a matched Fail build rule otherwise exits 3 and stops
  the pipeline before Draugr reads the file.
- **A SAST, secrets or IaC finding is read at its file and line** under JFrog's rule id, such as
  `js-template-injection`, with the CWE a SAST rule names. It is rated by JFrog's severity, as a
  dependency finding is, except that `Unknown` or no severity says `not rated, so ranked high`.
- **A secret's token validation is kept in the detail and changes no priority.** A secret JFrog marks
  `Not a token` ranks as any other does.
- **Only `commit` binds the file**, since it names no commit.
- **A file is refused** when the scan for the import's control did not run or failed, when it lists an
  error, when a severity is not one of JFrog's, when a vulnerability names no package, advisory id or
  manifest, or when a code finding names no rule or file. Each error says which.
- **The import takes no `severity` mapping and no `suppressions`**: the file states its own rating
  and records no suppression.

## Import Checkmarx One

Checkmarx One's JSON holds a scan's SAST, SCA and KICS results in one file. Import that file once
into each control whose results you want, and each import reads its own:

```bash
cx results show --scan-id <id> --report-format json --output-path reports    # writes reports/cx_result.json
```

```yaml
imports:
  - control: sast
    file: reports/cx_result.json
    format: checkmarx-one-json
    commit: ${{ GITHUB_SHA }}
  - control: sca
    file: reports/cx_result.json
    format: checkmarx-one-json
    commit: ${{ GITHUB_SHA }}
  - control: iac
    file: reports/cx_result.json
    format: checkmarx-one-json
    commit: ${{ GITHUB_SHA }}
```

- **A SAST result is a finding** at the file and line where its data flow starts, as Checkmarx's
  SARIF places it, under its query, such as `SQL_Injection`, with its CWE. Its description is the
  detail, followed by the file and line the data flows to.
- **An SCA result is a finding** in the package at the version installed, in each manifest
  Checkmarx names. Its rule is its CVE, so KEV and EPSS reach it, else Checkmarx's own id. Its fixed
  version is Checkmarx's recommended version, and where it is not itself a direct dependency, its
  detail names the direct dependencies that bring it in. Maven, Go and npm packages with a version
  get a package URL.
- **A KICS result is a finding** at its file and line, under KICS's query id, the rule Draugr's own
  [KICS](../../internal/scanners/kics.md) reports it under.
- **Rated by Checkmarx's severity:** `CRITICAL`, `HIGH`, `MEDIUM` and `LOW` as their bands, and
  `INFO` as low. No severity ranks high, and the finding says so: `not scored yet` on a dependency,
  `not rated, so ranked high` on code.
- **A result triaged Not Exploitable or Ignored in Checkmarx One is one the tool suppressed**: set
  aside with the state and its comment as the reason, or counted with `suppressions: count`.
  Proposed Not Exploitable awaits review, and counts.
- **The file's container image and supply-chain results are not read**, since they describe no file
  in the repository.
- **Only `commit` binds the file**, since it names no commit. It is the commit the scan read, which
  for a scan exported later with `--scan-id` may not be the pipeline's current commit.
- **A file is refused** when it does not list as many results as its `totalCount`, when a severity is not
  one of Checkmarx's, or when a result names no query, file, package or manifest, and an import into
  any control but `sast`, `sca` and `iac` is refused. Each error says which.
- **The import takes no `severity` mapping**: the file states its own rating.

## Import Mend

Mend's code scan writes SARIF, which imports as any other SARIF file does. Its dependency scan,
`mend dep`, writes no SARIF, so import its JSON into `sca`:

```bash
mend dep --format json --export-results reports/mend.json
```

```yaml
imports:
  - control: sca
    file: reports/mend.json
    format: mend-json
    commit: ${{ GITHUB_SHA }}
```

- **Each vulnerability of a library is a finding** at the version installed, in the manifest Mend
  names. Its rule is its CVE, so KEV and EPSS reach it, else Mend's own id, such as `WS-2022-0468`.
  A library the tree lists more than once still gives one finding per vulnerability. A transitive
  library's detail names the direct dependency that brings it in.
- **The package and version come from the library's file name**, `jackson-databind-2.9.5.jar`. A name
  with no hyphen before a digit, such as `foo.jar`, is the package whole, with no version, and the
  detail says so.
- **A Maven package is named `group:artifact` and gets a package URL** when Mend's fixes for the
  library agree on one group, as Trivy names a package in a `pom.xml`. Otherwise it keeps the artifact
  name, with no package URL.
- **The fixed version is read from Mend's fix** where it names this package, as `2.9.8` or
  `com.fasterxml.jackson.core:jackson-databind:2.9.10.8`. Only versions above the installed one count,
  and several are joined with commas, as Trivy's are.
- **Mend's whole fix stays in the detail** when it also names another package, names no version above
  the installed one, or is written in any other form.
- **Rated by Mend's severity:** `CRITICAL`, `HIGH`, `MEDIUM` and `LOW` as their bands.
- **Only `commit` binds the file**, since it names no commit.
- **A file is refused** when it is not a list of libraries, when a library has no `name` or
  `dependencyFile`, when a vulnerability has no `name`, or when a severity is not one of Mend's, and an
  import into any control but `sca` is refused. Each error says which.
- **The import takes no `severity` mapping and no `suppressions`**: the file states its own rating
  and records no suppression.

## Import Prisma Cloud

Import the JSON Prisma Cloud's `twistcli images scan` writes into `images`. The
`PaloAltoNetworks/prisma-cloud-scan` Action's SARIF names each package only in text, so import the
JSON rather than that. `twistcli` does not pull the image, so pull or build it first:

```bash
twistcli images scan --address "$PRISMA_CONSOLE" --user "$PRISMA_ACCESS_KEY" \
  --password "$PRISMA_SECRET_KEY" --output-file reports/twistcli.json ghcr.io/acme/web:1.0
```

```yaml
imports:
  - control: images
    file: reports/twistcli.json
    format: twistcli-json
    commit: ${{ GITHUB_SHA }}
```

- **Each vulnerability of a package is a finding** at the version installed, in the image. Its rule is
  its CVE, so KEV and EPSS reach it, and its location is the image's name, or its ID where the file
  names none.
- **An operating-system package** is one `twistcli` writes as `glibc (used in libc6, libc-bin)`, or
  lists with the type `os`. It is named by its source package, `glibc`, in the distribution's
  ecosystem, with the image's operating system, and the binary packages are in the detail.
- **Any other package** keeps the name `twistcli` gives it, with no ecosystem, and its path in the
  image is in the detail.
- **The fixed version is read from the status**, `fixed in` and one or more versions. Where the
  package's ecosystem is known, only versions above the installed one count; otherwise every version
  counts. Several are joined with commas, as Trivy's are. `open` is no fix.
- **The whole status stays in the detail** when it is written in any other form or names no version
  above the installed one.
- **Rated by the CVSS score, else `twistcli`'s severity.** A score less severe than the severity is
  not used, so the finding keeps the severity. `critical`, `high`, `medium` and `low` are their bands,
  and `important` and `moderate`, a distribution's words, are high and medium.
- **Compliance results are not read.** They describe how the image is built, such as a missing
  `HEALTHCHECK`, not a flaw in a package.
- **Only `commit` binds the file**, since it names no commit.
- **An import into any control but `images` is refused.**
- **The import takes no `severity` mapping and no `suppressions`**: the file states its own rating
  and records no suppression.

## Import Aqua

Import the JSON Aqua's `scannercli scan` writes into `images`. The image is scanned from a
registry Aqua's console has an integration for, and `--registry` is that integration's name:

```bash
scannercli scan --host "$AQUA_CONSOLE" --user "$AQUA_USER" --password "$AQUA_PASSWORD" \
  --registry "$AQUA_REGISTRY" --jsonfile reports/aqua.json acme/web:1.0
```

```yaml
imports:
  - control: images
    file: reports/aqua.json
    format: aqua-json
    commit: ${{ GITHUB_SHA }}
```

- **Each vulnerability of a package is a finding** at the version installed, in the image. Its rule is
  its CVE, so KEV and EPSS reach it, else Aqua's id for it, such as a Debian `DSA`. Its location is
  the file's `image`, else the reference it was pulled by, else its digest. A package listed twice
  with the same vulnerability at the same path is one finding, rated by the more severe copy.
- **An operating-system package** is one whose format is `apk`, `deb` or `rpm`. It is in the
  distribution's ecosystem and carries the image's operating system. A binary package built from a
  differently named source package names the source in the detail.
- **Any other package** is in the ecosystem its format names where Draugr knows it, such as `npm`, and
  in none otherwise. Aqua names a Java package by its path in the image, and a library it finds by
  path alone has only that path, which becomes its name. Where Aqua found it is in the detail.
- **The fixed version is read from `fix_version`**: one version, or several joined by commas. Where
  the package's ecosystem is known, only versions above the installed one count; otherwise every
  version counts.
- **The whole fix stays in the detail** when Aqua writes the vendor's words after the versions or in
  place of them, or names no version above the installed one.
- **Rated by the more severe of Aqua's CVSS score and its severity.** `critical`, `high`, `medium`
  and `low` are their bands, and `negligible`, which Aqua gives where a distribution calls a flaw
  unimportant, is low. So Aqua's `critical` at a score of 3.7 stays critical, and its `negligible`
  at a score of 10 is critical.
- **Sensitive data, malware and image assurance results are not read.**
- **Only `commit` binds the file**, since it names no commit.
- **An import into any control but `images` is refused.**
- **The import takes no `severity` mapping and no `suppressions`**: the file states its own rating
  and records no suppression.

## Import Semgrep

Semgrep's SARIF names a Supply Chain finding's package and CVE only in its message. Its JSON keeps
both, with the code results beside them, so import it once into each of `sast` and `sca`. For code
results alone, Semgrep's SARIF imports as any other SARIF file; the JSON also rates them from the
rule's impact and likelihood, as [`semgrep`](../../internal/scanners/semgrep.md) does.

```bash
semgrep ci --json-output=reports/semgrep.json
```

```yaml
imports:
  - control: sast
    file: reports/semgrep.json
    format: semgrep-json
    commit: ${{ GITHUB_SHA }}
  - control: sca
    file: reports/semgrep.json
    format: semgrep-json
    commit: ${{ GITHUB_SHA }}
```

`semgrep scan --config <rules> --json-output=<file>` writes the same format, for a scan with rules
of your own.

- **Each code result is a finding in `sast`** at its file and line, under its rule's id, with the
  CWE the rule's metadata names. It is rated from the rule's impact and likelihood, as Draugr's own
  Semgrep run rates it, else by the rule's severity: `CRITICAL` critical, `ERROR` and `HIGH` high,
  `WARNING` and `MEDIUM` medium, `LOW` and `INFO` low.
- **In `sast`, the tool is named as Semgrep's SARIF names it**, `Semgrep OSS`, or `Semgrep PRO` for a
  scan with the Pro engine, so a code finding Draugr's own Semgrep run also reports is counted once.
- **Each Supply Chain result is a finding in `sca`**: an advisory in a dependency at the version
  installed, in the lockfile that lists it. Its rule is its CVE, so KEV and EPSS reach it, else its
  GHSA id, else Semgrep's rule id. An npm, PyPI, RubyGems, Go, Cargo, Maven, Composer, NuGet, Pub or
  Hex package carries its package URL.
- **The fixed version is read from the rule's `sca-fix-versions`**, the versions it names for this
  package. Where the ecosystem's versions can be ordered, only those above the installed one count.
  A fix for an older release line is not counted: where Semgrep names no version above the installed
  one, the detail lists what it names.
- **Rated by the advisory's `sca-severity`**: `CRITICAL`, `HIGH`, `MODERATE` or `MEDIUM` as medium,
  and `LOW`,
  else by the rule's severity.
- **A rule that looks for the vulnerable code** reports a result at each place it finds it. Those
  results are one finding, whose detail names each place, or says Semgrep found no use. The rating
  stays the advisory's either way.
- **Semgrep Secrets results are not read**, in either control.
- **A file a rule timed out on is listed under `unread-files`** in `sast`, as for Draugr's own run,
  and so is a file Semgrep skipped for its size where it ran with `--verbose`.
- **What a `nosemgrep` comment suppressed is not in the file**, unless Semgrep ran with
  `--disable-nosem`, and nor is a finding triaged as
  ignored in Semgrep AppSec Platform, so Draugr never sees or counts either. To keep such a decision
  in the report, with its reason, set the finding aside in the descriptor's `config.exclude`.
- **Only `commit` binds the file**, since it names no commit.
- **An import into any control but `sast` or `sca` is refused.**
- **The import takes no `severity` mapping and no `suppressions`**: it is rated as described above,
  and the file records no suppression.

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

## Import SonarQube

SonarQube writes no report file: its findings stay on the server. Draugr reads a project's security
issues from SonarQube's Web API, as it reads GitHub's alerts. Name the project by its key:

```yaml
components:
  - name: api
    repositories:
      - url: https://github.com/acme/api
    imports:
      - control: sast
        source: sonarqube
        project: acme_api
```

Then scan with a token that can browse the project in `SONAR_TOKEN`, and, for SonarQube Server, its
address in `SONAR_HOST_URL`, the two variables SonarSource's own scanners read. Where
`SONAR_HOST_URL` is unset, Draugr reads SonarQube Cloud. A token in another variable is named with
`tokenEnv` and listed in `$DRAUGR_TOKEN_ENVS`, as for GitHub's alerts.

What to expect:

- **Only security issues are read**: each at its file and line, under its rule, rated by its
  security impact, with the rule's CWEs on SonarQube Cloud. Code smells and bugs are not read, nor
  are security hotspots, which SonarQube now raises as security issues.
- **An issue a person accepted or marked as a false positive is set aside**, with the latest comment
  on it as the reason. `suppressions: count` counts it instead.
- **The commit is the one SonarQube's latest analysis read.** Run the scan after the analysis of the
  same commit, or the import is listed under **Caveats** as `unbound-imports`.
- **SonarQube's refusals stop the run**: a token it refuses, a project it does not know, a project
  with no analysis yet, or more than the 10,000 issues its search returns. None reads as a project
  with no findings.
- **SonarSource's terms govern the token's use.** Its
  [Acceptable Use Policy](https://www.sonarsource.com/legal/aup/) applies to SonarQube Cloud and
  Server; Community Build is outside it. [License & terms](../../internal/scanners/sarif-import.md#license--terms)
  quotes the clauses that bear on reading results into another tool.

[SonarQube's security issues](../../internal/scanners/sarif-import.md#sonarqubes-security-issues)
has how each issue is read and every error.

## See also

- [Import each tool's file](importing-each-tool.md): the export command, the control and the quirks
  for CodeQL, Snyk, Checkmarx One, Fortify, Semgrep, Checkov, KICS, gosec and others.
- [`components[].imports`](../reference/saga-schema.md#componentsimports) in the Saga reference.
- The [`sarif-import` scanner](../../internal/scanners/sarif-import.md): how severities are read,
  every field under **Measured against**, and the errors a file can produce.
- [The verdict and the gate](../concepts/verdict-and-gating.md), for caveats and
  `failOnCaveats`.

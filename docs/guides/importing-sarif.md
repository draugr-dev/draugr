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

The steps below use Bandit, which writes no commit into its SARIF, so they include binding the file
to the commit it scanned. Another tool's file follows the same steps, with the limits
[Before you import](../../internal/scanners/sarif-import.md#before-you-import) lists. The ones a
first import meets:

- **A finding the control's own scanner also reports is counted once.** Semgrep's file imported
  into `sast` beside Draugr's Semgrep run, or Trivy's into `sca` beside `trivy-fs`, lists each
  finding once and names both scanners. A dependency finding merges on its advisory and package, a
  code finding on its rule, file and line. In a component with several repositories, a file merges
  only where its `versionControlProvenance` names the repository it scanned.
  [Merging with the control's scanners](../../internal/scanners/sarif-import.md#merging-with-the-controls-scanners)
  lists what stays apart, such as Bandit's rule beside Semgrep's on the same line.
- **Severity comes from `security-severity`, written as a string or a number, or from the level.**
  A file that states only levels never yields critical, and one that writes only `warning` ranks P2 at most,
  below the default gate, unless KEV or EPSS raises a finding whose rule id is a CVE.
- **A dependency finding's package and fix are read where the tool states them**, for Trivy's,
  Grype's and OSV-Scanner's files, so their findings in one package become one upgrade to the
  release that clears them. [Dependency findings](../../internal/scanners/sarif-import.md#dependency-findings)
  lists where each tool puts them. A file that names no package, as most code scanners' do, gets a
  "Fix <rule>" action per rule.
- **KEV and EPSS need a CVE**, in the rule id or listed by the file beside it, as OSV-Scanner lists
  an advisory's other identifiers. Grype names its findings by GitHub and Go advisory and lists no
  CVE, so neither reaches them, and **Signals** counts the imported findings that name no CVE.
- **Paths are read relative to the repository's root.** An absolute path or `file://` URI inside the
  component's repository, when its `url` is a local path, is made relative to it. Any other absolute
  path is kept as written: its finding still counts, the scan lists the path under `unread-files`,
  and [`config.exclude`](../reference/saga-schema.md#configexclude) paths and links to the line do
  not match it. A component whose `url` is a remote address has no local directory to compare
  against, so write the file's paths relative to the repository root.
- **The file's own suppressions hold.** A result it suppresses stays in the report, suppressed.

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

A SARIF file left from an earlier run reads exactly like a current one. When a file names the
commit it scanned, in `runs[].versionControlProvenance`, Draugr holds it to the commit this run
reads:

- **The same commit:** the file is read, and the report names the commit.
- **A different commit:** the run stops with an error naming both.
- **No commit:** the file is read, and the report lists it under **Caveats** as `unbound-imports`.

To see whether a tool already writes the field:

```bash
jq '.runs[].versionControlProvenance' bandit.sarif
```

Bandit's prints `null`. Add the field from the checkout the tool ran in:

```bash
mkdir -p reports
jq --arg uri "$(git remote get-url origin)" --arg rev "$(git rev-parse HEAD)" \
  '.runs[].versionControlProvenance = [{repositoryUri: $uri, revisionId: $rev}]' \
  bandit.sarif > reports/bandit.sarif
```

`git remote get-url origin` prints the address as the remote holds it. Where that address carries a
credential, as `https://user:token@host/…` does, pass the address without it, since the SARIF file is
often kept as a pipeline artifact. A checkout with no remote has no address to print; pass the
repository's address as Draugr's descriptor names it.

A component with one repository is held to it whatever address the file gives. With several, the
address has to name one of them.

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

`control` names the control that reports the findings, such as `sast` or `sca`. Every finding in the file
belongs to the component that imports it. A component can import several files, one entry each.

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
      reason: <why it does not apply>
  draugr explain <rule>                    what a rule means and how to fix it, from .draugr/out
```

This run is [`draugr-demo`](https://github.com/draugr-dev/draugr-demo), whose `api` component
declares the step 3 import and is `exposure: public` and `criticality: important`, so Bandit's
high-severity findings rank P1. Draugr did not run Bandit, so **Measured against** states what the
file says about itself: the tool and version, when it was written, where severities came from, the
commit it was checked against, and its SHA-256. This file names no commit, so the run reads
`commit: not stated` and lists the file under **Caveats** as `unbound-imports`, which does not fail
the run. Step 5 makes it fail; the GitHub Actions example below shows how to write the commit into
the file.

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
      bandit -r app -f sarif -o bandit.sarif --exit-zero
      mkdir -p reports
      jq --arg uri "$(git remote get-url origin)" --arg rev "$(git rev-parse HEAD)" \
        '.runs[].versionControlProvenance = [{repositoryUri: $uri, revisionId: $rev}]' \
        bandit.sarif > reports/bandit.sarif
  - uses: draugr-dev/draugr@v0
    with:
      saga: draugr.saga.yaml
      tools: true
```

The commit comes from the checkout, so on a pull request it is the merge commit the workflow checked
out, which is also the commit Draugr reads.

## See also

- [`components[].imports`](../reference/saga-schema.md#componentsimports) in the Saga reference.
- The [`sarif-import` scanner](../../internal/scanners/sarif-import.md): how severities are read,
  every field under **Measured against**, and the errors a file can produce.
- [The verdict and the gate](../concepts/verdict-and-gating.md), for caveats and
  `failOnCaveats`.

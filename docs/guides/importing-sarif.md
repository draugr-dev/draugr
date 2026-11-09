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
to the commit it scanned. The same steps fit any tool that writes SARIF 2.1.0.

## 1. Write the SARIF file

Run the tool in a step before the scan. Bandit writes SARIF only with its `sarif` extra installed,
and `--exit-zero` leaves the verdict to Draugr's gate, since Bandit otherwise exits non-zero when it
finds something:

```bash
pipx install 'bandit[sarif]'
bandit -r app -f sarif -o bandit.sarif --exit-zero
```

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
DRAUGR  FAIL  draugr-demo 1.0  (scope: 1 of 3 components; sast)  9.19s

 9 P1 6 P2 6 P3 0 P4

CONTROLS
  sast  FAIL   9 P1 6 P2 6 P3

MEASURED AGAINST
  sast  sarif-import · tool: Bandit 1.9.4 · file: reports/bandit.sarif · written: 2026-10-11
        04:57 UTC · severity: issue_severity and issue_confidence · commit: not stated ·
        component: api · sha256: 989dfee1ddac26aab9d76c86197c84eb29af9d5a375cd4fa923873fcf61bc…

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

FIX FIRST  top 3 of 21, by priority
  P1  critical  …dangerous-system-call · Found user-controlled data used in a system call.…
      Run the command as an argument list, without a shell
      scanner semgrep oss · fix change the code
      app/app.py:16 · impact high · likelihood high

  P1  high      B605 · Starting a process with a shell, possible injection detected, security…
      Run the command as an argument list, without a shell
      scanner bandit · fix change the code
      app/app.py:16 · issue_severity high

  P1  high      B602 · subprocess call with shell=True identified, security issue.
      Run the command as an argument list, without a shell
      scanner bandit · fix change the code
      app/app.py:23 · issue_severity high

… and 18 findings not listed.

TRY
  --top 0                 every one of them, not the first three
  --report html -o <dir>  every row the console cut, in one searchable page
  --view compact          one line each, to see how much there is
  --view actions          the same findings as a list of things to do
  draugr explain <rule>   what a rule means and how to fix it
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

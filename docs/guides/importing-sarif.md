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

Run the tool in a step before the scan. Bandit exits non-zero when it finds something, and
`--exit-zero` leaves the verdict to Draugr's gate:

```bash
bandit -r app -f sarif -o bandit.sarif --exit-zero
```

Bandit's SARIF output needs its `sarif` extra: `pipx install 'bandit[sarif]'`.

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

A component with one repository is held to it whatever address the file gives. With several, the
address has to name one of them.

## 3. Declare the import

```yaml
components:
  - name: api
    exposure: public
    criticality: critical
    imports:
      - control: sast
        file: reports/bandit.sarif   # relative to where Draugr runs
```

`control` is the control the findings join, such as `sast` or `sca`. Every finding in the file
belongs to the component that imports it. A component can import several files, one entry each.

## 4. Scan

```console
$ draugr scan --controls sast --components api --top 3
DRAUGR  FAIL  draugr-demo 1.0  (scope: 1 of 3 components; sast)  9.871s

 10 P1 10 P2 1 P3 0 P4

CONTROLS
  sast  FAIL   10 P1 10 P2 1 P3

MEASURED AGAINST
  sast  sarif-import · tool: Bandit 1.9.4 · file: reports/bandit.sarif · written: 2026-10-11
        04:51 UTC · severity: SARIF level · commit: 123509aace3d · component: api · sha256:
        e97d84c8ab67b3c15a6297bd2210fa205a7a60b2c685ea4392d5404a74307ea3

COMPONENTS
  api         FAIL   10 P1 10 P2 1 P3
  storefront  not scanned
  platform    not scanned

SIGNALS
  KEV   nothing raised
  EPSS  nothing raised

FIX FIRST  top 3 of 21, by priority
  P1  high      B605 · Starting a process with a shell, possible injection detected, security…
      scanner bandit · fix change the code
      app/app.py:16

  P1  high      B602 · subprocess call with shell=True identified, security issue.
      scanner bandit · fix change the code
      app/app.py:23

  P1  high      B201 · A Flask app appears to be run with debug=True, which exposes the…
      scanner bandit · fix change the code
      app/app.py:35

… and 18 findings not listed.
```

Run in a copy of [`draugr-demo`](https://github.com/draugr-dev/draugr-demo) with the import above
added to its `api` component, which is public and important, so Bandit's high-severity findings rank
P1. **Measured against** records what Draugr knows
about the file: the tool and version it states, when it was written, where severities came from,
the commit it was checked against, and its SHA-256.

## 5. Require the commit

To make a file that names no commit fail the run, list the caveat kind in the gate:

```yaml
config:
  gate:
    failOnCaveats: [unbound-imports]
```

The caveat is then marked `✗`, its component reads `ERROR`, and the scan exits non-zero as an
incomplete one does. `--fail-on-caveats unbound-imports` sets the same for one run.

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

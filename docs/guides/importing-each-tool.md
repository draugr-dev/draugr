---
title: Import each tool's file
description: The export command, the control and the quirks for each tool whose results Draugr can import, from CodeQL, Snyk, Checkmarx One and Fortify to Semgrep, Trivy, Checkov, KICS and gosec.
section: Guides
order: 28
---

# Import each tool's file

[Import another scanner's SARIF](importing-sarif.md) walks through one import, from the file to the
scan. This page gives what differs from tool to tool: the command that writes the file, the control
its findings go in, what Draugr reads from it, and what to watch for. Each section names the version
its command was checked on, from the tool's `--help`, its documentation or its source at that
release.

| Tool | Control | Import |
|---|---|---|
| [CodeQL](#codeql) | `sast` | SARIF |
| [Snyk](#snyk) | `sast`, `sca` | SARIF |
| [Checkmarx One](#checkmarx-one) | `sast`, `sca`, `iac` | `checkmarx-one-json` |
| [Fortify](#fortify) | `sast` | SARIF |
| [Veracode Pipeline Scan](importing-sarif.md#import-veracode-pipeline-scan) | `sast` | `veracode-pipeline-json` |
| [Semgrep](#semgrep) | `sast` | SARIF |
| [gosec](#gosec) | `sast` | SARIF |
| [Trivy](#trivy) | `sca` | `trivy-json` |
| [Grype](#grype) | `sca` | `grype-json` |
| [OSV-Scanner](#osv-scanner) | `sca` | `osv-scanner-json` |
| [JFrog Xray](importing-sarif.md#import-jfrog-xray) | `sca` | `jfrog-simple-json` |
| [Checkov](#checkov) | `iac` | SARIF |
| [KICS](#kics) | `iac` | SARIF |
| Black Duck, Coverity, SonarQube, Wiz, Prisma Cloud | | [No file to import yet](#no-file-to-import-yet) |

For every tool:

- **Name the commit.** No tool here writes the commit it scanned into its file, so each import names
  its `commit` ([step 2](importing-sarif.md#2-name-the-commit-the-file-describes)).
- **Keep the tool's exit code from failing the step**, or the pipeline stops before Draugr reads the
  file. Each section names the option that keeps it at 0, or, where a tool has none, the exit code
  that means it found something, to allow on its own:

  ```bash
  osv-scanner scan source --format json --output-file reports/osv-scanner.json . || [ $? -eq 1 ]
  ```

  `|| true` allows every exit code, so a run that failed and wrote nothing passes too.
- **Keep the control's own scanner on.** A finding both report is counted once
  ([Merging with the control's scanners](../../internal/scanners/sarif-import.md#merging-with-the-controls-scanners)).

## CodeQL

Checked on CodeQL CLI 2.27.6. Findings go in `sast`.

```bash
codeql database analyze <database> <query suite> --format=sarifv2.1.0 --output=reports/codeql.sarif
```

- **Rating:** [CodeQL](../../internal/scanners/sarif-import.md#codeql).
- **Name `sarifv2.1.0`.** CodeQL's documentation calls `sarif-latest` unsuitable for automation.
- **Create the database from the repository's root**, so the file's paths are relative to it.

## Snyk

Checked on Snyk CLI 1.1309.0. Snyk Code findings go in `sast`, Snyk Open Source findings in `sca`.

```bash
snyk code test --sarif-file-output=reports/snyk-code.sarif || [ $? -eq 1 ]
snyk test --sarif-file-output=reports/snyk.sarif || [ $? -eq 1 ]
```

- **Exit code:** 1 when Snyk finds something. Snyk documents no option that keeps it at 0.
- **Rating:** [Snyk](../../internal/scanners/sarif-import.md#snyk).
- **Snyk Open Source names the package as `name@version` in `logicalLocations`**, which Draugr
  reads ([Dependency findings](../../internal/scanners/sarif-import.md#dependency-findings)). Its
  CVE is only in the rule's description text, so KEV and EPSS do not reach its findings. Reading a
  real Snyk Open Source file end to end is tracked in
  https://github.com/draugr-dev/draugr/issues/2177.

## Checkmarx One

Checked on `cx` 2.3.72. Findings go in `sast`, `sca` and `iac`, from one file:

```bash
cx results show --scan-id <id> --report-format json --output-path reports    # writes reports/cx_result.json
```

`cx scan create <options> --report-format json --output-path reports` writes the same file when the
scan ends. `cx results show` exports a scan that already ran, so its import names the commit that
scan read. Import the file once into each control, as
[Import Checkmarx One](importing-sarif.md#import-checkmarx-one) shows.

- **Exit code:** 0 when `cx` finds something, unless `--threshold` is set.
- **Rating:** Checkmarx's severity on each result.

## Fortify

Checked on fcli 3.30.1. Findings go in `sast`. fcli exports an analysis Fortify has already run, from
Software Security Center or Fortify on Demand:

```bash
fcli ssc action run sarif-sast-report --av <application>:<version> -f reports/fortify.sarif
fcli fod action run sarif-sast-report --rel <application>:<release> -f reports/fortify.sarif
```

- **Rating:** the `security-severity` fcli writes on each result
  ([Fortify](../../internal/scanners/sarif-import.md#fortify)). The file names no CWE.
- **Name the commit the analysis read**, which may be older than the one the pipeline checked out.

## Semgrep

Checked on Semgrep 1.182.1. Findings go in `sast`, where Draugr runs Semgrep by default.

```bash
semgrep scan --config <rules> --sarif-output=reports/semgrep.sarif
```

- **Exit code:** 0 when Semgrep finds something, unless `--error` is set.
- **Rating:** the result's `level`.
- **`--sarif-output` writes a copy of the results**, beside what Semgrep prints.
- **Run it from the repository's root**, since its paths are relative to where it runs.

## gosec

Checked on gosec 2.30.0. Findings go in `sast`, where Draugr's own `gosec` scanner can run gosec too.

```bash
gosec -fmt=sarif -out=reports/gosec.sarif -no-fail ./...
```

- **Exit code:** 0 with `-no-fail`.
- **Rating:** [gosec](../../internal/scanners/sarif-import.md#gosec), as Draugr's `gosec` scanner
  rates it.
- **gosec writes paths relative to the Go module**, not the repository. For a module below the
  repository's root, such as `checkout/`, `main.go` names no file in the checkout: its finding still
  counts, and the scan lists it under `unread-files`. Add the module's directory to every path before
  importing:

  ```bash
  jq '.runs[].results[].locations[].physicalLocation.artifactLocation.uri |= "checkout/" + .' \
    reports/gosec.sarif > reports/gosec-checkout.sarif
  ```

## Trivy

Checked on Trivy 0.76.1. Findings go in `sca`, imported as `format: trivy-json`.

```bash
trivy fs --format json -o reports/trivy.json .
```

- **Exit code:** 0 when Trivy finds something, unless `--exit-code` is set.
- **Rating:** the CVSS score, else Trivy's severity.
- **Import the JSON, not the SARIF.** The JSON keeps the package, the fixed version and the CVSS score
  ([Import a tool's own JSON](importing-sarif.md#import-a-tools-own-json)).

## Grype

Checked on Grype 0.121.0. Findings go in `sca`, imported as `format: grype-json`.

```bash
grype dir:. -o json --file reports/grype.json
```

- **Exit code:** 0 when Grype finds something, unless `--fail-on` is set.
- **Rating:** the CVSS score, else Grype's severity.
- **Import the JSON, not the SARIF.** The JSON lists the CVE, which KEV and EPSS need.
- **Scan a directory.** An image scan's file is refused.

## OSV-Scanner

Checked on OSV-Scanner 2.7.1. Findings go in `sca`, imported as `format: osv-scanner-json`.

```bash
osv-scanner scan source --format json --output-file reports/osv-scanner.json . || [ $? -eq 1 ]
```

- **Exit code:** 1 when OSV-Scanner finds a vulnerability, and 128 when it finds no packages.
- **Rating:** the CVSS score, else the advisory's severity, else medium.
- **Import the JSON, not the SARIF.** The SARIF carries no score.
- **Write the file with `--output-file`.** `--output` is deprecated.

## Checkov

Checked on Checkov 3.4.10. Findings go in `iac`.

```bash
checkov -d . -o sarif --output-file-path reports --soft-fail    # writes reports/results_sarif.sarif
```

- **Exit code:** 0 with `--soft-fail`, and otherwise non-zero on a failed check.
- **Rating:** high for every failed check. Checkov writes a check's severity only where its platform
  supplies it, so an open-source run writes each failed check at level `error` with no
  `security-severity`.
- **A check skipped with a `checkov:skip` comment comes through as a suppression**, with the comment
  as its reason, so the finding is set aside on an **Accepted** row named for Checkov
  ([The tool's own suppressions](../../internal/scanners/sarif-import.md#the-tools-own-suppressions)).

## KICS

Checked on KICS 2.2.1. Findings go in `iac`, where Draugr's own `kics` scanner can run KICS too.

```bash
docker run --rm -v "$PWD":/src -w /src checkmarx/kics:v2.2.1 \
  scan -p . --report-formats sarif -o reports --output-name kics --ignore-on-exit results
```

- **Exit code:** 0 with `--ignore-on-exit results`, and otherwise non-zero on any result.
- **Rating:** the result's `level`, so a critical result reads as high. KICS writes `error` for both.
  Draugr's `kics` scanner reads KICS's JSON, which tells them apart.
- **Run the container from the mounted directory, with `-w /src -p .`.** Otherwise KICS can write
  each path as the container saw it, such as `../../src/deploy/pod.yaml`, which names no file in the
  checkout.
- **The rule id is the KICS query's id**, such as `dd29336b-fe57-445b-a26e-e6aa867ae609`, and that
  is what a `config.exclude` entry names.

## No file to import yet

- **Black Duck and Coverity.** Black Duck Detect and Coverity write no SARIF. Bridge CLI writes it
  for a Black Duck SCA scan (`blackducksca.reports.sarif.create=true`) and for a Polaris scan, which
  covers Coverity (`polaris.reports.sarif.create=true`), though not for a pull-request scan. What
  those files carry has not been checked against a real one. Reading Black Duck's and Coverity's own
  results is https://github.com/draugr-dev/draugr/issues/2317.
- **SonarQube.** Checked on SonarQube Server 2026.5, which reads SARIF and exports none. Reading its
  issues from its Web API is https://github.com/draugr-dev/draugr/issues/2319.
- **Wiz.** No command is given. Reading Wiz CLI results is
  https://github.com/draugr-dev/draugr/issues/2316.
- **Prisma Cloud.** `twistcli` writes JSON only. The `PaloAltoNetworks/prisma-cloud-scan` Action,
  checked on v1.9.0, converts its results to SARIF, but that file describes a container image rather
  than the repository and names each package only in text. Reading `twistcli`'s JSON is
  https://github.com/draugr-dev/draugr/issues/2312.

## See also

- [Import another scanner's SARIF](importing-sarif.md), the whole flow for one tool.
- [Write a converter](writing-a-converter.md), for a tool that writes neither SARIF nor a JSON Draugr
  reads.
- The [`sarif-import` scanner](../../internal/scanners/sarif-import.md), for how each part of a file
  is read.

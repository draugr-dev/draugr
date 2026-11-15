---
title: "sarif-import"
description: "Reads a SARIF file another tool wrote into one of Draugr's controls, so its findings are ranked and gated with the rest."
section: Scanners
order: 90
---

# Scanner: `sarif-import` (reads a SARIF file another tool wrote)

- **Control:** the control each import names in [`components[].imports`](../../docs/reference/saga-schema.md#componentsimports)
- **Tool:** none. Draugr reads a file; the tool that wrote it ran somewhere else.
- **Target:** file (a SARIF 2.1.0 log)
- **Effects:** none
- **Status:** ✅ implemented

[Import another scanner's SARIF](../../docs/guides/importing-sarif.md) walks through a pipeline that
writes the file, binds it to its commit, and scans.

## What it does

Reads a SARIF file a component imports and adds its findings to the control the descriptor names.
Each finding then takes the component's exposure and criticality into its priority, counts toward
the gate, and appears in the fix list and every report. [Before you import](#before-you-import) lists
what to set up first.

The file is read as SARIF 2.1.0:

- **Severity** comes from each result's `security-severity` property, a CVSS-style score written as
  a string such as `"7.5"`, the convention GitHub code scanning reads, inherited from its rule where
  the result has none. A result without one, in a file Bandit wrote, is rated from its
  `issue_severity` and `issue_confidence` (see [Bandit](#bandit)). Any other result falls back to
  its `level`, mapped as every other SARIF level is: `error` to high, `warning` to medium, `note`
  to low.
  - A file that states only levels never yields a critical finding.
  - A tool that writes only `warning` produces medium findings. A medium finding ranks P2 at most,
    so with the default gate, which fails on P1, such a file cannot fail the run unless KEV or EPSS
    raises a finding whose rule id holds a CVE.
- **Package and fix** come through only where the file carries Draugr's own `package` property. A
  dependency finding from another tool's file names no package, its fix reads `no package
  reported`, and it becomes a "Fix <rule>" action rather than an upgrade.
- **The tool** is the file's own `tool.driver`, so a finding says which product found it.

## Before you import

- **Switch off the control's own scanner when you import its tool's file.** An imported finding is
  not merged with the same finding from that scanner, so a tool Draugr also runs lists each finding
  twice, ranked twice.

  | Imported tool | Control | Switch off |
  |---|---|---|
  | Semgrep | `sast` | `config.controls.sast.semgrep.enabled: false` |
  | Trivy, vulnerabilities | `sca` | `config.controls.sca.trivyFs.enabled: false` |
  | Trivy, misconfigurations | `iac` | `config.controls.iac.trivyConfig.enabled: false` |

  The same block under `components[].controls` switches it off for one component.
- **Write paths relative to the repository's root.** Each location is kept as the file writes it.
  An absolute path or a `file://` URI is reported as written, and
  [`config.exclude`](../../docs/reference/saga-schema.md#configexclude) `paths` match it only as
  written.
- **Set aside an imported finding with `config.exclude`.** A repository's `paths:` and `ignore:`
  narrow the scanners Draugr runs, not an imported file: every finding in it belongs to the
  component.
- **Expect the file's own suppressions to hold.** A result with an entry in `suppressions` stays in
  the report, suppressed, whatever the entry's `status`.
- **Expect KEV and EPSS only on a CVE.** They read a CVE id in the rule id, so a finding whose rule
  id is a GHSA id or a tool's own code, such as `B602`, gets neither.

## What the report says about the file

Draugr did not run the tool, so the report states what it knows about the file instead, under
**Measured against** and in `results.sarif`:

| Field | Value |
|---|---|
| `tool` | the tool's name and version, as the file states them |
| `file` | the path the descriptor gave |
| `written` | when the file says its run ended (`invocations[].endTimeUtc`), or else the file's modification time |
| `severity` | where severities came from: `security-severity`, `issue_severity and issue_confidence`, `SARIF level`, or a count of each |
| `commit` | the commit the file was checked against, or `not stated` |
| `component` | the component that imports it |
| `sha256` | the file's content, so a run can be checked against the file it read |

## Bandit

A result in a run whose `tool.driver.name` is `Bandit` is rated from the two result properties
Bandit writes, `issue_severity` and `issue_confidence`, each `LOW`, `MEDIUM` or `HIGH`, by the table
below.

| `issue_severity` | severity | with `issue_confidence` `LOW` |
|---|---|---|
| `HIGH` | high | medium |
| `MEDIUM` | medium | low |
| `LOW` | low | low |

Bandit already writes the level from `issue_severity`, so the rating differs from the level only for
a result Bandit rates `LOW` confidence, which is one level lower. Bandit has no rung above `HIGH`, so
nothing it reports is critical. A result with an `issue_severity` outside the three, such as
`UNDEFINED`, keeps its level, and a result carrying a `security-severity` keeps that.

The report prints the rating on the finding's evidence line in Bandit's own terms,
`issue_severity medium`, with `issue_confidence low` added where Bandit rated the confidence `LOW`.
`results.sarif` keeps Bandit's level and adds the result property `draugr/rating`, which holds the
severity, that line, and both properties with Bandit's value. A file another tool wrote is not rated this way, whatever its
properties are called.

## Commit

A file left from an old run reads exactly like a current scan. Where the file names the commit it
scanned, in `runs[].versionControlProvenance`, Draugr holds it to the commit this run reads:

- **The same commit:** the file is read, and `commit` names it.
- **A different commit:** the run stops with an error naming both. Run the tool again on this
  commit, or remove the import.
- **No commit named:** the file is read and listed under **Caveats** as `unbound-imports`, because nothing
  ties its findings to this code.
  [`config.gate.failOnCaveats: [unbound-imports]`](../../docs/reference/saga-schema.md#configgate)
  makes that fail the run.

A component with one repository is held to it whatever address the file gives, because a tool
records the remote it saw and the descriptor may name the same repository by a local path. Entries
that list one repository at one revision, a subtree each, count as one. With several distinct
repositories, the address has to name one of them.

## Errors

A file that is missing, unreadable, empty, not SARIF, a SARIF version other than 2.1.0, or a log
with no runs stops the run as a scanner that could not run does, and `--allow-scan-errors` accepts
it. A valid file with no results is a clean result.

A file is also unreadable where a result property Draugr reads by name has another shape:
`security-severity` written as a JSON number, or one of Draugr's own result properties (`priority`
as a number, `labels` as an array, `package` as a string). The error names the field, as in
`not a SARIF log: json: cannot unmarshal number into Go struct field …security-severity of type
string`. Write `security-severity` as a string, `"7.5"`. Draugr reads a result's rule from `ruleId`
and its path from `artifactLocation.uri`: a result that names its rule only by `ruleIndex` has no
rule id, and a location given only by `artifactLocation.index` has no path.

## License & terms

No third-party tool is executed or bundled, so the scanner carries only Draugr's own license. The
file is the reader's; its tool's terms governed whoever produced it, before Draugr read it.

## Data

Nothing. The scan reads the file the descriptor names, on the machine running Draugr, and resolves
the component's repository revision with `git`, locally for a path and with `git ls-remote` for a
remote.

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
  a string such as `"7.5"`, the convention GitHub code scanning reads, or as a number. A result with
  none inherits its rule's. A result without one, in a file Bandit wrote, is rated from its
  `issue_severity` and `issue_confidence` (see [Bandit](#bandit)). Any other result falls back to
  its `level`, mapped as every other SARIF level is: `error` to high, `warning` to medium, `note`
  to low.
  - A file that states only levels never yields a critical finding.
  - A tool that writes only `warning` produces medium findings. A medium finding ranks P2 at most,
    so with the default gate, which fails on P1, such a file cannot fail the run unless KEV or EPSS
    raises a finding whose rule id holds a CVE.
- **Package and fix** are read wherever the file states them, as
  [Dependency findings](#dependency-findings) lists. A dependency finding with a package and a fixed
  version becomes one upgrade per package, however many advisories it clears.
- **The rule** is the result's `ruleId`, its `rule.id`, or the rule its `ruleIndex` or `rule.index`
  points at in the run's `tool.driver.rules`.
- **Other result properties are ignored.** Draugr's own `priority`, `aside` and suppression origin
  have no effect in a file another tool wrote. The properties read are `security-severity`,
  `package` (an object), `purls`, `tags`, Bandit's `issue_severity` and `issue_confidence`, and a
  suppression's `kind` and `justification`, which make it the tool's own.
- **The tool** is the file's own `tool.driver`, so a finding says which product found it.

## Before you import

- **Keep the control's own scanner on.** A finding it also reports is counted once, naming both, as
  [Merging with the control's scanners](#merging-with-the-controls-scanners) describes.
- **Paths are read relative to the repository's root.** A location may be a URI, an index into the
  run's `artifacts`, or a URI relative to a base the run declares in `originalUriBaseIds`.
  - A relative path, or one relative to a base the run leaves undefined, such as `%SRCROOT%`, is
    read as relative to the repository's root.
  - A path relative to a base outside every local checkout, such as the directory a build machine
    scanned, is read as the part below that base.
  - An absolute path or `file://` URI inside a local checkout of the component, the repository's
    `url` when it is a path, is made relative to that checkout.
  - Any other absolute path is kept as written. Its finding still counts, the scan lists the path
    under `unread-files`, and
    [`config.exclude`](../../docs/reference/saga-schema.md#configexclude) `paths` and links to the
    line do not match it. A repository named by a remote address has no local directory, so write
    the file's paths relative to the repository root.
- **Set aside an imported finding with `config.exclude`.** A repository's `paths:` and `ignore:`
  narrow the scanners Draugr runs, not an imported file: every finding in it belongs to the
  component.
- **Expect the file's own suppressions to hold.** A result with an entry in `suppressions` stays in
  the report, suppressed, whatever the entry's `status`.
- **Expect KEV and EPSS only on a CVE.** They read a CVE in the rule id or among the identifiers the
  file lists for the finding (see [Dependency findings](#dependency-findings)). A finding named by a
  GHSA id or a tool's own code, such as `B602`, gets neither unless its file lists a CVE for it.

## Dependency findings

SARIF has no member for a package, so each tool states it somewhere of its own. Draugr reads these,
the first that names the finding's package winning:

| Where the file states it | Package and installed version | Fixed version | Tools that write it |
|---|---|---|---|
| Draugr's own `package` property, an object | `name`, `version` | `fixedVersion` | Draugr |
| The result's message, on `Package:` and `Installed Version:` lines | those lines | its `Fixed Version:` line | Trivy |
| The result's message, opening `Package 'name@version' is vulnerable to` | the quoted name and version | rows naming the package in a `Package Name` and `Fixed Version` table in the rule's `help` | OSV-Scanner |
| One `logicalLocations` entry written as `name@version` | the entry | a `fixes` replacement inserting the same package at another version | no tool checked |
| One package URL in the `purls` property of the result, its artifact, or its rule | the package URL | the `Fix Version:` line of the rule's `help` text, where its `Package:` line names the package | Grype, on the rule |

The tools are the versions checked against a file each wrote: Trivy 0.76.1, Grype 0.121.0 and
OSV-Scanner 2.7.1.

- **Nothing is worked out from a rule id.** A finding whose file states no package keeps none, its
  fix reads `no package reported`, and it becomes a "Fix <rule>" action.
- **A fixed version is read only for the finding's own package.** A fix that upgrades the package
  bringing the vulnerable one in says nothing about which version of the vulnerable one is fixed. A
  package with no fixed version stated becomes a "Replace or accept" action.
- **A package URL must parse**, as `pkg:type/namespace/name@version`. One that does not, or one
  naming another package or version than the message, is left off the finding.
- **The ecosystem** comes from the package URL, or else from the dependency file the result is
  located in, such as `go.mod` or `package-lock.json`. It orders the versions an upgrade chooses
  between, and without one an upgrade whose advisories name several fixed versions lists them instead
  of naming the release that clears them all.

**Other identifiers.** A finding named by a GitHub or Go advisory reaches KEV and EPSS through a CVE
the file lists for it in the result's or the rule's `tags`, where the whole tag is the identifier,
or in the rule's `deprecatedIds`, which OSV-Scanner fills with the advisory's other identifiers.
Nothing is looked up, so Grype's file, which names its findings by GHSA and Go ids and lists no
CVE, reaches neither. A note under the KEV row of **Signals** counts each imported finding that
names a package or an advisory and no CVE, as in
`not checked against KEV or EPSS: 9 imported findings name no CVE`.

## Merging with the control's scanners

An imported finding that the control's own scanner also reports is counted once. The copy with the
higher rating is counted, and its row names the other copy's scanner, an imported copy as `imported`
followed by the tool the file names: `also found by imported Trivy`, with that copy's rating beside
it where the two disagree. An import and a native run of one tool are two scanners, though Semgrep's
file and Draugr's Semgrep run both name their tool `Semgrep OSS`, because each is a run that found
the flaw.

- **A dependency finding** merges with a native one for the same advisory in the same package. The
  advisory is the rule id, or an identifier the file lists for it. The package is matched on its
  package URL, or where the file gives none, as Trivy's does, on its ecosystem, name and version.
  Trivy's file imported into `sca` merges this way with `trivy-fs`.
- **A code finding**, one about a line of code rather than a package, merges with a native one for
  the same tool's rule at the same file and line. Semgrep puts the directory of a local rules file
  on each rule's id, as `rules.no-os-popen`, and Draugr's Semgrep run leaves out the part that comes
  from the path it was configured with, reporting `no-os-popen`. An imported Semgrep id that ends in
  the native one after a dot is the same rule; the same id is preferred where both are on the line.

These stay counted apart:

- **Another tool's rule on the same line.** Bandit's `B605` and a Semgrep rule about the same call
  are two rules, each the tool's own.
- **The same rule on another line, or the same advisory in another package.**
- **A rule reported more than once on one line.** Two copies on one line, at two columns, cannot be
  paired copy to copy.
- **An imported finding in a component whose other findings name two repositories.** The file's
  paths do not say which repository they are in, so its findings stay counted apart rather than
  being merged into whichever repository came first. Where the component's findings name one
  repository, the imported findings are placed in it.

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

A file is also unreadable where:

- `ruleIndex` or `rule.index` is not an entry of `tool.driver.rules`;
- `artifactLocation.index` has no `uri` beside it and is not an entry of `artifacts`;
- a `uriBaseId` resolves through more than 8 entries of `originalUriBaseIds`, which two entries
  referring to each other always do.

The error names the run and the result, counted from 1, as in `run 1, result 3: ruleIndex 7 is not an
entry of tool.driver.rules, which has 4 rules (0 to 3)`.

`draugr doctor` reads the file with the same reader, so a file the scan would refuse fails doctor
with the same message, and a file that passes reports how many results it holds. Doctor does not
compare paths with the component's checkout; the scan lists a path it cannot place under
`unread-files`.

## License & terms

No third-party tool is executed or bundled, so the scanner carries only Draugr's own license. The
file is the reader's; its tool's terms governed whoever produced it, before Draugr read it.

## Data

Nothing. The scan reads the file the descriptor names, on the machine running Draugr, and resolves
the component's repository revision with `git`, locally for a path and with `git ls-remote` for a
remote.

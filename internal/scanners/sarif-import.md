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
  none inherits its rule's. A result without one is rated by its tool's own rating where Draugr has
  a table for the tool, or the import's [`severity`](#a-tool-draugr-has-no-table-for) mapping where
  the descriptor gives one (see [Each tool's own rating](#each-tools-own-rating)). Any other result
  falls back to its `level`, mapped as every other SARIF level is: `error` to high, `warning` to
  medium, `note` to low.
  - A file rated by level alone never yields a critical finding.
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
  `package` (an object), `purls`, `tags`, the rating properties each tool's table names and the
  one the import's mapping names, and a suppression's `kind` and `justification`, which make it the
  tool's own.
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
- **A repository's `paths:` and `ignore:` apply to the file's findings**, as they do to the tree
  the component's own scanners read. A finding outside the component's scope is left out of it, and
  the report counts it, as [Paths and ignore](#paths-and-ignore) describes. To set aside a finding
  inside the scope, use `config.exclude`, which keeps it in the report, suppressed.
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
  the native one after a dot is the same rule where the two findings' messages are also the same,
  since a registry rule and a local rule can share a name. The same id is preferred where both are
  on the line, and needs no matching message.

An imported finding is in the repository the import establishes for it: the component's repository
where it declares one, or where it declares several, the one the file's
`runs[].versionControlProvenance` names by `repositoryUri`, matched as for
[Commit](#commit). Nothing else places it.

These stay counted apart:

- **Another tool's rule on the same line.** Bandit's `B605` and a Semgrep rule about the same call
  are two rules, each the tool's own.
- **The same rule on another line, or the same advisory in another package.**
- **A rule reported more than once on one line.** Two copies on one line, at two columns, cannot be
  paired copy to copy.
- **An imported finding whose repository the import cannot establish.** In a component that
  declares several repositories, a file whose provenance names none of them, or more than one, could
  be about any of them, so its findings stay counted apart rather than merging with a copy in a
  repository they may not be about.

## Paths and ignore

An imported finding belongs to the component only where its file is inside the
[`paths:` and `ignore:`](../../docs/reference/saga-schema.md#scoping-a-repository) of the
repository it is placed in, by the rules a checkout follows: a file outside `paths:`, or one
`ignore:` matches, is left out of the component. A tool that scans a whole monorepo writes one file
for all of it, and each component importing that file keeps the findings in its own subtrees, as a
native scan of the repository would. A component that lists one repository several times, a subtree
each, keeps a finding inside any of them.

The repository is the one the import places the finding in, as
[Merging with the control's scanners](#merging-with-the-controls-scanners) describes. Where the scope
cannot be applied, the finding stays:

- **No repository established.** In a component with several repositories, a file whose
  `versionControlProvenance` names none of them, or more than one, could be about any of them, each
  scoped differently. Its findings stay and are counted as not scoped.
- **No location.** A finding that names no file is kept.
- **A path outside every checkout.** It is kept as written and listed under `unread-files`.

**Measured against** says what was left out, after `component`:

```text
component: web · left out: 2 findings outside paths, 1 matched by ignore
```

`report.json` lists the same counts under
[`scopedImports[]`](../../docs/reference/report-schema.md#telling-a-partial-run-from-a-clean-one).
A left-out finding is in no other count of the report, and `config.exclude` does not see it.

## What the report says about the file

Draugr did not run the tool, so the report states what it knows about the file instead, under
**Measured against** and in `results.sarif`:

| Field | Value |
|---|---|
| `tool` | the tool's name and version, as the file states them |
| `file` | the path the descriptor gave |
| `written` | when the file says its run ended (`invocations[].endTimeUtc`), or else the file's modification time |
| `severity` | where severities came from: `security-severity`, the tool's own rating as its table below names it, such as `gosec's severity tag`, the import's mapping, as `acme-severity, mapped by the descriptor`, `SARIF level`, or a count of each, as `security-severity for 2, problem.severity for 5` |
| `commit` | the commit the file was checked against, or `not stated` |
| `component` | the component that imports it |
| `left out` | how many findings the repository's `paths:` and `ignore:` left out of the component, as `3 findings outside paths, 1 matched by ignore`. Absent where none was left out |
| `not scoped` | how many findings were kept without applying `paths:` and `ignore:`, because the file establishes no one repository of the component's. Absent where none was, and where the component's repositories declare no scope |
| `sha256` | the file's content, so a run can be checked against the file it read |

## Each tool's own rating

Most tools state their own rating somewhere in the file besides the level. For the tools below,
Draugr reads it by a table taken from the tool's documentation or its source, named under each. A
table applies to a run whose `tool.driver.name` is the name shown, compared regardless of case, and
to no other run: another tool writing a property of the same name has not said it means the same
thing by it.

- **A numeric `security-severity` still decides first.** A table rates only a result without one.
- **A result the table has no row for keeps its level.**
- **A property is read from the result, and else from its rule**, the way `security-severity` is.
- **The finding records the row that applied.** The report prints the tool's words on the
  finding's evidence line, such as `severity tag medium`, and `results.sarif` keeps the tool's level
  and adds the result property `draugr/rating`, holding the severity, that line, and the properties
  read with the tool's values.

| Tool, as `tool.driver.name` | Rating read | Source |
|---|---|---|
| `Bandit` | `issue_severity`, `issue_confidence` | [Bandit](#bandit) |
| `gosec` | the rule's severity tag | [gosec](#gosec) |
| `CodeQL` | `problem.severity` | [CodeQL](#codeql) |
| `Micro Focus Fortify Static Code Analyzer` | `Impact`, `Accuracy`, `Probability`, `Confidence` | [Fortify](#fortify) |
| `dependency-check` | CVSS properties, `severity`, the rule's summary | [OWASP dependency-check](#owasp-dependency-check) |
| `Snyk Open Source` | the rule's summary | [Snyk](#snyk) |

A tool not listed is rated by its level, unless the import names a mapping
([A tool Draugr has no table for](#a-tool-draugr-has-no-table-for)).

### Bandit

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

The evidence line reads `issue_severity medium`, with `issue_confidence low` added where Bandit
rated the confidence `LOW`. The provenance's `severity` field reads `issue_severity and
issue_confidence`.

### gosec

gosec states its rating only as a tag on the rule, `"tags": ["security", "MEDIUM"]`, and writes the
level `error` for a `MEDIUM` rule as well as a `HIGH` one, and `warning` for a `LOW` one. Read by
level, a `MEDIUM` finding ranks high and a `LOW` one medium, a band above where gosec put each.

| severity tag | severity | level gosec writes |
|---|---|---|
| `HIGH` | high | `error` |
| `MEDIUM` | medium | `error` |
| `LOW` | low | `warning` |

Source: gosec's SARIF writer,
[`report/sarif/formatter.go`](https://github.com/securego/gosec/blob/244f1f6f4d1d0d14f89e79a73dab1219eabb5228/report/sarif/formatter.go)
(`parseSarifRule` and `getSarifLevel`). It is the table Draugr's own [gosec](gosec.md) scanner
reads, so an imported gosec file ranks each finding as a gosec run by Draugr does. gosec has no rung
above `HIGH`, so nothing it reports is critical. Its confidence, written as the rule's `precision`,
is not read, as the gosec scanner does not read it. The evidence line reads `severity tag medium`.

### CodeQL

A CodeQL security query carries `security-severity` on its rule, which is read first. A query without
one is rated from its rule's `problem.severity`:

| `problem.severity` | severity |
|---|---|
| `error` | high |
| `warning` | medium |
| `recommendation` | low |

Source: CodeQL's
[query metadata style guide](https://github.com/github/codeql/blob/57bace85f49150248166ec49587bcbb1fa53c440/docs/query-metadata-style-guide.md),
where `error` is "likely to cause incorrect program behavior, for example a crash or vulnerability",
`warning` "a potential problem", and `recommendation` code that "behaves correctly, but it could be
improved". The guide maps none of them to a band. These are the bands of the level CodeQL writes for
each, `error`, `warning` and `note`, so the rating names CodeQL's word without moving any finding.
The evidence line reads `problem.severity warning`.

### Fortify

A file Fortify Static Code Analyzer writes carries `Impact`, `Accuracy` and `Probability` on each
rule and `Confidence` on each result, each from 0 to 5. Fortify ranks a finding by impact and
likelihood:

```text
likelihood = Accuracy × Confidence × Probability / 25
```

| | likelihood 2.5 or more | likelihood below 2.5 |
|---|---|---|
| `Impact` 2.5 or more | critical | high |
| `Impact` below 2.5 | medium | low |

Source: Fortify's own computation in fcli,
[`VulnFinalizer.java`](https://github.com/fortify/fcli/blob/d3f24cc9763f8889a232a08167f0a1bde31a89da/fcli-core/fcli-common-fpr/src/main/java/com/fortify/cli/common/fpr/processor/VulnFinalizer.java)
(`deriveFields`), whose four priorities, Critical, High, Medium and Low, are the severities of the
same names. A value of exactly 2.5 falls in the 2.5-or-more column, as Fortify counts it. A result missing any of the
four values keeps its level: Fortify fills a missing one from category data the file does not carry.
The evidence line reads `Impact 3.0 · likelihood 3.2`.

A file Fortify on Demand writes through fcli scores every result with `security-severity`, which is
read before any table, so it needs none.

### OWASP dependency-check

dependency-check writes `security-severity` wherever an advisory has a CVSS v3 or v4 score, and it
is read first. Otherwise the rating is the first of these the file states:

| Read | severity |
|---|---|
| `cvssv3_baseSeverity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` to the band of the same name |
| `cvssv2_score` | banded as every score is: 9.0 or more critical, 7.0 or more high, 4.0 or more medium, below 4.0 low |
| `cvssv2_severity`, where no v2 score is written | `HIGH`, `MEDIUM`, `LOW` to the band of the same name |
| `severity`, for an advisory with no CVSS score | `critical`, `high`, `medium` and `low` to the band of the same name; `moderate` to medium; `info` and `informational` to low |
| the rule's summary, `medium severity - CVE-…` | the same words as `severity` |

Sources: dependency-check's SARIF template,
[`sarifReport.vsl`](https://github.com/dependency-check/DependencyCheck/blob/ae861fc07f84e3d0be75c2ed2e46b498bc03bcc1/core/src/main/resources/templates/sarifReport.vsl),
which writes the properties on the rule (version 6 wrote them on the result), and
[`ReportTool.java`](https://github.com/dependency-check/DependencyCheck/blob/ae861fc07f84e3d0be75c2ed2e46b498bc03bcc1/core/src/main/java/org/owasp/dependencycheck/reporting/ReportTool.java),
whose `normalizeSeverity` gives the words and `buildShortDescription` the summary. The CVSS v3 words
are the qualitative ratings of the
[CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document), section 5.

CVSS v2 defines no critical rating, so a v2 score of 9.0 or more is rated critical, the higher of the
two readings, rather than the `HIGH` its `cvssv2_severity` says. `unknown` rates nothing. The
evidence line names the property read, as in `cvssv3_baseSeverity medium`.

### Snyk

Snyk Open Source writes `security-severity` from an advisory's CVSS score, which is read first, and
opens each rule's summary with its own rating: `High severity - Prototype Pollution vulnerability in
lodash`. An advisory with no CVSS score, such as a license issue, is rated from that word:

| Summary opens | severity |
|---|---|
| `Critical severity - ` | critical |
| `High severity - ` | high |
| `Medium severity - ` | medium |
| `Low severity - ` | low |

Source: Snyk's CLI,
[`open-source-sarif-output.ts`](https://github.com/snyk/cli/blob/c8a6dc1b8b0df471b3f048c69b86a06d7eea4dd3/src/lib/formatters/open-source-sarif-output.ts)
(`getRules`). The level Snyk writes is `error` for critical and high alike
([`get-sarif-result.ts`](https://github.com/snyk/cli/blob/c8a6dc1b8b0df471b3f048c69b86a06d7eea4dd3/src/lib/formatters/get-sarif-result.ts),
`getLevel`), so without the summary a critical advisory with no score ranks high.

Snyk Code, `SnykCode` in the file, needs no table: its level is its rating, `error` high, `warning`
medium and `note` low, as Snyk's own code reads it back (`SarifLevelToSeverity` in
[`go-application-framework`](https://github.com/snyk/go-application-framework/blob/2362bfa6f85ae5b935bd49cb77e569c402c95516/pkg/utils/sarif/sarif.go)),
and it has no critical rung. Its `priorityScore` is not read: Snyk publishes no mapping from it to a
severity, and it adds things that are not how bad the flaw is, such as how often it occurs and
whether fix examples exist.

### A tool Draugr has no table for

The import's `severity` names the result property the tool rates in and the severity each of its
values means ([`components[].imports`](../../docs/reference/saga-schema.md#componentsimports)):

```yaml
imports:
  - control: sast
    file: reports/acme.sarif
    severity:
      property: acme-severity
      values: {Blocker: critical, Major: high, Minor: medium, Info: low}
```

Values match regardless of case and space, and a number matches however it is written. A list, such
as a rule's `tags`, takes the most severe value the mapping names. A value it does not name keeps the
level. The mapping replaces Draugr's table for a tool it has one for. The evidence line reads
`acme-severity Blocker`, and the provenance's `severity` field `acme-severity, mapped by the
descriptor`.

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

---
title: "sarif-import"
description: "Reads a file another tool wrote, or a repository's GitHub alerts, into one of Draugr's controls, so their findings are ranked and gated with the rest."
section: Scanners
order: 90
---

# Scanner: `sarif-import` (reads a file another tool wrote)

- **Control:** the control each import names in [`components[].imports`](../../docs/reference/saga-schema.md#componentsimports)
- **Tool:** none. Draugr reads a file; the tool that wrote it ran somewhere else.
- **Target:** file (a SARIF 2.1.0 log, a tool's own JSON as [A tool's own JSON](#a-tools-own-json)
  lists, or a converter's file as [A converter's file](#a-converters-file) describes), or a
  repository's alerts on GitHub ([GitHub's alerts](#githubs-alerts))
- **Effects:** none for a file. An import with `source` has a `network` effect: it asks GitHub's REST API for the repository's alerts with the import's token
- **Status:** ✅ implemented

[Import another scanner's SARIF](../../docs/guides/importing-sarif.md) walks through a pipeline that
writes the file, binds it to its commit, and scans.

## What it does

Reads a SARIF file a component imports and adds its findings to the control the descriptor names.
Each finding then takes the component's exposure and criticality into its priority, counts toward
the gate, and appears in the fix list and every report. [Before you import](#before-you-import) lists
what to set up first.

The file is read as SARIF 2.1.0 unless the import's `format` names a tool's own JSON, which
[A tool's own JSON](#a-tools-own-json) describes:

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
  one the import's mapping names, and a suppression's `kind`, `status` and `justification`, which make it
  the tool's own. A converter the descriptor declares may set some of Draugr's properties, in a file
  of its own ([A converter's file](#a-converters-file)).
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
- **Expect the file's own suppressions to hold, where they stand.** A result whose every entry in
  `suppressions` is `accepted` or has no `status` stays in the report, set aside, named by the tool,
  where it was suppressed and why. An entry that is `rejected` (the team decided not to suppress
  it) or `underReview` (not decided yet) leaves the finding counting, and its detail says `the
  file's suppression is rejected` or `underReview`. The import's `suppressions: count` counts every
  finding, as [The tool's own suppressions](#the-tools-own-suppressions) describes.
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
Nothing is looked up, so Grype's SARIF, which names its findings by GHSA and Go ids and lists no
CVE, reaches neither; Grype's JSON, imported as `grype-json`, lists the CVE, and so does
OSV-Scanner's, imported as `osv-scanner-json` (see [A tool's own JSON](#a-tools-own-json)). A note under the KEV row of **Signals** counts each imported finding that
names a package or an advisory and no CVE, as in
`not checked against KEV or EPSS: 9 imported findings name no CVE`.

## A tool's own JSON

A dependency scanner's SARIF states the package and its fixed version in prose, if at all,
govulncheck's carries no call path, Grype's names no CVE for a finding it reports under a GitHub
or Go advisory, and OSV-Scanner's carries no score. The import's
[`format`](../../docs/reference/saga-schema.md#componentsimports) reads the tool's own JSON instead,
with the parser Draugr's own run of that tool uses, so an imported finding is the finding a native
run makes of the same file. Draugr does not run OSV-Scanner, so its JSON is read on its own terms,
into findings shaped as Draugr's dependency scanners shape theirs.

| `format` | The file | Read as | Each finding carries |
|---|---|---|---|
| `sarif` | a SARIF 2.1.0 log, from any tool (the default) | this page describes | what the file states, as [Dependency findings](#dependency-findings) lists |
| `trivy-json` | `trivy fs --format json` | [`trivy-fs`](trivy-fs.md) reads it | the advisory, the package, its installed and fixed versions, its package URL and ecosystem, the other advisory ids Trivy lists, and an exclusion Trivy recorded |
| `govulncheck-json` | `govulncheck -format json` | [`govulncheck`](govulncheck.md) reads it | the advisory under its CVE, the module, its version and fixed version, and the reachability verdict with its call paths |
| `grype-json` | `grype dir:<path> -o json` | [`grype-fs`](grype-fs.md) reads it | the advisory, the package, its installed and fixed versions, its package URL and ecosystem, the identifiers Grype relates to the advisory, such as its CVE, and a match Grype's configuration ignored |
| `osv-scanner-json` | `osv-scanner scan --format json` | this page describes | the advisory OSV-Scanner matched, every id and alias it groups with it, such as its CVE, the package, its installed and fixed versions, its package URL and ecosystem, and the score OSV-Scanner gives the group |
| `draugr-converter` | what a converter the descriptor declares writes | the [converter contract](../../docs/reference/converter-contract.md) | the finding as the tool reported it, and the properties the converter may set ([A converter's file](#a-converters-file)) |

- **Severity is the native run's.** A Trivy finding is rated by the highest CVSS score Trivy lists
  for it, else by Trivy's own severity, `CRITICAL` and `HIGH` as high, `MEDIUM` as medium, `LOW` as
  low, and `UNKNOWN` as high, labeled `not scored yet`. A Grype finding is rated by its CVSS score (a
  vendor's before the NVD's), else by the bottom of the band its severity names, `Negligible` as low.
  A Grype finding with no CVSS score and an `Unknown` severity is high, labeled `not scored yet`. The
  Go vulnerability
  database publishes no severity, so a govulncheck finding is medium, as a native one is. An
  OSV-Scanner finding is rated by its group's `max_severity`, the highest CVSS score OSV-Scanner
  computed from the grouped advisories' vectors, version 4 included; else by the highest
  `database_specific.severity` among them, `CRITICAL` as critical, `HIGH` as high, `MODERATE` as
  medium, `LOW` as low; else as high, labeled `not scored yet`. The tables
  in [Each tool's own rating](#each-tools-own-rating) read SARIF and do not apply, and the
  descriptor refuses an import's `severity` beside a tool's JSON.
- **Only a Grype scan of a directory is read.** An image scan is about the image, not the
  component's repositories, so it is refused. Draugr reads the JSON as grype-fs reads a run, with the
  SARIF Grype would have written from it.
- **Only OSV-Scanner's lockfile and SBOM results are read.** Each is a file in the repository,
  whose path places the finding: an absolute path inside the component's local checkout is made
  relative to it, and any other is kept as a SARIF file's is. A container image's results are about
  the image and a git result names a commit rather than a version, so a file holding either is
  refused.
- **An OSV-Scanner finding is one vulnerability in one package**, as OSV-Scanner groups advisories
  that alias each other, under the group's first id. Its fixed version is the one closing the
  advisory's range for that package that holds the installed version, never another package's the
  advisory also covers, and the later of two where grouped advisories differ. A range closed by
  `last_affected`, or by nothing, means no fix. The package URL loses the `source` qualifier
  OSV-Scanner adds, such as `?source=PUBLIC_REGISTRY`, so the finding meets another scanner's copy
  of the flaw in the same package.
- **A vulnerability OSV-Scanner's configuration ignores never reaches Draugr.** OSV-Scanner leaves a
  vulnerability listed under `[[IgnoredVulns]]` in its `osv-scanner.toml`, with its aliases, out of
  the JSON altogether, and states the reason only on its standard error. With OSV-Scanner 2.7.1 ignoring
  GHSA-29mw-wpgm-hmr9 for the reason `test`, it printed
  `GHSA-29mw-wpgm-hmr9 and 1 alias have been filtered out because: test` and
  `Filtered 1 vulnerability from output`, and the JSON held the other three groups. Draugr cannot
  count, list or audit what is not in the file, so the decision appears nowhere in its report,
  unlike an exclusion in the descriptor, which stays in the report as a suppressed finding with its
  reason. OSV-Scanner's
  [configuration documentation](https://google.github.io/osv-scanner/configuration/) names no
  setting that writes ignored vulnerabilities into the output. To keep the decision on record, set
  it aside in the descriptor's `config.exclude` instead. The import refuses `suppressions`, which
  has nothing to apply to.
- **The checkout is read only to place a finding.** Where the component has one repository and its
  `url` is a path, the parsers read that checkout as a native run reads its own: Trivy's for the
  line of a package's entry in its manifest, govulncheck's for the `go.mod` of each module, matched
  from the packages each run started from, Grype's for the `.grype.yaml` holding a rule that
  ignored a match, which the suppression names, and OSV-Scanner's for the line of a package's entry
  in its lockfile. With several repositories, or a remote address, a Trivy finding has the line
  Trivy recorded or none, a govulncheck finding is at `go.mod`, a match Grype ignored names the
  imported file, and an OSV-Scanner finding is at its lockfile with no line.
- **What a native run reads of this machine is left out.** Trivy's list of every package and of the
  dependency files it read, and govulncheck's runs per platform and its mark on a requirement no
  run compiled, describe the build of the machine that ran them. A file written on another machine
  says nothing about this one's.
- **A verdict needs nothing but the file.** Reachable is a call path the run found. Unreachable
  needs a run that analyzed symbols, as govulncheck does by default, and listed the module in what
  it built; a run with `-scan module` or `-scan package` leaves every verdict undetermined. The
  verdict reaches another scanner's finding of the same advisory in the same `go.mod` and
  repository, as a native run's does, and the imported copy is then folded into it. It is dated by
  the file's modification time, and it is not narrowed to the call paths that start in the
  component's `paths:`.
- **A govulncheck file covers the Go modules its runs were started in.** With a local checkout, each
  `go.mod` in it is accounted for, and one no imported file analyzed is listed under `unread-files`
  with the command to run there. Without a local checkout, no module is accounted for.
- **Bind a govulncheck file with `commit`, or its unreachable verdicts lower nothing.** Without a
  binding (no `commit`, an unset variable, or a component of several repositories) an unreachable
  verdict is read as undetermined and the finding keeps its band, its message ending `reachability
  not determined: the file is bound to no commit`. A reachable verdict applies either way. See
  [Commit](#commit).
- **The file names no commit or repository.** Only the import's `commit` binds it, and only in a
  component of one repository (see [Commit](#commit)). In a component of several, its findings are
  placed in none: they merge with no native copy, `paths:` and `ignore:` do not apply, and the file
  is unbound. Import it into a component of one repository to place it.
- **The report names the format beside the tool**, under **Measured against** as
  `tool: trivy 0.76.1 · format: trivy-json`, and on a merged finding as
  `also found by imported trivy (trivy-json)`.

## A converter's file

A tool Draugr has no reader for reaches a report through a converter: a program a CI step runs on
the tool's output, writing a file in the [converter
contract](../../docs/reference/converter-contract.md). Draugr never runs it. The import names it
with `format: draugr-converter` and declares it under
[`converter`](../../docs/reference/saga-schema.md#componentsimports), and [Write a
converter](../../docs/guides/writing-a-converter.md) walks through one.

- **The file names its commit**, and is held to it as a SARIF file's `versionControlProvenance` is
  (see [Commit](#commit)). In a component with several repositories it names the one it is about
  in `repository`, and is placed and bound there.
- **Severity is the converter's**: its `score` where it gives one, else its `severity`. The
  provenance's `severity` field reads `converter score` or `converter rating`.

The [converter contract](../../docs/reference/converter-contract.md#what-a-converter-may-set) lists
what a converter may and may never set, and the stamp each finding carries.

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
- **The same rule on another line, or the same advisory in another package.** Two packages stay two
  findings at one line too: Trivy's SARIF places every Go dependency at `go.mod:1` and names the
  package only in its message, and each keeps its own package and fixed version. Each keeps the
  advisory's own title, so two rows can share a title and differ only in the package line.
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
| `tool` | the tool's name and version, as the file states them. OSV-Scanner's JSON states neither, and reads `osv-scanner` |
| `format` | the import's `format`, where it is a tool's own JSON. Absent for SARIF |
| `file` | the path the descriptor gave |
| `written` | when the file says its run ended (`invocations[].endTimeUtc`, `CreatedAt` in Trivy's JSON, or `descriptor.timestamp` in Grype's), or else the file's modification time |
| `severity` | where severities came from: `security-severity`, the tool's own rating as its table below names it, such as `gosec's severity tag`, the import's mapping, as `acme-severity, mapped by the descriptor`, `SARIF level`, or a count of each, as `security-severity for 2, problem.severity for 5`. For a tool's own JSON, `CVSS score`, `Trivy's severity` and `Trivy's UNKNOWN, not scored yet, read as high`, `CVSS score, else Grype's severity`, `govulncheck states none, read as medium`, or for OSV-Scanner `CVSS score`, `the advisory's severity` and `OSV-Scanner states none, not scored yet, read as high` |
| `commit` | the commit the file was checked against, or `not stated`. Where the import's `commit` could not bind the file, why, as `not stated, ${{ GITHUB_SHA }} is not set` or `not stated, the file does not say which repository 0123456789ab is in` |
| `component` | the component that imports it |
| `left out` | how many findings were dropped from this component because the repository's `paths:` or `ignore:` excludes their file, as `3 findings outside paths, 1 matched by ignore, not counted`. They are not in the findings, the priorities or the gate. Absent where none was left out |
| `not scoped` | how many findings were kept without applying `paths:` and `ignore:`, because the file names none of the component's repositories, or more than one. Add `runs[].versionControlProvenance` naming the repository the tool scanned, as [In a component with several repositories](../../docs/guides/importing-sarif.md#in-a-component-with-several-repositories) shows, and they are scoped on the next run. Absent where none was, and where the component's repositories declare no scope |
| `folded` | how many results repeated another of the file's exactly, with the same rule, place, message and package, and were counted once, as `1 finding repeating another of the file's exactly, counted once`. Absent where none did |
| `sha256` | the file's content, so a run can be checked against the file it read |

## The tool's own suppressions

A tool records that it suppressed a finding in a SARIF `suppressions` entry: `kind` `inSource` for
a comment in the code, such as Bandit's `# nosec` or Semgrep's `# nosemgrep`, and `external` for
its own settings, such as a finding dismissed in the tool's console. `justification` is the reason,
which SARIF leaves optional, and SARIF has no field for who suppressed it. The import's
[`suppressions`](../../docs/reference/saga-schema.md#componentsimports) decides what Draugr does
with a finding whose every suppression is `accepted` or has no `status`:

- **`honor`**, the default, sets it aside:
  - It stays in the report and out of the gate.
  - The `ACCEPTED` block counts it on a row named for the tool, and `--evidence` lists under the
    row where the tool suppressed each and why, as
    [Findings an imported tool suppressed](../../docs/reference/saga-schema.md#findings-an-imported-tool-suppressed)
    shows.
  - In `report.json` its `suppressed` carries `origin` `tool` (in a comment in the code) or
    `scanner` (in the tool's own settings), the `justification` where there is one, and the file as
    `source`.
- **`count`** counts it, and the gate judges it. Its detail says what the tool recorded:
  `bandit suppressed it in a comment in the code · no reason given · counted, as the import says suppressions: count`.

A suppression the file marks `rejected` or `underReview` leaves its finding counting under either
value, and [`config.exclude`](../../docs/reference/saga-schema.md#configexclude) sets aside any
counted finding with a reason in the descriptor.

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
scanned, in `runs[].versionControlProvenance`, or the import's
[`commit`](../../docs/reference/saga-schema.md#componentsimports) names it, Draugr holds the file to
the commit this run reads:

- **The same commit:** the file is read, and `commit` names it.
- **A different commit:** the run stops with an error naming both, as `scanned fedcba987654, this
  run reads 0123456789ab. Run the tool again`. Run the tool on this commit, or remove the import.
- **No commit named:** the file is read and listed under **Caveats** as `unbound-imports`, because nothing
  ties its findings to this code.
  [`config.gate.failOnCaveats: [unbound-imports]`](../../docs/reference/saga-schema.md#configgate)
  makes that fail the run.

A commit matches its abbreviation, of 7 characters or more, regardless of case. Where the file and
the import both name a commit and they differ, the run stops with `file has 0123456789ab,
commit is fedcba987654. Fix commit, or run the tool again`. An import's `commit` that references a variable the
environment does not set, such as `${{ GITHUB_SHA }}` on a laptop, leaves the file unbound rather
than failing the load.

A component with one repository is held to it whatever address the file gives, because a tool
records the remote it saw and the descriptor may name the same repository by a local path. Entries
that list one repository at one revision, a subtree each, count as one. With several distinct
repositories, the address has to name one of them. The import's `commit` names no repository, so
with several it is held to the one the file's `repositoryUri` names, and a file that names none of
them, or more than one, stays unbound.

A tool's own JSON states no commit and no repository, so the import's `commit` is the only binding,
and with several distinct repositories the file stays unbound, `commit` reading `not stated,
trivy-json names no repository and the component has several`.

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

A file read as a tool's own JSON is refused where it is not that JSON, rather than read as a scan
that found nothing:

- `not Trivy JSON. Write it with trivy fs --format json`, for a file with no `SchemaVersion`, such
  as a SARIF log or a CycloneDX document;
- `schema 3 Trivy JSON; Draugr reads schema 2`, for a report in a schema Draugr does not read;
- `not govulncheck JSON. Write it with govulncheck -format json`, for a stream whose runs do not
  each open with govulncheck's `config` message;
- `not Grype JSON. Write it with grype dir:. -o json`, for a file whose `descriptor` does not name
  Grype or that lists no `matches`;
- `image scan; Draugr reads only directory scans. Run grype dir:. -o json`, for Grype's JSON of a
  scan of anything but a directory;
- `not OSV-Scanner JSON. Write it with osv-scanner scan --format json`, for a file with no
  `results` list, or a result or group that names no source type or no id;
- `docker source; Draugr reads only lockfiles and SBOMs. Scan the directory`, for OSV-Scanner's JSON
  holding a result of any source but `lockfile` and `sbom`, the type named first;
- `not a converter file. A converter writes contract draugr-converter`, for a file read as a
  converter's that is not one. The [converter
  contract](../../docs/reference/converter-contract.md#errors) lists the rest, each naming the key
  at fault.

`draugr doctor` reads the file with the same reader, so a file the scan would refuse fails doctor
with the same message, and a file that passes reports how many results it holds, as
`SARIF 2.1.0, 3 results` or `Trivy JSON, 4 findings`. Doctor does not
compare paths with the component's checkout, and does not hold the file to a commit: the scan lists
a path it cannot place under `unread-files`, and stops on a file named for another commit.

## GitHub's alerts

An import's [`source`](../../docs/reference/saga-schema.md#githubs-alerts) reads a repository's
alerts from GitHub's REST API in place of a file:

| `source` | Endpoint | Alerts read |
|---|---|---|
| `github-code-scanning` | `GET /repos/{owner}/{repo}/code-scanning/alerts` | `open` and `dismissed` |
| `github-dependabot` | `GET /repos/{owner}/{repo}/dependabot/alerts` | `open`, `dismissed` and `auto_dismissed` |

Each state is asked for 100 alerts a page, following the `Link` header's next page, with API version
`2026-03-10`. A `fixed` alert is not read. No `ref` is sent: GitHub answers a ref it has not
analyzed with an empty list, the same answer as a repository with no alerts, so the default branch's
alerts are read and held to the commit this run reads instead ([Alerts and the commit](#alerts-and-the-commit)). GitHub marks
the Dependabot alerts API "public preview and subject to change", and the report says so under
**Measured against** as `api`.

**The repository** is the component's one repository, read from its `url`, or from the remote of a
local checkout, which has to be on `github.com`. A component of several repositories names one with
`repository: owner/name`, one import each, and validate refuses a source that leaves the choice
open; a `repository` the component does not declare stops the run. Its findings are placed in that
repository, so its `paths:` and `ignore:` apply, as [Paths and ignore](#paths-and-ignore) describes.
GitHub Enterprise Server is reached where the pipeline sets `$GITHUB_API_URL`, with the repository
named by `repository`, since its address is not on `github.com`.

**The token** is read from the variable `tokenEnv` names, `GITHUB_TOKEN` when unset. Any other name
has to be listed in `$DRAUGR_TOKEN_ENVS`, which the pipeline sets, because the descriptor changes by
pull request and the token goes to GitHub. It is sent as `Authorization: Bearer` over https to the
API's own address, never to a next page on another host, and is never stored, logged, or written to
a report. GitHub's documentation names the classic scope `security_events`, or `public_repo` for a
public repository only. Its REST pages for both endpoints state no fine-grained token permission,
so none is named here. In GitHub Actions, `GITHUB_TOKEN` lists code-scanning alerts with
`security-events: read` and Dependabot alerts with `vulnerability-alerts: read`, as the workflow
syntax's `permissions` table states.

### Code-scanning alerts

| Finding | From the alert |
|---|---|
| tool | `tool.name`, as `Draugr` or `CodeQL` |
| rule | `rule.id` |
| location | `most_recent_instance.location`: `path` and `start_line`. A Scorecard alert's `no file associated with this alert` is read as no location |
| message | `most_recent_instance.message.text`, else `rule.description` |
| severity | `rule.security_severity_level` (`critical`, `high`, `medium`, `low`) where the rule has one; else `rule.severity` as a SARIF level: `error` high, `warning` medium, `note` and `none` low |

An alert carries a severity bucket and no score, package URL, aliases or fixed version, so its
finding is ranked from less than a SARIF file with scores. The report's `severity` field says so:
`rule.severity for 8, security_severity_level for 3; alerts carry no score, package, aliases or fix`.
KEV and EPSS reach a finding only where its rule id is a CVE. A finding merges with the control's
own scanner's copy of the same tool's rule at the same line, as a SARIF file's does.

An alert Draugr uploaded of its own run names `Draugr` as its tool, and its rule's `scanner:` tag
names the tool that found it, such as `gosec`. Where that tool's native finding of the same rule at
the same line was suppressed in this commit's code, by a `#nosec` or a `nosemgrep`, the alert takes
that suppression, origin `tool` and its reason, and is set aside rather than counted. An alert whose
native copy counts keeps counting, and an alert's dismissal never sets a native finding aside.

### Dependabot alerts

| Finding | From the alert |
|---|---|
| tool | `Dependabot` |
| rule | `security_advisory.ghsa_id` |
| aliases | `security_advisory.cve_id` and the other `identifiers`, so KEV and EPSS reach it through the CVE |
| location | `dependency.manifest_path` |
| package | `dependency.package.name` and `ecosystem` |
| fixed version | `security_vulnerability.first_patched_version.identifier`, which makes it an upgrade |
| score | `security_advisory.cvss_severities.cvss_v3.score`, else `cvss_v4`, else `cvss`; with none, `security_advisory.severity` as a level |

The alert's own `epss` is not read: the CVE reaches Draugr's EPSS data, so a finding is not ranked by
two copies of one feed from different days. The alert names no installed version, and correlation
keys a package on its name and version, so a Dependabot finding is counted beside the control's own
scanner's copy of the same advisory rather than merged into it.

### Dismissed alerts

| State | `suppressions: honor` (the default) | `suppressions: count` |
|---|---|---|
| `dismissed`, by a person (`dismissed_by.type` `User`) | set aside: `who` is `dismissed_by.login`, the reason `dismissed_reason` with `dismissed_comment`, or `no reason given`, and the source the alert's address | counted, its detail `octocat dismissed it in Dependabot · reason: tolerable risk (…) · counted, as the import says suppressions: count` |
| `dismissed`, by a bot or an account of no stated type | counted | counted |
| `auto_dismissed` (Dependabot) | counted | counted |

A bot's dismissal counts because a workflow is not a person's decision about the finding, and an
account whose type GitHub does not state is not assumed to be a person. Its detail names the account,
so a team sees which workflow did it, and gives the
[`config.exclude`](../../docs/reference/saga-schema.md#configexclude) entry that sets it aside here,
with the alert's file as `paths`, for a reader who has looked:

```text
dismissed by github-actions[bot] in GitHub code scanning · reason: won't fix (Accepted in Draugr: a go.mod inside the checkout) · counted. To set it aside, add to config.exclude {rules: [G304], paths: [internal/scanners/govulncheck.go], reason: <why it is set aside>, expires: <YYYY-MM-DD>}
```

An alert Dependabot dismissed by one of its own rules counts the same way, because nobody looked at
the finding, with the manifest as `paths`:

```text
dismissed automatically by a GitHub rule · counted. To set it aside, add to config.exclude {rules: [GHSA-xvch-5gv4-984h], paths: [web/package-lock.json], reason: <why it is set aside>, expires: <YYYY-MM-DD>}
```

A set-aside alert is counted on an `ACCEPTED` row named for the service and the tool, as
`GitHub code scanning (CodeQL)  2 alerts dismissed in GitHub, not counted`, or `Dependabot`, and
`--evidence` names who dismissed each, as
[Findings an imported tool suppressed](../../docs/reference/saga-schema.md#findings-an-imported-tool-suppressed)
shows. In `report.json` its `suppressed` carries `origin` `scanner`, `service`, `author`, `asserted`
and the alert's address as `source`.

### Alerts and the commit

Each code-scanning alert names the commit GitHub last saw it at, and each analysis, a tool and a
category, runs on its own schedule: a weekly OpenSSF Scorecard analysis names an older commit than a
scanner run on every push. Each analysis is held to the commit this run reads apart, as each run of
a SARIF file is:

- **An analysis with an alert seen at this commit** describes this commit. A dismissed alert of it
  last seen at another commit is one that analysis did not find here: it is left out of the
  findings, the gate and the `ACCEPTED` block alike, and **Measured against** counts it, as
  `left out: 1 dismissed alert not counted: GitHub last saw it at another commit`.
- **An analysis with no alert seen at this commit** describes other code. Its alerts are kept, the
  open ones counting at their full rating, and the import is unbound, `commit` reading `not stated ·
  1 of 2 analyses last ran at another commit; this run reads cc4899689bce`. `--evidence` names the
  analyses, as `analyses: Scorecard (supply-chain/local) last ran at another commit`.
- **No alerts at all** reads `not stated · GitHub lists no alerts`.

Dependabot alerts name no commit. They describe the default branch's manifests when GitHub last read
them, which need not be the commit this run reads, so a Dependabot import is always unbound, `commit`
reading `not stated · Dependabot alerts name no commit`. An unbound import is listed under
**Caveats** as `unbound-imports`, and nothing in it is ranked lower for an absence:

```text
unbound-imports
  draugr
    GitHub code scanning  1 of 2 analyses ran at another commit; some alerts may not describe this code
  shop
    Dependabot  Dependabot alerts describe the default branch, not this commit
```

Alerts are read on every run, never from the cache: an alert is dismissed, or a new analysis lands,
with nothing in the descriptor or the tree changing.

### What the report says about the alerts

| Field | Value |
|---|---|
| `tool` | the tools the alerts name, each once with its versions, as `Draugr 0.181.1, Scorecard v5.6.0`, or `Dependabot` |
| `source` | the service and the repository, as `GitHub code scanning alerts for draugr-dev/draugr` |
| `read` | when the alerts were read |
| `severity` | where severities came from, as above |
| `commit` | as [Alerts and the commit](#alerts-and-the-commit) describes |
| `analyses` | with `--evidence` only, the analyses GitHub last ran at another commit. Absent where none did |
| `component` | the component that imports them |
| `left out` | dismissed alerts last seen at another commit, which are in no finding or count. Absent where none was |
| `api` | for Dependabot, that its API is in public preview and subject to change |

### Errors

Each refusal stops the run as a scanner that could not run does, rather than reading as a repository
with no alerts:

| GitHub answers | The error |
|---|---|
| 401 | `GitHub refused $GITHUB_TOKEN as invalid or expired. Create a new one` |
| 403 to code scanning, "Code Security must be enabled" | `Code Security is off. Turn it on in the repository's settings (HTTP 403)` |
| 403 to Dependabot, "Dependabot alerts are disabled" | `Dependabot alerts are off. Turn them on in Settings, Code security (HTTP 403)` |
| 403, any other | `a classic token needs security_events, or public_repo if public (HTTP 403)` |
| 404, "no analysis found" | `GitHub has no code-scanning analysis of acme/api (HTTP 404)` |
| 404, any other | `no repository acme/api, or the token cannot see it (HTTP 404)` |
| 429, or 403 with a rate limit | waited out, as below |

Each source's message is read only from that source, so another 403 that says something must be
enabled, such as an organization's SAML enforcement, is read as the token lacking access.

A rate-limited answer is waited out for as long as its `retry-after` says, or until the
`x-ratelimit-reset` it sends with `x-ratelimit-remaining: 0`, or a minute where it names neither, as
GitHub's documentation asks, and asked again, three times in all. A wait longer than two minutes
stops the run with `GitHub's rate limit lasts until 15:40 UTC (HTTP 403)`, and a limit still in force
after the third try with `GitHub kept limiting requests after 3 tries (HTTP 429)`. An empty or
unlisted token variable, and an `--offline` run, stop the run before anything is sent.

`draugr doctor` checks that the token's variable may be read and is set, sending nothing.

## What is sent

For an import of a file, nothing. For an import with `source`, to GitHub's REST API at
`api.github.com`, or `$GITHUB_API_URL`: the repository's owner and name, the alert states asked for,
and the token. Nothing about the code, the findings or the descriptor is sent.

## License & terms

No third-party tool is executed or bundled, so the scanner carries only Draugr's own license. The
file is the reader's; its tool's terms governed whoever produced it, before Draugr read it.

An import with `source` uses GitHub's REST API with the reader's own token, under
[GitHub's Terms of Service](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service),
section H, API Terms, and the
[GitHub General Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement),
both read on 2026-11-17. The terms say "Abuse or excessively frequent requests … may result in the
temporary or permanent suspension of your Account's access to the API", and that "You may not share
API tokens to exceed GitHub's rate limitations". Draugr asks for one repository's alerts per import
per run and honors `retry-after`. The terms say nothing specific about a tool keeping alert data; the
alerts go into the report on the machine that ran the scan.

## Data

For a file, no data source: the scan reads the file the descriptor names, on the machine running
Draugr, and resolves the component's repository revision with `git`, locally for a path and with
`git ls-remote` for a remote.

For an import with `source`, `api.github.com` (or `$GITHUB_API_URL`), on every run: the alerts are
GitHub's current account of the repository and are not cached.

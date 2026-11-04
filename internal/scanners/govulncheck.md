---
title: "govulncheck"
description: "Decides which known vulnerabilities this Go code can actually reach, with the call path as evidence."
section: Scanners
order: 60
---

# `govulncheck` scanner

Reachability analysis for Go modules: which of a repository's known vulnerabilities this code can
actually reach.

- **Control:** `sca`
- **Target:** repository
- **Tool:** [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck), from the Go team
- **Enabled by:** `config.reachability.analyzers: [govulncheck]`. Opt-in, because it needs the Go
  toolchain and only answers for Go

## What it does

It asks a different question from the other `sca` scanners. Trivy reads a manifest and reports
which dependencies have known vulnerabilities. `govulncheck` builds a call graph from the packages
that are actually in the build and reports which of those vulnerabilities the code can reach, and
for the ones it can, the call path that reaches them.

That makes it an enrichment rather than a second opinion, and it is wired as one. Its verdicts are
folded onto the findings the manifest scanner already produced, matched on component, repository,
the `go.mod` that declared the dependency, the dependency and the vulnerability id; its own copy is
then dropped. Without that fold, every Go vulnerability would be
reported twice under two different identifiers, `CVE-2022-32149` from Trivy and `GO-2022-1059`
here, which is the opposite of what a noise-reduction feature is for.

govulncheck reports a finding under the identifier the manifest scanners use. That is the
advisory's CVEs, or its GitHub advisory ids (`GHSA-…`) where it has no CVE, or its Go advisory id
(`GO-…`) where it has neither.

**The finding keeps the advisory's other identifiers**, the Go advisory id and each alias the Go
vulnerability database lists on the entry govulncheck printed, other than the rule id. Grype reports
a Go flaw with no CVE from the same database under its Go id, `GO-2026-5775`, where this finding
carries `GHSA-9g5q-2w5x-hmxf`. The verdict reaches Grype's copy through the Go id, this copy folds
onto it, and the flaw is counted once, ranked by the verdict. An identifier govulncheck also reports
as a finding of its own carries no verdict across, because it reported the two as two findings.

A vulnerability only this scanner reports is **kept**, because a finding one tool found and
another missed is exactly the one that must not disappear in a deduplication.

**Each Go module is analyzed on its own**, once per `go.mod` outside `vendor/` and `testdata/`,
and each verdict is located at that module's `go.mod`. Two modules requiring the same dependency
each get a verdict. The module that calls the vulnerable function is `reachable`, and the one that
only requires it is not lent that call path. Two components sharing a repository, each scoped by
`paths:` or `ignore:`, each get the verdict for their own code. A module a `go.work` workspace uses
is analyzed as the workspace builds it, which is the build `go build` in that directory produces,
and a module the workspace does not use is analyzed on its own.

**A module with nothing to build is passed by.** A `go.mod` whose module holds no Go file in the
build, under the default build constraints for the machine and any `-tags` your `GOFLAGS` sets, has
no code to start a call graph from, and govulncheck does not run over it. A `tools` module holding
only a `//go:build tools` file is the common case, and nothing is reported for it.

**A module govulncheck cannot load is a caveat, and the others keep their verdicts.** A module that
does not compile, needs a C library the machine lacks, or uses generated code nobody generated fails
to load. Its `go.mod` is listed under **Caveats** as `unread-files`, and the reason, after
`govulncheck:`, names what to do where govulncheck's diagnostics show what is missing:

| Cause | Reason |
|---|---|
| a cgo package's C header is not installed | `install the package that provides fuse.h, which github.com/winfsp/cgofuse/fuse includes` |
| a cgo package's pkg-config library is not installed | `install the package that provides <library>, which <package> needs`, naming two and counting the rest |
| a file of the package declares the identifier behind a build tag | `set GOFLAGS=-tags=noassets, under which cmd/infra/strelaypoolsrv/auto/noassets.go declares auto.Assets` |
| nothing in the checkout declares the identifier, usually generated code | `generate or declare pb.PredictOptions, used at pkg/grpc/backend.go:71` |
| anything else | govulncheck's first diagnostic |

The module's findings keep the band the manifest scanner gave them and carry no verdict, and an
advisory only govulncheck reports, such as one in the standard library, was not checked there. A
failure that
holds for every module, such as a database govulncheck cannot reach, still fails the repository's
job. To fail the run on a module that did not load, set
[`config.gate.failOnCaveats: [unread-files]`](../../docs/reference/saga-schema.md#configgate).

**Standard-library advisories follow each module's Go.** govulncheck runs with the module as its
working directory, where it reads `go env GOVERSION`, so the standard library is checked at the
version the go command builds that module with: the toolchain its `go` or `toolchain` line, or its
`go.work`'s, selects, or the Go on PATH where that is newer. With go1.26.10 on PATH, a module
declaring `go 1.27.1` is checked against go1.27.1 and one declaring `go 1.26` against go1.26.10.

**Components carved out of one module** are each analyzed from their own code. The checkout holds
the whole module, as [Scoping a repository](../../docs/reference/saga-schema.md#scoping-a-repository)
describes, and govulncheck starts from the packages the component's `paths` hold: `./cmd/api/...`
for `paths: [go.mod, cmd/api]`. A vulnerable function that only another component calls is
`unreachable` for this one.

A component whose `paths` hold no Go package of the module, only its `go.mod`, is analyzed from the
whole module and keeps the call paths that start in its own files. govulncheck reports one call
path per vulnerable function, so with none of its own the verdict is `unknown`. The verdict stays
with the component whose `paths` name the module's `go.mod`, and goes to any other component only
with a call path from its files.

## The three verdicts, and why there are three

| verdict | means |
|---|---|
| `reachable` | a call path was found, and is attached as evidence |
| `unreachable` | the module was analyzed and no path was found |
| `unknown` | no analysis covered it, or the only call path found starts in another component's code |

The third is the one that keeps the other two honest. A dependency used **only from `_test.go`
files** produces no `govulncheck` output at all, not a module-level record, nothing, at every scan
level, while a manifest scanner reports it normally. So the absence of a record is not evidence of
unreachability, and `unreachable` is only claimed when the run reported `scan_level: symbol`
**and** the module appears in the run's `SBOM` message. Anything else is `unknown`.

This scanner is not a superset of a manifest scanner. It sees the build graph; a manifest scanner
sees the manifest.

## What a verdict does to a finding

It feeds the priority band and never rewrites the severity the scanner reported, exactly as
exploitability enrichment does in the other direction. An `unreachable` finding is ranked one band
down; a `reachable` one is unchanged, because severity already assumes the code runs.

The band moves because of **how** this scanner decided, not because it decided. It records
`method: call-graph`, which Draugr treats as evidence that the vulnerable code does not run; an
analyzer whose negative rests on a framework's own account of its routing is reported and lowers
nothing. [Prioritization](../../docs/concepts/prioritization.md) has the table.

It never suppresses. Static analysis is defeated by reflection, dynamic dispatch and code
generation, and a suppression in Draugr records that a *person* decided, with a name attached. An
inference is not a decision. Where exploitability enrichment has already raised a finding, that
wins: observed exploitation outranks a call graph's failure to find a path.

## License and terms of use

Two different licenses, because the tool and the data it reads are distributed separately:

- **The tool**. `golang.org/x/vuln` is distributed by the Go team under a **BSD-3-Clause**
  license. Draugr executes it as a subprocess and neither links nor bundles it, so its license
  stays its own.
- **The data**, entries in the [Go vulnerability database](https://go.dev/security/vuln/database)
  are distributed under **CC-BY-4.0**. Attribution is a condition of that license, which is why
  reports name the database rather than presenting its contents as Draugr's own findings.

No account, key or registration is required, and no tier restricts commercial use.

## What is sent

Nothing about the code under scan. The tool fetches the vulnerability database over HTTPS from
`https://vuln.go.dev`, an index at `/index/modules.json`, then individual advisory records at
`/ID/$id.json`. The API is documented as having "no query parameters, and no specific headers are
required": no manifest, no source and no inventory is uploaded.

Fetching a vendor's vulnerability database is not an effect on the target, so this scanner declares
none, the same reasoning that applies to the other database-backed scanners. It needs network
access to that host, or a local copy fetched with `draugr feeds update govulndb`.

## Integration notes

- **Output is a concatenated JSON stream**, not JSONL and not one document. It is decoded with a
  streaming decoder in a loop. Message kinds are `config`, `SBOM`, `progress`, `osv` and `finding`.
- **One vulnerability produces several `finding` messages**, at module, package and symbol
  granularity, distinguished only by how much of the trace is filled in. Reachability is derived
  from the set, not read off any one of them.
- **Traces are ordered callee first.** They are reversed on the way in so a call path reads from
  this project's own code toward the vulnerable symbol.
- **The Go vulnerability database publishes no severity**, so findings this scanner contributes on
  its own carry none and normalize to `warning`. Where a manifest scanner rated the same
  vulnerability, the fold keeps that rating.
- **An advisory is reported under each CVE it has**, and under its `GO-` id only when it has no
  CVE. The same choice `retirejs` makes, and what lets exclusions, exploitability feeds and other
  scanners' findings line up with it.
- **Tests are not analyzed.** Reporting a vulnerability reachable only from code that never ships
  produces a finding a developer cannot act on, which is the kind that teaches people to stop
  reading the report.
- **Requires a Go module, and a Go toolchain to install and to run.** `draugr tools install govulncheck`
  provisions it at the pinned version with `go install`, because govulncheck publishes no release
  binary, so there is no archive to download. The build is verified against the Go checksum
  database, which covers every module it is built from and not only the tool; an install that
  could not reach the database still succeeds and is recorded as `unverified`, because reporting
  otherwise would claim evidence nobody gathered. With no Go on PATH, the error names the toolchain
  and the `go install` line that does the same job by hand.

  **The Go that builds govulncheck is pinned beside it.** The go/types package compiled into
  govulncheck refuses a package whose `go` line names a newer language version than the Go that
  built it, so a govulncheck built with Go 1.26 reports `package requires newer Go version go1.27`
  for a module declaring `go 1.27.1`. The install builds with the `go` on PATH where it is at least
  the pin, and otherwise sets `GOTOOLCHAIN` to the pin, which `go` downloads and checks against the
  same checksum database. A `GOTOOLCHAIN` in your environment that names a release, such as
  `go1.28.0`, is used instead. The install record names the Go that built the binary, and a build
  from a Go older than the pin is not current, so the next `draugr tools install` replaces it.
  `draugr doctor` reads that Go from the binary's build information, because `govulncheck -version`
  prints the Go on PATH instead, and flags a build older than the pin.

  govulncheck loads a module's packages with `go`. A scan over a module with no `go` on PATH fails
  with ``govulncheck needs Go, and no `go` is on PATH``, where govulncheck itself would report
  `no go.mod file`. A tree holding no module runs nothing and needs no Go. A run loads one Go
  module's packages at a time, across govulncheck and gosec on every repository, so the compile
  processes of a load stay within the bound each tool runs under for the whole run rather than for
  each repository.

  Draugr does not run govulncheck over a module whose `go` line, or the `go` line of the `go.work`
  governing it, names a newer language version than the Go govulncheck was built with. The
  repository's job fails with the file, both versions and the command that rebuilds the tool:

  ```console
  govulncheck was built with go1.26.10 and cannot load services/api/go.mod, which declares go 1.27.1. Run draugr tools install govulncheck --force.
  ```

  Where the module declares a newer Go than the pin, the command names that Go as `GOTOOLCHAIN`, or
  a newer Draugr. The `go.work` read is the one `GOWORK` names, or the nearest one above the module
  inside the checkout, and none under `GOWORK=off`.

  **A workspace is read from a copy.** The checkout is read-only, and in workspace mode the go
  command writes any checksum it lacks to the `go.work.sum` beside `go.work`, so a repository that
  commits `go.work` without a complete `go.work.sum` would fail with `permission denied`. For a
  module listed under `use` in the governing `go.work`, govulncheck runs with `GOWORK` naming a copy
  of that `go.work` in a temporary directory, beside a copy of `go.work.sum` where the repository
  commits one. The copy's `use` paths and relative `replace` paths are absolute, so they name the
  checkout's modules. The go command writes its checksums beside the copy, the copy is removed when
  the run ends, and nothing in the checkout changes. A module the `go.work` does not list runs with
  `GOWORK=off`, the only setting under which the go command builds it. A workspace with
  `vendor/modules.txt` beside a `go.work` declaring go 1.22 or later is built from `vendor/`, reads
  no checksums, and runs from the checkout without a copy. A `GOWORK` already set in your
  environment is used as it is.

  `draugr doctor` asks for it whenever a descriptor names it under `config.reachability`, so a
  missing analyzer is reported before a scan rather than by one. It is not required when the `sca`
  control is switched off, because `config.reachability` is project-wide and an analyzer whose
  control never runs is a tool nobody needs to install.

## Scope of the claim

**Go only.** The docs say *reachability for Go* every time, because a reachability claim without
its language is an overclaim, and because the analysis behind the word differs between tools: a
call graph and a framework heuristic are both called reachability and are not the same evidence.

## Data

The **vulnerability database**, from `vuln.go.dev`. Without a local copy, govulncheck fetches it on
**every** invocation, and there is one invocation per Go module in the checkout, and one per
component where several are carved out of one module.

`draugr feeds update govulndb` downloads `https://vuln.go.dev/vulndb.zip` into
`~/.draugr/feeds/govulndb`. A scan passes that copy to govulncheck as `-db file://…` when it passes
three checks, and refuses it otherwise:

| Check | Refused when |
|---|---|
| age | fetched longer ago than [`config.exploitability.maxAge`](../../docs/reference/saga-schema.md#configexploitability), default 24h |
| `index/db.json` | missing, unreadable, or without a `modified` date |
| `index/modules.json` | missing, unreadable, or listing no modules |

The checks exist because govulncheck reports "No vulnerabilities found" and exits 0 against an
empty or unreadable database. A refused copy is never read:

| Network | Refused or missing copy |
|---|---|
| online | govulncheck queries `vuln.go.dev`, and the scan warns with the reason |
| `--offline` | the control reports an error naming the failed check |

The database the run read is recorded under `database` in the evidence: `local copy, fetched
<date>`, `vuln.go.dev`, or `vuln.go.dev` with the reason a local copy was refused. The cache key
carries the database's own `modified` date, so refreshing the copy invalidates cached results.

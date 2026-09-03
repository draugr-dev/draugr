# `govulncheck` scanner

Reachability analysis for Go modules: which of a repository's known vulnerabilities this code can
actually reach.

- **Control:** `sca`
- **Target:** repository
- **Tool:** [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck), from the Go team
- **Enabled by:** `controllers.sca.govulncheck.enabled: true` — opt-in, because it needs the Go
  toolchain and only answers for Go

## What it does

It asks a different question from the other `sca` scanners. Trivy reads a manifest and reports
which dependencies have known vulnerabilities. `govulncheck` builds a call graph from the packages
that are actually in the build and reports which of those vulnerabilities the code can reach — and
for the ones it can, the call path that reaches them.

That makes it an enrichment rather than a second opinion, and it is wired as one. Its verdicts are
folded onto the findings the manifest scanner already produced, matched on repository, module and
vulnerability id; its own copy is then dropped. Without that fold, every Go vulnerability would be
reported twice under two different identifiers — `CVE-2022-32149` from Trivy and `GO-2022-1059`
here — which is the opposite of what a noise-reduction feature is for.

A vulnerability only this scanner reports is **kept**, because a finding one tool found and
another missed is exactly the one that must not disappear in a deduplication.

## The three verdicts, and why there are three

| verdict | means |
|---|---|
| `reachable` | a call path was found, and is attached as evidence |
| `unreachable` | the module was analyzed and no path was found |
| `unknown` | no analysis covered it |

The third is the one that keeps the other two honest. A dependency used **only from `_test.go`
files** produces no `govulncheck` output at all — not a module-level record, nothing — at every
scan level, while a manifest scanner reports it normally. So the absence of a record is not
evidence of unreachability, and `unreachable` is only claimed when the run reported
`scan_level: symbol` **and** the module appears in the run's `SBOM` message. Anything else is
`unknown`.

This scanner is not a superset of a manifest scanner. It sees the build graph; a manifest scanner
sees the manifest.

## What a verdict does to a finding

It feeds the priority band and never rewrites the severity the scanner reported, exactly as
exploitability enrichment does in the other direction. An `unreachable` finding is ranked one band
down; a `reachable` one is unchanged, because severity already assumes the code runs.

It never suppresses. Static analysis is defeated by reflection, dynamic dispatch and code
generation, and a suppression in Draugr records that a *person* decided, with a name attached — an
inference is not a decision. Where exploitability enrichment has already raised a finding, that
wins: observed exploitation outranks a call graph's failure to find a path.

## License and terms of use

Two different licenses, because the tool and the data it reads are distributed separately:

- **The tool** — `golang.org/x/vuln` is distributed by the Go team under a **BSD-3-Clause**
  license. Draugr executes it as a subprocess and neither links nor bundles it, so its license
  stays its own.
- **The data** — entries in the [Go vulnerability database](https://go.dev/security/vuln/database)
  are distributed under **CC-BY-4.0**. Attribution is a condition of that license, which is why
  reports name the database rather than presenting its contents as Draugr's own findings.

No account, key or registration is required, and no tier restricts commercial use.

## What is sent

Nothing about the code under scan. The tool fetches the vulnerability database over HTTPS from
`https://vuln.go.dev` — an index at `/index/modules.json`, then individual advisory records at
`/ID/$id.json`. The API is documented as having "no query parameters, and no specific headers are
required": no manifest, no source and no inventory is uploaded.

Fetching a vendor's vulnerability database is not an effect on the target, so this scanner
declares none — the same reasoning that applies to the other database-backed scanners. It does
need network access to that host, or a mirror pointed at with the tool's own `-db` flag.

## Integration notes

- **Output is a concatenated JSON stream**, not JSONL and not one document — it is decoded with a
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
  CVE — the same choice `retirejs` makes, and what lets exclusions, exploitability feeds and other
  scanners' findings line up with it.
- **Tests are not analyzed.** Reporting a vulnerability reachable only from code that never ships
  produces a finding a developer cannot act on, which is the kind that teaches people to stop
  reading the report.
- **Requires a Go module, and a Go toolchain to install.** `draugr tools install govulncheck`
  provisions it at the pinned version, building it with the `go` on PATH — govulncheck publishes
  no release binary, so there is no archive to download. The build is verified against the Go
  checksum database, which covers every module it is built from and not only the tool; an install
  that could not reach the database still succeeds and is recorded as `unverified`, because
  reporting otherwise would claim evidence nobody gathered. With no Go on PATH, the error names
  the toolchain and the `go install` line that does the same job by hand.

  `draugr doctor` asks for it whenever a descriptor names it under `config.reachability`, so a
  missing analyzer is reported before a scan rather than by one. It is not required when the `sca`
  control is switched off, because `config.reachability` is project-wide and an analyzer whose
  control never runs is a tool nobody needs to install.

## Scope of the claim

**Go only.** The docs say *reachability for Go* every time, because a reachability claim without
its language is an overclaim — and because the analysis behind the word differs between tools: a
call graph and a framework heuristic are both called reachability and are not the same evidence.

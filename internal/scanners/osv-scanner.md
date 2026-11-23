---
title: "osv-scanner"
description: "A further opinion on dependency vulnerabilities, from advisory databases Trivy and Grype do not read."
section: Scanners
order: 85
---

# Scanner: `osv-scanner`

- **Control:** `sca`
- **Tool:** [OSV-Scanner](https://github.com/google/osv-scanner), `osv-scanner scan source --offline … --format json <checkout>`
- **Status:** ✅ implemented, **opt-in** (Trivy runs by default)
- **Targets:** source repositories
- **Effects:** none. Every scan runs `--offline`, so nothing about the repository leaves the machine
- **License / terms:** see [license, terms and what is sent](#license-terms-and-what-is-sent)

## What it does

Checks out a component's repository, reads its lockfiles and SBOMs with OSV-Scanner, and matches
the packages against OSV's databases, for the `sca` control.

What it adds is data. OSV aggregates advisory databases that neither Trivy's database nor Grype's
carries: the PyPA advisory database for Python, RustSec for Rust, the Go vulnerability database and
the Erlang Ecosystem Foundation's. A `Cargo.lock` pinning `zstd-safe 7.1.0` reports nine RustSec
advisories here, and none under `trivy-fs`.

It costs time and some precision. Over the 230 projects measured in
https://github.com/draugr-dev/draugr/issues/1897, OSV-Scanner took about 34 times Trivy's time, and
much of what it added over Trivy was a requirements range read at its lowest version, which
`trivyFs.detectionPriority: comprehensive` already reads. It is off unless a descriptor turns it on.
[`draugr init`](../../docs/reference/cli.md#draugr-init-dir) turns it on where the tree holds a
`Cargo.lock`, and so does a scan with no descriptor: on a Rust project it reported five flaws in
pinned versions that Trivy did not, for about 0.3s more per scan and a first download of 4 MB, as
https://github.com/draugr-dev/draugr/issues/2377 records. On a Python project it reported none that Trivy missed. To turn it on yourself:

```yaml
config:
  controls:
    sca:
      osvScanner:
        enabled: true
```

The descriptor key is `osvScanner`, not `osv-scanner`: scanner names appear in reports and can be
hyphenated, descriptor fields are camelCase without exception. It takes no option besides
`enabled`.

## Choices worth knowing

**Always `--offline`.** Without it, OSV-Scanner sends the name and version of every package it read
to `api.osv.dev`, and resolves a `pom.xml`'s or a requirements file's dependencies through
`deps.dev`. Offline it matches against the databases on disk and contacts nothing, which is also why
a `pom.xml`'s transitive dependencies are not read. See [The database](#the-database) for how the
databases get there.

**`--no-ignore`.** OSV-Scanner skips a file a `.gitignore` pattern matches, even one git tracks, so
a committed lockfile under an ignored directory would go unread with nothing to say so.

**No call analysis.** `--no-call-analysis=go` and `--no-call-analysis=rust`. Rust call analysis runs
the crate's build scripts, which is running the repository's own code. Go reachability comes from
[`govulncheck`](govulncheck.md), turned on by `config.reachability`.

**The repository's `osv-scanner.toml` is not read.** Its `[[IgnoredVulns]]` and
`[[PackageOverrides]]` remove a finding from OSV-Scanner's report altogether, with the reason only
in its log, so Draugr could not keep it in the report as set aside. Draugr passes `--config` with an
empty file, which replaces every `osv-scanner.toml` in the checkout. To set a finding aside, write it
in [`config.exclude`](../../docs/reference/saga-schema.md#configexclude), which keeps it in the report,
suppressed, with the reason.

**A repository with no file OSV-Scanner reads is a clean scan**, with `--allow-no-lockfiles`, as it
is for Trivy.

**Each finding is read as an import of the same JSON is read.** One finding per vulnerability
OSV-Scanner grouped, in each package, in each file, keyed on the group's first id with its other ids
and their aliases beside it. The rating is the group's highest CVSS score, else the advisory's own
severity, else high, marked `not scored yet`. The package URL loses OSV-Scanner's `source`
qualifier. [`sarif-import`](sarif-import.md#a-tools-own-json) has the details.

**A RustSec unmaintained notice is low.** RustSec publishes informational advisories beside its
vulnerabilities, and marks one that says a crate has no maintainer `"informational": "unmaintained"`.
Such a notice names no flaw, no affected function and no fixed version, and RustSec gives it no
score, so read as a vulnerability it would rank high as `not scored yet`. It is reported at low,
level `note`, with `RustSec unmaintained notice, which names no flaw in a version` as its rating. An
`unsound` advisory, such as `RUSTSEC-2021-0145` for atty, describes a flaw in a version and is read
as a vulnerability. An import of OSV-Scanner's JSON reads every group as a vulnerability, notices
included.

**Findings merge with Trivy's and Grype's.** A finding names the advisories it groups and every
alias they list, so a Python finding under `PYSEC-2026-1994` and Trivy's under `CVE-2025-66471` for
the same package in the same repository are one flaw, counted once, under the stronger reading. The
same flaw in two files of one repository, such as `requirements.txt` and `uv.lock`, is one flaw too.

**One scan per repository.** A component may hold several, and each is scanned and attributed
separately: findings from two repositories that share a path stay two findings.

## The database

OSV publishes one database per ecosystem, a zip archive at
`https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`. Which ones a run needs is
known only once a checkout has been read, so they are not fetched before the scan:

- **The first OSV-Scanner job of a run** passes `--download-offline-databases`. OSV-Scanner downloads
  the archive of each ecosystem it read, or keeps the one on disk where OSV's checksum of the
  published archive matches it.
- **Every later job** reads what is on disk, and passes `--download-offline-databases` only where it
  read an ecosystem no job of this run has downloaded.
- **No job reads an archive while another is downloading.** OSV-Scanner writes an archive in place,
  and a job that read it half-written would fail, or several jobs on a cold cache would each
  download it.

The archives are kept under `~/.draugr/data/osv-scanner`, or `$DRAUGR_HOME/data/osv-scanner`, which
`draugr tools uninstall osv-scanner` removes with the tool. Where `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`
is set, OSV-Scanner uses that directory instead and Draugr leaves it alone.

**Offline, nothing is downloaded,** and a repository whose ecosystem has no archive on disk fails the
control rather than passing:

```text
run osv-scanner: no crates.io and PyPI database in /home/you/.draugr/data/osv-scanner, and an
offline scan downloads none. Scan once online, or copy the directory from a machine that did
```

OSV-Scanner exits 127 in that case and still writes a report with no results, which Draugr does not
read. Any exit other than 0, or 1 for a scan that found something, fails the scan with the line of
OSV-Scanner's log that says why.

A cached result is keyed on OSV-Scanner's version and not on the databases' age, so with `--cache-dir`
a result is reused until `--cache-ttl` passes, 24 hours by default.

## Installing it

`draugr tools install osv-scanner` fetches the release binary for Linux or macOS, amd64 or arm64,
pinned by SHA-256. Each pinned hash is of the downloaded bytes and matched `osv-scanner_SHA256SUMS`
of the same release. OSV-Scanner publishes SLSA provenance beside its binaries
(`multiple.intoto.jsonl`), which Draugr does not check, and no cosign signature. Another version,
with `--version`, is checked against that release's `osv-scanner_SHA256SUMS`.

## License, terms and what is sent

**Tool license: Apache-2.0.** Draugr executes OSV-Scanner as a subprocess and neither links nor
bundles it, so the license stays Google's. Version 2.7.1 was published on 2026-11-09 under Google's
OSV project.

**The databases are a separate artifact, under the licenses of their sources.** OSV aggregates
advisories from other databases and keeps each record under its source's license, which OSV's
[data sources page](https://google.github.io/osv.dev/data/) lists, read on 2026-11-22. Among those
a scan of a source repository reads:

| Source | License |
|---|---|
| GitHub Advisory Database | CC-BY 4.0 |
| PyPA Advisory Database | CC-BY 4.0 |
| Go Vulnerability Database | CC-BY 4.0 |
| Erlang Ecosystem Foundation CNA | CC-BY 4.0 |
| RustSec Advisory Database | CC0 1.0 |
| OpenSSF Malicious Packages | Apache-2.0 |

CC-BY 4.0 asks whoever shares the records to credit their source. Draugr shares none: each finding
links its record at `https://osv.dev/<id>`, where OSV credits the source, and the archives stay on
the machine that ran the scan.

**Chainguard and Wolfi records carry a non-commercial license.** OSV lists the Chainguard / Wolfi
feed under CC-BY-NC-ND 4.0, or Chainguard's license for commercial scanners. OSV-Scanner downloads
that feed's archive only for packages of those ecosystems, which a source repository holds only
through an SBOM listing a Chainguard or Wolfi image's packages. Where a repository does, read
Chainguard's terms before scanning it with this scanner.

**No terms of use govern the download.** OSV's documentation offers the archives for anyone to
download, over HTTPS without an account or a key. Neither osv.dev's home page nor its FAQ and data
sources pages, read on 2026-11-22, name terms of service or a privacy notice for the archives or the
API, and no agreement gates the download. What applies is Apache-2.0 over the tool and the licenses
of the records above.

**What is sent: nothing about the repository.** Under `--offline`, OSV-Scanner contacts no host
while it scans: traced with `strace -f -e trace=connect` over a Cargo and a Python project, OSV-Scanner
2.7.1 made no connection. The download asks Google Cloud Storage for `<ecosystem>/all.zip`, with a
`HEAD` request for the published archive's checksum where a copy is on disk and a `GET` where it
differs or there is none, so the host learns which ecosystems a run reads, such as `PyPI`, and the
address asking. No package name, version, file or finding is sent.

## Links

- OSV-Scanner: https://github.com/google/osv-scanner
- Offline mode: https://google.github.io/osv-scanner/usage/offline-mode/
- OSV data sources: https://google.github.io/osv.dev/data/
- The default for this control: [`trivy-fs`](trivy-fs.md)
- Reading OSV-Scanner's JSON from a file: [`sarif-import`](sarif-import.md#a-tools-own-json)

## Data

The **vulnerability database, one archive per ecosystem**, from
`osv-vulnerabilities.storage.googleapis.com`, downloaded once per ecosystem per run by the first job
that reads it, and never during an `--offline` run.

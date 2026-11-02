---
title: "trivy-fs"
description: "Dependency vulnerabilities from a repository's manifests and lockfiles. The default for the sca control."
section: Scanners
order: 180
---

# Scanner: `trivy-fs` (dependency SCA)

- **Control:** [`sca`](../controllers/sca.md)
- **Tool:** Aqua **Trivy** (filesystem mode), https://trivy.dev
- **Status:** ✅ implemented (dependency vulnerabilities)
- **Target:** source repository (`RepositoryTarget`), checked out at the scanned revision
- **License / terms:** **Apache-2.0** (permissive). Run via **exec**. Vulnerability DB has
  separate terms (see the Trivy scanner doc).

## What it does

Checks out the component's repository, then runs
`trivy fs --quiet --scanners vuln --format json --list-all-pkgs <dir>` to find known
vulnerabilities in the project's dependencies (Software Composition Analysis), and converts the
result to SARIF. Trivy's JSON names the package as a field, where its SARIF names it only in prose,
and `--list-all-pkgs` records the line of each package's entry in its manifest. See the [SCA
glossary entry](../../docs/reference/glossary.md#sca-software-composition-analysis).

## Links

- Trivy filesystem scanning: https://trivy.dev/latest/docs/target/filesystem/
- License scanning, in the separate [`trivy-license`](trivy-license.md) scanner: https://trivy.dev/latest/docs/scanner/license/

## Saga options

```yaml
config:
  controls:
    sca:
      trivyFs:
        pkgTypes: [library]                          # skip the OS layer
        dbRepository: [registry.internal/trivy-db:2] # an internal mirror
        filePatterns: ["pip:requirements-.*\\.txt"]  # more files for the pip analyzer
        detectionPriority: comprehensive             # read >=1.2 as 1.2
```

| Option | What it does |
|---|---|
| `pkgTypes` | Which package types to analyze: `os`, `library`, or both (`--pkg-types`). Narrow it when the OS layer is a platform team's responsibility. |
| `dbRepository` | OCI repositories to pull the vulnerability database from, in priority order (`--db-repository`). For runners with no route to a public registry. |
| `filePatterns` | More files for an analyzer to read, each `analyzer:regex` (`--file-patterns`, once per entry). Trivy's pip analyzer reads only `requirements.txt`; the example adds files named `requirements-<something>.txt`. `draugr init` writes the patterns for the requirements files it finds. |
| `detectionPriority` | `precise`, the default, reads pinned versions only. `comprehensive` also reads a range such as `>=1.2` in `requirements.txt` as its minimum version, and reports Go standard-library vulnerabilities (`--detection-priority`). |
| `includeDevDeps` | Deprecated. Read as [`config.controls.sca.devDependencies`](../controllers/sca.md#development-dependencies), `true` as `report` and `false` as `suppress`, with a warning. |

`pkgTypes` and `dbRepository` also apply to the `trivy` image scanner. `filePatterns` and
`detectionPriority` decide which of a checkout's dependencies are read, and belong to `trivy-fs`
only.

**Development dependencies are read on every run.** Trivy marks each one `Dev` in its JSON, and each
finding about it carries `dev` on its package. A lockfile holding only development dependencies
counts as read. [Development dependencies](../../docs/reference/saga-schema.md#development-dependencies)
says which lockfiles carry the mark, how other scanners take it, and which setting decides whether
those findings count.

Trivy's `--severity` and `--ignorefile` are deliberately absent: both drop findings inside the
tool, where a suppression cannot be recorded or reviewed. Use `config.exclude` instead.

## Notes

- Integration mode: **exec** over a local checkout; Trivy + `git` must be on `PATH`.
- License findings come from [`trivy-license`](trivy-license.md), a separate scanner serving the
  [`licenses`](../controllers/licenses.md) control, which has its own policy and its own gate
  threshold.
- Each `lang-pkgs` result in Trivy's JSON names a file it took packages from. Those are the files
  the report counts as read; every other dependency file in the checkout is listed as unread, see
  [`sca`](../controllers/sca.md#unread).

## Data

The **vulnerability database**, from `mirror.gcr.io` and `ghcr.io`, which are Trivy's own
defaults in that order. Warmed once per run. With `--offline`, Draugr passes `--skip-db-update` and
`--offline-scan`. The second stops Trivy resolving a `pom.xml` against Maven Central, so a
dependency the pom declares is read from the pom itself.

`config.controls.sca.trivyFs.dbRepository` replaces both with an internal mirror.

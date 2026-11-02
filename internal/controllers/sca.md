# Controller: `sca` (Software Composition Analysis)

- **Industry term:** Software Composition Analysis
- **Scope:** component
- **Status:** ✅ implemented (dependency vulnerabilities)
- **Scanners:** [`trivy-fs`](../scanners/trivy-fs.md) (default); [`grype-fs`](../scanners/grype-fs.md),
  [`retirejs`](../scanners/retirejs.md) and [`mend-sca`](../scanners/mend-sca.md) (opt-in);
  [`govulncheck`](../scanners/govulncheck.md) (enabled by `config.reachability`)
- **Resource:** a component's `repositories:`

## What it does

Plans one scan per repository declared on a component (each is checked out and scanned for
dependency vulnerabilities), then aggregates + deduplicates findings into a per-control
result with a severity summary.

## Unread

A dependency file is **unread** when a scanner serving the control took no packages from it. The
report lists it under **Caveats** as `unread-files`, with a reason and the control. When no scanner
of the control read the file, the row names the control alone, as `no lockfile (sca)`, and the
packages it declares were not checked. When another scanner read it, the row names the scanner that
did not, as `no packages read (sca: grype-fs)`, and its packages were checked by the other scanner
alone, so a finding from that file has one source where the control has two.

| Reason | What the file is | Fix |
|---|---|---|
| `no lockfile` | a manifest of version ranges, such as `pyproject.toml`, `package.json`, `Cargo.toml` or a `.csproj`, with no lockfile beside it or above it | commit the lockfile the package manager writes |
| `no pinned versions` | a requirements file with no exact `==` version | pin it, or generate it from a lockfile |
| `no packages read` | a file `trivy-fs` passes over, such as `requirements-dev.txt`, `setup.py` or `pdm.lock` | enable [`grype-fs`](../scanners/grype-fs.md), which reads all three; for a requirements file, add a `pip:` pattern to `trivy-fs`'s `filePatterns` as well |
| `no packages read` | a file `grype-fs` passes over, such as `buildscript-gradle.lockfile` or a `.txt` under a `requirements` directory | none; `trivy-fs` reads the first, and the second through the `filePatterns` that `draugr init` writes |
| `no packages read` | Bun's binary `bun.lockb` | commit the text `bun.lock`, which Bun 1.2 and later write |
| `not parsed: ` and the parser's error | a file Trivy failed to parse, such as a `bun.lock` holding a dependency on a git repository, from which `trivy-fs` and `trivy-license` read no package, registry packages included | depend on a registry release instead of the git repository |
| `no packages read` | a conda `environment.yml` | none; no scanner Draugr runs checks conda packages |

`trivy-fs` and `trivy-license` name every file they took packages from in their JSON output, and
`grype-fs` names them in the CycloneDX inventory it writes beside its SARIF. Trivy logs a file it
failed to parse only at debug level, so both Trivy scanners run with `--debug`, and Draugr reads the
log for the file and the error. Draugr walks the same checkout for dependency files, leaving out
`node_modules`, `vendor`, `.venv` and files that declare no dependencies, and a file the walk finds
that a scanner did not name is unread by that scanner. A lockfile is left out only when its content
is that lockfile's format and pins no package; one Draugr cannot recognize stays in the walk. A
scanner that does not list what it read, such as `mend-sca`, leaves its files out of the count
rather than reporting all of them unread.

The console names three files per component and counts the rest; `--top 0` names every one.
`report.json` carries the count of files read and every unread file under `dependencyFiles`, see
the [report schema](../../docs/reference/report-schema.md).

## Links

- Glossary: [SCA](../../docs/reference/glossary.md#sca-software-composition-analysis)
- Saga reference: [`docs/reference/saga-schema.md`](../../docs/reference/saga-schema.md)

## Notes

- Dependency **vulnerabilities** only. License findings are the [`licenses`](licenses.md)
  control, deliberately separate: license risk is legal rather than technical, a different
  team owns the policy, and `config.gate.controls` can hold it to its own threshold.

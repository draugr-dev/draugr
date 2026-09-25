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

A dependency file is **unread** when no scanner serving the control took packages from it. The
packages it declares were not checked, and the report lists it under **Unread**, once per
component, with a reason:

| Reason | What the file is | Fix |
|---|---|---|
| `no lockfile` | a manifest of version ranges, such as `pyproject.toml`, `package.json`, `Cargo.toml` or a `.csproj`, with no lockfile beside it or above it | commit the lockfile the package manager writes |
| `no pinned versions` | a requirements file with no exact `==` version | pin it, or generate it from a lockfile |
| `no packages read` | a file the scanners passed over, such as `requirements-dev.txt`, `setup.py` or `pdm.lock` under `trivy-fs` | enable [`grype-fs`](../scanners/grype-fs.md), which reads all three |
| `no packages read` | Bun's binary `bun.lockb` | commit the text `bun.lock`, which Bun 1.2 and later write |
| `no packages read` | a conda `environment.yml` | none; no scanner Draugr runs checks conda packages |

`trivy-fs` and `trivy-license` name every file they took packages from in their JSON output, and
`grype-fs` names them in the CycloneDX inventory it writes beside its SARIF. Draugr walks the same
checkout for dependency files, leaving out `node_modules`, `vendor`, `.venv` and files that declare
no dependencies, and a file the walk finds that no scanner named is unread. A file one scanner read
counts as read for the control. A scanner that does not list what it read, such as `mend-sca`,
leaves its files out of the count rather than reporting all of them unread.

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

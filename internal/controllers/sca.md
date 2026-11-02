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
packages it declares were not checked, and the report lists it under **Caveats** as `unread-files`, with
a reason:

| Reason | What the file is | Fix |
|---|---|---|
| `no lockfile` | a manifest of version ranges, such as `pyproject.toml`, `package.json`, `Cargo.toml` or a `.csproj`, with no lockfile beside it or above it | commit the lockfile the package manager writes |
| `no pinned versions` | a requirements file with no exact `==` version | pin it, or generate it from a lockfile |
| `no packages read` | a file the scanners passed over, such as `requirements-dev.txt`, `setup.py` or `pdm.lock` under `trivy-fs` | enable [`grype-fs`](../scanners/grype-fs.md), which reads all three |
| `no packages read` | Bun's binary `bun.lockb` | commit the text `bun.lock`, which Bun 1.2 and later write |
| `no packages read` | a `bun.lock` holding a dependency on a git repository, from which `trivy-fs` reads no package, registry packages included | depend on a registry release instead of the git repository |
| `no packages read` | a conda `environment.yml` | none; no scanner Draugr runs checks conda packages |

`trivy-fs` and `trivy-license` name every file they took packages from in their JSON output, and
`grype-fs` names them in the CycloneDX inventory it writes beside its SARIF. Draugr walks the same
checkout for dependency files, leaving out `node_modules`, `vendor`, `.venv` and files that declare
no dependencies, and a file the walk finds that no scanner named is unread. A lockfile is left out
only when its content is that lockfile's format and pins no package; one Draugr cannot recognize
stays in the walk. A file one scanner read
counts as read for the control. A scanner that does not list what it read, such as `mend-sca`,
leaves its files out of the count rather than reporting all of them unread.

The console names three files per component and counts the rest; `--top 0` names every one.
`report.json` carries the count of files read and every unread file under `dependencyFiles`, see
the [report schema](../../docs/reference/report-schema.md).

A requirements file is **read in part** when a scanner took packages from its pinned requirements
and none from the requirements with no exact `==` version. The file counts as read, and the report
lists it under **Caveats** as `unread-files` with a reason naming the requirements not checked, as
`1 requirement not pinned: urllib3`, or counting them past three, as `29 requirements not pinned`.
Under `detectionPriority: comprehensive`, Trivy takes a range at its minimum version, and the reason
counts the requirements it did not take, as `2 requirements not read`. A scanner that took a package
for every requirement clears the row. This holds for every requirements file the walk recognizes:
`requirements.txt`, a `.txt` whose name contains `requirements`, such as `requirements-dev.txt`, and
any `.txt` under a `requirements` directory. The fix is the one for `no pinned versions`: pin them,
or generate the file from a lockfile.

A `pom.xml` is **read in part** when Trivy took its declared dependencies and none of theirs.
Every Trivy run passes `--offline-scan`, so Trivy finds a dependency's own dependencies, and its
license, only in the local Maven repository, and a pom that resolves there is read in full.
Otherwise the report lists it under **Caveats** as `unread-files`, for `sca` and for
[`licenses`](licenses.md), with the reason `transitive dependencies not resolved, run mvn
dependency:resolve`. Running `mvn dependency:resolve` before the scan fills the local repository and
clears the row for both controls, sending nothing beyond what the build already fetches. Setting
[`config.controls.sca.trivyFs.resolveMaven`](../scanners/trivy-fs.md#saga-options) to `true` has
`trivy-fs` fetch each dependency's pom from Maven Central and the repositories the pom names, which
clears the row for `sca` only, since `trivy-license` never resolves.

## Links

- Glossary: [SCA](../../docs/reference/glossary.md#sca-software-composition-analysis)
- Saga reference: [`docs/reference/saga-schema.md`](../../docs/reference/saga-schema.md)

## Notes

- Dependency **vulnerabilities** only. License findings are the [`licenses`](licenses.md)
  control, deliberately separate: license risk is legal rather than technical, a different
  team owns the policy, and `config.gate.controls` can hold it to its own threshold.

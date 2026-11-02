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
packages it declares were not checked, and the report lists it under **Caveats** as `unread-files`,
with the control and a reason:

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
that no scanner named is unread. A lockfile is left out only when its content is that lockfile's
format and pins no package; one Draugr cannot recognize stays in the walk. A scanner that does not
list what it read, such as `mend-sca`, leaves its files out of the count rather than reporting all
of them unread.

A file one scanner took no packages from while another scanner of the control read it is
**missed** by that scanner, for one of the reasons above. Its packages were checked by the other
scanner, so it is not a caveat, and `config.gate.failOnCaveats: [unread-files]` does not fail on it.
`--evidence` records it as `missed  sca: grype-fs · android · buildscript-gradle.lockfile · no
packages read`, and `report.json` under `dependencyFiles[].missed`, with the scanner and its reason.
A finding from that file comes from the other scanner alone.

The console names three files per component and counts the rest; `--top 0` names every one.
`report.json` carries the count of files read, every unread file and every missed file under
`dependencyFiles`, see the [report schema](../../docs/reference/report-schema.md).

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

A `pom.xml` is **read in part** when Trivy left some of its dependencies unchecked. Every Trivy run
passes `--offline-scan`, so Trivy reads a parent POM, an imported BOM, and a dependency's own pom
only from the checkout or the local Maven repository, and a pom that resolves there is read in
full. Otherwise the report lists it under **Caveats** as `unread-files`, for `sca` and for
[`licenses`](licenses.md), with one of two reasons:

| Reason | What Trivy could not read |
|---|---|
| `2 dependency versions not resolved, run mvn dependency:resolve` | the version of a direct dependency that takes it from a parent POM, an imported BOM, or a property one of them defines. The dependency, and everything below it, was not checked. A version written in the pom, or in a property the pom defines, is read. |
| `transitive dependencies not resolved, run mvn dependency:resolve` | the dependencies of its dependencies, every direct one having a version |

Running `mvn dependency:resolve` before the scan fills the local repository and clears the row for
both controls, sending nothing beyond what the build already fetches. Setting
[`config.controls.sca.trivyFs.resolveMaven`](../scanners/trivy-fs.md#saga-options) to `true` has
`trivy-fs` fetch each pom it needs from Maven Central and the repositories the pom names, which
clears the row for `sca` only, since `trivy-license` never resolves.

## Links

- Glossary: [SCA](../../docs/reference/glossary.md#sca-software-composition-analysis)
- Saga reference: [`docs/reference/saga-schema.md`](../../docs/reference/saga-schema.md)

## Notes

- Dependency **vulnerabilities** only. License findings are the [`licenses`](licenses.md)
  control, deliberately separate: license risk is legal rather than technical, a different
  team owns the policy, and `config.gate.controls` can hold it to its own threshold.
